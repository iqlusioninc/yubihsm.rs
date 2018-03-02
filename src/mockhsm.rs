//! Software simulation of the `YubiHSM2` for integration testing
//!
//! To enable, make sure to build yubihsm-client with the "mockhsm" feature

extern crate tiny_http;

use self::tiny_http::{Method, Request, Server, StatusCode};
use self::tiny_http::Response as HttpResponse;

use byteorder::{BigEndian, ByteOrder};
use ed25519_dalek::Keypair as Ed25519Keypair;
use failure::Error;
use rand::OsRng;
use sha2::Sha512;
use std::collections::HashMap;
use std::io::Cursor;

use {Algorithm, Capability, Domain, ObjectId, ObjectLabel, ObjectOrigin, ObjectType, SequenceId,
     SessionId};
use commands::{Command, DeleteObjectCommand, GenAsymmetricKeyCommand, GetObjectInfoCommand,
               ListObjectsCommand};
use connector::{PBKDF2_ITERATIONS, PBKDF2_SALT};
use responses::{DeleteObjectResponse, EchoResponse, GenAsymmetricKeyResponse,
                GetObjectInfoResponse, ListObjectsEntry, ListObjectsResponse, Response};
use securechannel::{Challenge, Channel, CommandMessage, CommandType, ResponseMessage, StaticKeys,
                    CHALLENGE_SIZE};

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: ObjectId = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

/// Software simulation of a `YubiHSM2` intended for testing
pub struct MockHSM {
    addr: String,
    server: Server,
    static_keys: StaticKeys,
    sessions: HashMap<SessionId, Channel>,
    ed25519_keys: HashMap<ObjectId, Object<Ed25519Keypair>>,
}

/// Objects stored in the `MockHSM`
#[allow(dead_code)]
struct Object<T> {
    value: T,
    object_type: ObjectType,
    algorithm: Algorithm,
    capabilities: Vec<Capability>,
    delegated_capabilities: Vec<Capability>,
    domains: Vec<Domain>,
    length: u16,
    sequence: SequenceId,
    origin: ObjectOrigin,
    label: ObjectLabel,
}

impl<T> Object<T> {
    pub fn object_info_response(&self, object_id: ObjectId) -> GetObjectInfoResponse {
        GetObjectInfoResponse {
            capabilities: self.capabilities.clone(),
            id: object_id,
            length: self.length,
            domains: self.domains.clone(),
            object_type: self.object_type,
            algorithm: self.algorithm,
            sequence: self.sequence,
            origin: self.origin,
            label: self.label.clone(),
            delegated_capabilities: self.delegated_capabilities.clone(),
        }
    }
}

impl Object<Ed25519Keypair> {
    pub fn new(label: ObjectLabel, capabilities: Vec<Capability>, domains: Vec<Domain>) -> Self {
        let mut cspring = OsRng::new().unwrap();

        Self {
            value: Ed25519Keypair::generate::<Sha512>(&mut cspring),
            object_type: ObjectType::Asymmetric,
            algorithm: Algorithm::EC_ED25519,
            capabilities,
            delegated_capabilities: vec![],
            domains,
            length: 24,
            sequence: 1,
            origin: ObjectOrigin::Generated,
            label,
        }
    }
}

impl MockHSM {
    /// Create a new MockHSM. This will bind to the given address/port but will
    /// not start processing requests until the `run` method is invoked
    pub fn new(addr: &str) -> Result<Self, Error> {
        let server = Server::http(addr)
            .or_else(|e| Err(format_err!("error creating MockHSM server: {:?}", e)))?;

        Ok(Self {
            addr: addr.to_owned(),
            server,
            static_keys: StaticKeys::derive_from_password(
                DEFAULT_PASSWORD.as_bytes(),
                PBKDF2_SALT,
                PBKDF2_ITERATIONS,
            ),
            sessions: HashMap::new(),
            ed25519_keys: HashMap::new(),
        })
    }

    /// Run the MockHSM server, processing the given number of requests and then stopping
    pub fn run(&mut self, num_requests: usize) {
        for _ in 0..num_requests {
            let mut request = self.server.recv().unwrap();

            let response = match *request.method() {
                Method::Get => match request.url() {
                    "/connector/status" => Some(self.status()),
                    _ => None,
                },
                Method::Post => match request.url() {
                    "/connector/api" => Some(self.api(&mut request)),
                    _ => None,
                },
                _ => None,
            }.unwrap_or_else(|| {
                HttpResponse::new(
                    StatusCode::from(404),
                    vec![],
                    Cursor::new(vec![]),
                    None,
                    None,
                )
            });

            request.respond(response).unwrap();
        }
    }

    /// GET /connector/status - status page
    fn status(&self) -> HttpResponse<Cursor<Vec<u8>>> {
        let mut addr_parts = self.addr.split(':');

        HttpResponse::from_string(
            [
                "status=OK",
                "serial=*",
                "version=1.0.1",
                "pid=12345",
                &format!("address={}", addr_parts.next().unwrap()),
                &format!("port={}", addr_parts.next().unwrap()),
            ].join("\n"),
        )
    }

    /// POST /connector/api - perform HSM operation
    fn api(&mut self, request: &mut Request) -> HttpResponse<Cursor<Vec<u8>>> {
        let mut body = Vec::new();
        request
            .as_reader()
            .read_to_end(&mut body)
            .expect("HTTP request read error");

        let command = CommandMessage::parse(body).unwrap();

        match command.command_type {
            CommandType::CreateSession => self.create_session(&command),
            CommandType::AuthSession => self.authenticate_session(&command),
            CommandType::SessionMessage => self.session_message(command),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        }
    }

    /// Create a new HSM session
    fn create_session(&mut self, command: &CommandMessage) -> HttpResponse<Cursor<Vec<u8>>> {
        assert_eq!(
            command.data.len(),
            10,
            "create_session: unexpected command data length {} (expected 10)",
            command.data.len()
        );

        let auth_key_id = BigEndian::read_u16(&command.data[..2]);
        assert_eq!(
            auth_key_id, DEFAULT_AUTH_KEY_ID,
            "unexpected auth key ID: {}",
            auth_key_id
        );

        let host_challenge = Challenge::from_slice(&command.data[2..]);
        let card_challenge = Challenge::random();

        let session_id = self.sessions
            .keys()
            .max()
            .map(|id| id.succ().expect("session count exceeded"))
            .unwrap_or_else(|| SessionId::new(0).unwrap());

        let channel = Channel::new(
            session_id,
            &self.static_keys,
            &host_challenge,
            &card_challenge,
        );

        let card_cryptogram = channel.card_cryptogram();

        let mut response_body = Vec::with_capacity(1 + CHALLENGE_SIZE * 2);
        response_body.push(session_id.to_u8());
        response_body.extend_from_slice(card_challenge.as_slice());
        response_body.extend_from_slice(card_cryptogram.as_slice());

        assert!(self.sessions.insert(session_id, channel).is_none());

        HttpResponse::from_data(
            ResponseMessage::success(CommandType::CreateSession, response_body).into_vec(),
        )
    }

    /// Authenticate an HSM session
    fn authenticate_session(&mut self, command: &CommandMessage) -> HttpResponse<Cursor<Vec<u8>>> {
        let session_id = command
            .session_id
            .unwrap_or_else(|| panic!("no session ID in command: {:?}", command.command_type));

        self.channel(&session_id)
            .verify_authenticate_session(command)
            .unwrap();

        HttpResponse::from_data(
            ResponseMessage::success(CommandType::AuthSession, vec![]).into_vec(),
        )
    }

    /// Encrypted session messages
    fn session_message(
        &mut self,
        encrypted_command: CommandMessage,
    ) -> HttpResponse<Cursor<Vec<u8>>> {
        let session_id = encrypted_command.session_id.unwrap_or_else(|| {
            panic!(
                "no session ID in command: {:?}",
                encrypted_command.command_type
            )
        });

        let command = self.channel(&session_id)
            .decrypt_command(encrypted_command)
            .unwrap();

        let response = match command.command_type {
            CommandType::DeleteObject => self.delete_object(command),
            CommandType::Echo => self.echo(command),
            CommandType::GenAsymmetricKey => self.gen_asymmetric_key(command),
            CommandType::GetObjectInfo => self.get_object_info(command),
            CommandType::ListObjects => self.list_objects(command),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        };

        let encrypted_response = self.channel(&session_id)
            .encrypt_response(response)
            .unwrap();

        HttpResponse::from_data(encrypted_response.into_vec())
    }

    /// Delete an object
    fn delete_object(&mut self, cmd_message: CommandMessage) -> ResponseMessage {
        let command = DeleteObjectCommand::parse(cmd_message)
            .unwrap_or_else(|e| panic!("error parsing CommandType::DeleteObject: {:?}", e));

        match command.object_type {
            // TODO: support other asymmetric keys besides Ed25519 keys
            ObjectType::Asymmetric => match self.ed25519_keys.remove(&command.object_id) {
                Some(_) => respond(DeleteObjectResponse {}),
                None => {
                    ResponseMessage::error(&format!("no such object ID: {:?}", command.object_id))
                }
            },
            _ => panic!("MockHSM only supports delete_object for ObjectType::Asymmetric"),
        }
    }

    /// Echo a message back to the host
    fn echo(&self, cmd_message: CommandMessage) -> ResponseMessage {
        respond(EchoResponse {
            message: cmd_message.data,
        })
    }

    /// Generate a new random asymmetric key
    fn gen_asymmetric_key(&mut self, cmd_message: CommandMessage) -> ResponseMessage {
        let command = GenAsymmetricKeyCommand::parse(cmd_message)
            .unwrap_or_else(|e| panic!("error parsing CommandType::GetObjectInfo: {:?}", e));

        match command.algorithm {
            Algorithm::EC_ED25519 => {
                let key = Object::new(command.label, command.capabilities, command.domains);
                assert!(self.ed25519_keys.insert(command.key_id, key).is_none());
            }
            other => panic!("unsupported algorithm: {:?}", other),
        }

        respond(GenAsymmetricKeyResponse {
            key_id: command.key_id,
        })
    }

    /// Get detailed info about a specific object
    fn get_object_info(&self, cmd_message: CommandMessage) -> ResponseMessage {
        let command = GetObjectInfoCommand::parse(cmd_message)
            .unwrap_or_else(|e| panic!("error parsing CommandType::GetObjectInfo: {:?}", e));

        if command.object_type != ObjectType::Asymmetric {
            panic!("MockHSM only supports ObjectType::Asymmetric for now");
        }

        // TODO: support other asymmetric keys besides Ed25519 keys
        match self.ed25519_keys.get(&command.object_id) {
            Some(key) => respond(key.object_info_response(command.object_id)),
            None => ResponseMessage::error(&format!("no such object ID: {:?}", command.object_id)),
        }
    }

    /// List all objects presently accessible to a session
    fn list_objects(&self, cmd_message: CommandMessage) -> ResponseMessage {
        // TODO: filter support
        let _command = ListObjectsCommand::parse(cmd_message);

        let list_entries = self.ed25519_keys
            .iter()
            .map(|(object_id, object)| ListObjectsEntry {
                id: *object_id,
                object_type: object.object_type,
                sequence: object.sequence,
            })
            .collect();

        respond(ListObjectsResponse {
            objects: list_entries,
        })
    }

    /// Obtain the channel for a session by its ID
    fn channel(&mut self, id: &SessionId) -> &mut Channel {
        self.sessions
            .get_mut(id)
            .unwrap_or_else(|| panic!("invalid session ID: {:?}", id))
    }
}

/// Send a `Response` message back to the client
fn respond<R: Response>(response: R) -> ResponseMessage {
    ResponseMessage::success(R::COMMAND_TYPE, response.into_vec())
}
