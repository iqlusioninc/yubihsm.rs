//! Software simulation of the `YubiHSM2` for integration testing
//!
//! To enable, make sure to build yubihsm-client with the "mockhsm" feature

extern crate tiny_http;

use std::collections::HashMap;
use std::io::Cursor;

use ed25519_dalek::Keypair as Ed25519Keypair;
use failure::Error;
use rand::OsRng;
use sha2::Sha512;
use self::tiny_http::{Method, Request, Server, StatusCode};
use self::tiny_http::Response as HttpResponse;

use {Algorithm, Capabilities, Domains, ObjectId, ObjectLabel, ObjectOrigin, ObjectType,
     SequenceId, SessionId};
use commands::*;
use connector::{PBKDF2_ITERATIONS, PBKDF2_SALT};
use responses::*;
use securechannel::{Challenge, Channel, CommandMessage, CommandType, ResponseMessage, StaticKeys};
use serializers::deserialize;

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
    objects: Objects,
}

/// Objects stored in the `MockHSM`
#[derive(Default)]
pub struct Objects {
    // TODO: other object types besides Ed25519 keys
    ed25519_keys: HashMap<ObjectId, Object<Ed25519Keypair>>,
}

impl Objects {
    /// Create a new MockHSM object store
    pub fn new() -> Self {
        Objects {
            ed25519_keys: HashMap::new(),
        }
    }
}

/// An individual object in the `MockHSM`, specialized for a given object type
struct Object<T> {
    value: T,
    object_type: ObjectType,
    algorithm: Algorithm,
    capabilities: Capabilities,
    delegated_capabilities: Capabilities,
    domains: Domains,
    length: u16,
    sequence: SequenceId,
    origin: ObjectOrigin,
    label: ObjectLabel,
}

impl Object<Ed25519Keypair> {
    pub fn new(label: ObjectLabel, capabilities: Capabilities, domains: Domains) -> Self {
        let mut cspring = OsRng::new().unwrap();

        Self {
            value: Ed25519Keypair::generate::<Sha512>(&mut cspring),
            object_type: ObjectType::Asymmetric,
            algorithm: Algorithm::EC_ED25519,
            capabilities,
            delegated_capabilities: Capabilities::default(),
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
            objects: Objects::new(),
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
    fn create_session(&mut self, cmd_message: &CommandMessage) -> HttpResponse<Cursor<Vec<u8>>> {
        let cmd: CreateSessionCommand = deserialize(cmd_message.data.as_ref())
            .unwrap_or_else(|e| panic!("error parsing CreateSession command data: {:?}", e));

        assert_eq!(
            cmd.auth_key_id, DEFAULT_AUTH_KEY_ID,
            "unexpected auth key ID: {}",
            cmd.auth_key_id
        );

        // Generate a random card challenge to send back to the client
        let card_challenge = Challenge::random();

        let session_id = self.sessions
            .keys()
            .max()
            .map(|id| id.succ().expect("session count exceeded"))
            .unwrap_or_else(|| SessionId::new(0).unwrap());

        let channel = Channel::new(
            session_id,
            &self.static_keys,
            &cmd.host_challenge,
            &card_challenge,
        );

        let card_cryptogram = channel.card_cryptogram();
        assert!(self.sessions.insert(session_id, channel).is_none());

        let mut response = CreateSessionResponse {
            card_challenge,
            card_cryptogram,
        }.serialize();

        response.session_id = Some(session_id);
        let response_bytes: Vec<u8> = response.into();

        HttpResponse::from_data(response_bytes)
    }

    /// Authenticate an HSM session
    fn authenticate_session(&mut self, command: &CommandMessage) -> HttpResponse<Cursor<Vec<u8>>> {
        let session_id = command
            .session_id
            .unwrap_or_else(|| panic!("no session ID in command: {:?}", command.command_type));

        let response_bytes: Vec<u8> = self.channel(&session_id)
            .verify_authenticate_session(command)
            .unwrap()
            .into();

        HttpResponse::from_data(response_bytes)
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
            CommandType::DeleteObject => self.delete_object(&command.data),
            CommandType::Echo => self.echo(&command.data),
            CommandType::GenAsymmetricKey => self.gen_asymmetric_key(&command.data),
            CommandType::GetObjectInfo => self.get_object_info(&command.data),
            CommandType::GetPubKey => self.get_pubkey(&command.data),
            CommandType::ListObjects => self.list_objects(&command.data),
            CommandType::SignDataEdDSA => self.sign_data_eddsa(&command.data),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        };

        let encrypted_response: Vec<u8> = self.channel(&session_id)
            .encrypt_response(response)
            .unwrap()
            .into();

        HttpResponse::from_data(encrypted_response)
    }

    /// Delete an object
    fn delete_object(&mut self, cmd_data: &[u8]) -> ResponseMessage {
        let command: DeleteObjectCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::DeleteObject: {:?}", e));

        match command.object_type {
            // TODO: support other asymmetric keys besides Ed25519 keys
            ObjectType::Asymmetric => match self.objects.ed25519_keys.remove(&command.object_id) {
                Some(_) => DeleteObjectResponse {}.serialize(),
                None => {
                    ResponseMessage::error(&format!("no such object ID: {:?}", command.object_id))
                }
            },
            _ => panic!("MockHSM only supports delete_object for ObjectType::Asymmetric"),
        }
    }

    /// Echo a message back to the host
    fn echo(&self, cmd_data: &[u8]) -> ResponseMessage {
        EchoResponse {
            message: cmd_data.into(),
        }.serialize()
    }

    /// Generate a new random asymmetric key
    fn gen_asymmetric_key(&mut self, cmd_data: &[u8]) -> ResponseMessage {
        let command: GenAsymmetricKeyCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::GetObjectInfo: {:?}", e));

        match command.algorithm {
            Algorithm::EC_ED25519 => {
                let key = Object::new(command.label, command.capabilities, command.domains);
                assert!(
                    self.objects
                        .ed25519_keys
                        .insert(command.key_id, key)
                        .is_none()
                );
            }
            other => panic!("unsupported algorithm: {:?}", other),
        }

        GenAsymmetricKeyResponse {
            key_id: command.key_id,
        }.serialize()
    }

    /// Get detailed info about a specific object
    fn get_object_info(&self, cmd_data: &[u8]) -> ResponseMessage {
        let command: GetObjectInfoCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::GetObjectInfo: {:?}", e));

        if command.object_type != ObjectType::Asymmetric {
            panic!("MockHSM only supports ObjectType::Asymmetric for now");
        }

        // TODO: support other asymmetric keys besides Ed25519 keys
        match self.objects.ed25519_keys.get(&command.object_id) {
            Some(key) => GetObjectInfoResponse {
                capabilities: key.capabilities,
                id: command.object_id,
                length: key.length,
                domains: key.domains,
                object_type: key.object_type,
                algorithm: key.algorithm,
                sequence: key.sequence,
                origin: key.origin,
                label: key.label.clone(),
                delegated_capabilities: key.delegated_capabilities,
            }.serialize(),
            None => ResponseMessage::error(&format!("no such object ID: {:?}", command.object_id)),
        }
    }

    /// Get the public key associated with a key in the HSM
    fn get_pubkey(&self, cmd_data: &[u8]) -> ResponseMessage {
        let command: GetPubKeyCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::GetPubKey: {:?}", e));

        // TODO: support other asymmetric keys besides Ed25519 keys
        match self.objects.ed25519_keys.get(&command.key_id) {
            Some(key) => GetPubKeyResponse {
                algorithm: Algorithm::EC_ED25519,
                data: Vec::from(key.value.public.as_bytes().as_ref()),
            }.serialize(),
            None => ResponseMessage::error(&format!("no such object ID: {:?}", command.key_id)),
        }
    }

    /// List all objects presently accessible to a session
    fn list_objects(&self, cmd_data: &[u8]) -> ResponseMessage {
        // TODO: filter support
        let _command: ListObjectsCommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::ListObjects: {:?}", e));

        // TODO: support other asymmetric keys besides Ed25519 keys
        let list_entries = self.objects
            .ed25519_keys
            .iter()
            .map(|(object_id, object)| ListObjectsEntry {
                id: *object_id,
                object_type: object.object_type,
                sequence: object.sequence,
            })
            .collect();

        ListObjectsResponse {
            objects: list_entries,
        }.serialize()
    }

    /// Sign a message using the Ed25519 signature algorithm
    fn sign_data_eddsa(&self, cmd_data: &[u8]) -> ResponseMessage {
        let command: SignDataEdDSACommand = deserialize(cmd_data)
            .unwrap_or_else(|e| panic!("error parsing CommandType::SignDataEdDSA: {:?}", e));

        // TODO: support other asymmetric keys besides Ed25519 keys
        match self.objects.ed25519_keys.get(&command.key_id) {
            Some(key) => {
                let signature = key.value.sign::<Sha512>(command.data.as_ref()).to_bytes();
                SignDataEdDSAResponse {
                    signature: Vec::from(signature.as_ref()),
                }.serialize()
            }
            None => ResponseMessage::error(&format!("no such object ID: {:?}", command.key_id)),
        }
    }

    /// Obtain the channel for a session by its ID
    fn channel(&mut self, id: &SessionId) -> &mut Channel {
        self.sessions
            .get_mut(id)
            .unwrap_or_else(|| panic!("invalid session ID: {:?}", id))
    }
}
