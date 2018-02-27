//! Software simulation of the `YubiHSM2` for integration testing
//!
//! To enable, make sure to build yubihsm-client with the "mockhsm" feature

extern crate tiny_http;

use self::tiny_http::{Method, Request, Server, StatusCode};
use self::tiny_http::Response as HttpResponse;

use byteorder::{BigEndian, ByteOrder};
use failure::Error;
use std::collections::HashMap;
use std::io::Cursor;

use connector::{PBKDF2_ITERATIONS, PBKDF2_SALT};
use securechannel::{Challenge, Channel, Command, CommandType, Response, StaticKeys, CHALLENGE_SIZE};
use super::{KeyId, SessionId};

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: KeyId = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

/// Software simulation of a `YubiHSM2` intended for testing
pub struct MockHSM {
    addr: String,
    server: Server,
    static_keys: StaticKeys,
    sessions: HashMap<SessionId, Channel>,
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

        let command = Command::parse(body).unwrap();

        match command.command_type {
            CommandType::CreateSession => self.create_session(&command),
            CommandType::AuthSession => self.authenticate_session(&command),
            CommandType::SessionMessage => self.session_message(command),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        }
    }

    /// Create a new HSM session
    fn create_session(&mut self, command: &Command) -> HttpResponse<Cursor<Vec<u8>>> {
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
            Response::success(CommandType::CreateSession, response_body).into_vec(),
        )
    }

    /// Authenticate an HSM session
    fn authenticate_session(&mut self, command: &Command) -> HttpResponse<Cursor<Vec<u8>>> {
        let session_id = command
            .session_id
            .unwrap_or_else(|| panic!("no session ID in command: {:?}", command.command_type));

        self.channel(&session_id)
            .verify_authenticate_session(command)
            .unwrap();

        HttpResponse::from_data(Response::success(CommandType::AuthSession, vec![]).into_vec())
    }

    /// Encrypted session messages
    fn session_message(&mut self, encrypted_command: Command) -> HttpResponse<Cursor<Vec<u8>>> {
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
            CommandType::Echo => self.echo(command),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        };

        let encrypted_response = self.channel(&session_id)
            .encrypt_response(response)
            .unwrap();

        HttpResponse::from_data(encrypted_response.into_vec())
    }

    /// Echo a message back to the host
    fn echo(&self, command: Command) -> Response {
        Response::success(CommandType::Echo, command.data)
    }

    /// Obtain the channel for a session by its ID
    fn channel(&mut self, id: &SessionId) -> &mut Channel {
        self.sessions
            .get_mut(id)
            .unwrap_or_else(|| panic!("invalid session ID: {:?}", id))
    }
}
