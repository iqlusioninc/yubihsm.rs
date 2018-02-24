//! Software simulation of the `YubiHSM2` for integration testing
//!
//! To enable, make sure to build yubihsm-client with the "mockhsm" feature

extern crate tiny_http;

use self::tiny_http::{Method, Request, Response, Server, StatusCode};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use failure::Error;
use std::collections::HashMap;
use std::io::Cursor;

use connector::{PBKDF2_ITERATIONS, PBKDF2_SALT};
use securechannel::{Challenge, Channel, Command, CommandType, StaticKeys, CHALLENGE_SIZE};
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
                Response::new(
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
    fn status(&self) -> Response<Cursor<Vec<u8>>> {
        let mut addr_parts = self.addr.split(':');

        Response::from_string(
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
    fn api(&mut self, request: &mut Request) -> Response<Cursor<Vec<u8>>> {
        let mut body = Vec::new();
        request
            .as_reader()
            .read_to_end(&mut body)
            .expect("HTTP request read error");

        let command = Command::parse(body).unwrap();

        match command.command_type {
            CommandType::CreateSession => self.create_session(&command),
            CommandType::AuthSession => self.authenticate_session(&command),
            CommandType::SessionMessage => self.session_message(&command),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        }
    }

    /// Create a new HSM session
    fn create_session(&mut self, command: &Command) -> Response<Cursor<Vec<u8>>> {
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
        respond_success(CommandType::CreateSession, &response_body)
    }

    /// Authenticate an HSM session
    fn authenticate_session(&mut self, command: &Command) -> Response<Cursor<Vec<u8>>> {
        let session_id = command.session_id.unwrap();

        self.sessions
            .get_mut(&session_id)
            .expect("invalid session ID")
            .verify_authenticate_session(command)
            .unwrap();

        respond_success(CommandType::AuthSession, b"")
    }

    /// Session keepalive(?) messages
    fn session_message(&self, _command: &Command) -> Response<Cursor<Vec<u8>>> {
        // TODO: verify C-MAC and send R-MAC
        respond_success(CommandType::SessionMessage, b"")
    }
}

/// Create a response for a successful request
fn respond_success(cmd: CommandType, command_data: &[u8]) -> Response<Cursor<Vec<u8>>> {
    let mut body = Vec::with_capacity(3 + command_data.len());
    body.push(cmd as u8 + 128);
    body.write_u16::<BigEndian>(command_data.len() as u16)
        .unwrap();
    body.extend_from_slice(command_data);

    Response::from_data(body)
}
