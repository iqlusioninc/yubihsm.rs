//! Software simulation of the YubiHSM2 for integration testing
//!
//! To enable, make sure to build yubihsm-client with the "mockhsm" feature

extern crate tiny_http;

use self::tiny_http::{Method, Request, Response, Server, StatusCode};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use failure::Error;
use std::io::Cursor;

use command::CommandType;
use connector::{PBKDF2_ITERATIONS, PBKDF2_SALT};
use scp03::{Challenge, Context, IdentityKeys, SessionKeys, CHALLENGE_SIZE};
use super::KeyID;

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: KeyID = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

/// Software simulation of a YubiHSM2 intended for testing
pub struct MockHSM {
    addr: String,
    server: Server,
    static_keys: IdentityKeys,
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
            static_keys: IdentityKeys::derive_from_password(
                DEFAULT_PASSWORD.as_bytes(),
                PBKDF2_SALT,
                PBKDF2_ITERATIONS,
            ),
        })
    }

    /// Run the MockHSM server, processing the given number of requests and then stopping
    pub fn run(&self, num_requests: usize) {
        for (i, mut request) in self.server.incoming_requests().enumerate() {
            //println!(
            //    "received request! method: {:?}, url: {:?}, headers: {:?}",
            //    request.method(),
            //    request.url(),
            //    request.headers()
            //);

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

            if i + 1 >= num_requests {
                break;
            }
        }
    }

    /// GET /connector/status - status page
    fn status(&self) -> Response<Cursor<Vec<u8>>> {
        let mut addr_parts = self.addr.split(":");

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
    fn api(&self, request: &mut Request) -> Response<Cursor<Vec<u8>>> {
        let mut body = Vec::new();
        request
            .as_reader()
            .read_to_end(&mut body)
            .expect("HTTP request read error");

        let length = BigEndian::read_u16(&body[1..3]);
        if (length + 3) as usize != body.len() {
            panic!(
                "unexpected HSM command length: {} (expected {})",
                body.len() - 3,
                length
            );
        }

        let payload = &body[3..];

        match CommandType::from_byte(body[0]).unwrap() {
            CommandType::CreateSession => self.create_session(payload),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        }
    }

    /// Create a new HSM session
    fn create_session(&self, payload: &[u8]) -> Response<Cursor<Vec<u8>>> {
        if payload.len() != 10 {
            panic!(
                "create_session: unexpected payload length {} (expected 10)",
                payload.len()
            );
        }

        let auth_key_id = BigEndian::read_u16(&payload[..2]);
        assert_eq!(
            auth_key_id, DEFAULT_AUTH_KEY_ID,
            "unexpected auth key ID: {}",
            auth_key_id
        );

        let host_challenge = Challenge::from_slice(&payload[2..]);
        let card_challenge = Challenge::random();
        let context = Context::from_challenges(&host_challenge, &card_challenge);
        let session_keys = SessionKeys::derive(&self.static_keys, &context);
        let card_cryptogram = session_keys.card_cryptogram(&context);

        // TODO: don't hardcode this
        let session_id = 0u8;

        let mut response_body = Vec::with_capacity(1 + CHALLENGE_SIZE * 2);
        response_body.push(session_id);
        response_body.extend_from_slice(card_challenge.as_slice());
        response_body.extend_from_slice(card_cryptogram.as_slice());

        respond_success(CommandType::CreateSession, &response_body)
    }
}

/// Create a response for a successful request
fn respond_success(cmd: CommandType, payload: &[u8]) -> Response<Cursor<Vec<u8>>> {
    let mut body = Vec::with_capacity(3 + payload.len());
    body.push(cmd as u8 + 128);
    body.write_u16::<BigEndian>(payload.len() as u16).unwrap();
    body.extend_from_slice(payload);

    Response::from_data(body)
}
