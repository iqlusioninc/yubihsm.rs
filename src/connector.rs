//! Client for yubihsm-connector and main library entry point

use std::io::Read;

use failure::Error;
use reqwest::{Client, StatusCode};
use reqwest::Response as HttpResponse;
use reqwest::header::{ContentType, UserAgent};

use ObjectId;
use securechannel::{Challenge, CommandMessage, ResponseMessage, StaticKeys};
use session::Session;

/// User-Agent string to supply
pub const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));

/// Salt value to use with PBKDF2
pub const PBKDF2_SALT: &[u8] = b"Yubico";

/// Number of PBKDF2 iterations to perform
pub const PBKDF2_ITERATIONS: usize = 10_000;

/// yubihsm-connector client
pub struct Connector {
    http: Client,
    url: String,
}

/// yubihsm-connector related errors
#[derive(Debug, Fail)]
pub enum ConnectorError {
    /// URL provided for yubihsm-connector is not valid
    #[fail(display = "invalid URL")]
    InvalidURL,

    /// Connection to yubihsm-connector failed
    #[fail(display = "connection failed: {}", description)]
    ConnectionFailed {
        /// Description of why the connection failed
        description: String,
    },

    /// Error making request
    #[fail(display = "invalid request: {}", description)]
    RequestError {
        /// Description of the error
        description: String,
    },

    /// yubihsm-connector sent bad response
    #[fail(display = "bad response from yubihsm-connector: {}", description)]
    ResponseError {
        /// Description of the bad response we received
        description: String,
    },
}

/// yubihsm-connector status
#[derive(Debug)]
pub struct Status {
    /// Status message for yubihsm-connector e.g. "OK"
    pub status: String,

    /// Serial number of `YubiHSM2` device(?)
    pub serial: String,

    /// `YubiHSM2` SDK version for yubihsm-connector
    pub version: String,

    /// PID of yubihsm-connector
    pub pid: u32,
}

impl Connector {
    /// Open a connection to a yubihsm-connector
    pub fn open(mut connector_url: &str) -> Result<Self, Error> {
        if !connector_url.starts_with("http://") && !connector_url.starts_with("https://") {
            Err(ConnectorError::InvalidURL)?;
        }

        // Strip trailing slash if present (all paths need to be '/'-prefixed
        if connector_url.ends_with('/') {
            connector_url = &connector_url[..connector_url.len() - 1];
        }

        let connector = Self {
            http: Client::new(),
            url: connector_url.to_owned(),
        };

        if connector.status()?.status == "OK" {
            Ok(connector)
        } else {
            fail!(
                ConnectorError::ConnectionFailed,
                "bad status response from {}",
                connector.url
            );
        }
    }

    /// GET /connector/status returning the result as connector::Status
    pub fn status(&self) -> Result<Status, Error> {
        let response = String::from_utf8(self.get("/connector/status")?)?;

        let mut status: Option<&str> = None;
        let mut serial: Option<&str> = None;
        let mut version: Option<&str> = None;
        let mut pid: Option<u32> = None;

        for line in response.split('\n') {
            if line.is_empty() {
                continue;
            }

            let mut fields = line.split('=');

            let key = fields
                .next()
                .ok_or_else(|| err!(ConnectorError::ResponseError, "couldn't parse key"))?;

            let value = fields
                .next()
                .ok_or_else(|| err!(ConnectorError::ResponseError, "couldn't parse value"))?;

            if let Some(remaining) = fields.next() {
                fail!(
                    ConnectorError::ResponseError,
                    "unexpected additional data: {}",
                    remaining
                )
            }

            match key {
                "status" => status = Some(value),
                "serial" => serial = Some(value),
                "version" => version = Some(value),
                "pid" => {
                    pid = Some(value.parse().map_err(|_| {
                        err!(ConnectorError::ResponseError, "invalid PID: {}", value)
                    })?)
                }
                _ => (),
            }
        }

        Ok(Status {
            status: status
                .ok_or_else(|| err!(ConnectorError::ResponseError, "missing status"))?
                .to_owned(),
            serial: serial
                .ok_or_else(|| err!(ConnectorError::ResponseError, "missing serial"))?
                .to_owned(),
            version: version
                .ok_or_else(|| err!(ConnectorError::ResponseError, "missing version"))?
                .to_owned(),
            pid: pid.ok_or_else(|| err!(ConnectorError::ResponseError, "missing PID"))?,
        })
    }

    /// Open a new session to the HSM, authenticating with the given keypair
    pub fn create_session(
        &self,
        auth_key_id: ObjectId,
        static_keys: &StaticKeys,
    ) -> Result<Session, Error> {
        let host_challenge = Challenge::random();
        Session::new(self, &host_challenge, auth_key_id, static_keys)
    }

    /// Open a new session to the HSM, authenticating with a given password
    pub fn create_session_from_password(
        &self,
        auth_key_id: ObjectId,
        password: &str,
    ) -> Result<Session, Error> {
        self.create_session(
            auth_key_id,
            &StaticKeys::derive_from_password(password.as_bytes(), PBKDF2_SALT, PBKDF2_ITERATIONS),
        )
    }

    /// POST /connector/api with a given command message
    pub(crate) fn send_command(&self, cmd: CommandMessage) -> Result<ResponseMessage, Error> {
        let cmd_type = cmd.command_type;
        let response_bytes = self.post("/connector/api", cmd.into())?;
        let response = ResponseMessage::parse(response_bytes)?;

        if response.is_err() {
            fail!(
                ConnectorError::ResponseError,
                "Error response code from HSM: {:?}",
                response.code
            );
        }

        if response.command().unwrap() != cmd_type {
            fail!(
                ConnectorError::ResponseError,
                "command type mismatch: expected {:?}, got {:?}",
                cmd_type,
                response.command().unwrap()
            );
        }

        Ok(response)
    }

    /// Make an HTTP GET request to the yubihsm-connector
    fn get(&self, path: &str) -> Result<Vec<u8>, Error> {
        let mut response = self.http
            .get(&self.url_for(path)?)
            .header(UserAgent::new(USER_AGENT))
            .send()?;

        handle_http_response(&mut response)
    }

    /// Make an HTTP POST request to the yubihsm-connector
    fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut response = self.http
            .post(&self.url_for(path)?)
            .header(ContentType::octet_stream())
            .header(UserAgent::new(USER_AGENT))
            .body(body)
            .send()?;

        handle_http_response(&mut response)
    }

    /// Obtain the full URL for a given path
    fn url_for(&self, path: &str) -> Result<String, Error> {
        // All paths must start with '/'
        if !path.starts_with('/') {
            Err(ConnectorError::InvalidURL)?;
        }

        Ok(format!("{}{}", self.url, path))
    }
}

// Handle responses from Reqwest
fn handle_http_response(response: &mut HttpResponse) -> Result<Vec<u8>, Error> {
    if response.status() != StatusCode::Ok {
        fail!(
            ConnectorError::ResponseError,
            "unexpected HTTP status: {}",
            response.status()
        );
    }

    let mut body = Vec::new();
    response.read_to_end(&mut body)?;

    Ok(body)
}
