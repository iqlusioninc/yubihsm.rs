//! Client for yubihsm-connector and main library entry point

use byteorder::{BigEndian, WriteBytesExt};
use command::{CommandType, Response};
use failure::Error;
use reqwest::{Client, StatusCode};
use reqwest::Response as HttpResponse;
use reqwest::header::{ContentType, UserAgent};
use scp03::{Challenge, IdentityKeys};
use session::Session;
use std::io::Read;
use std::u16;
use super::KeyID;

/// User-Agent string to supply
pub const USER_AGENT: &str = concat!("yubihsm-client.rs ", env!("CARGO_PKG_VERSION"));

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
    #[fail(display = "connection failed to: {}", url)]
    ConnectionFailed {
        /// URL which we attempted to connect to
        url: String,
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

    /// Serial number of YubiHSM2 device(?)
    pub serial: String,

    /// YubiHSM2 SDK version for yubihsm-connector
    pub version: String,

    /// PID of yubihsm-connector
    pub pid: u16,
}

impl Connector {
    /// Open a connection to a yubihsm-connector
    pub fn open(mut connector_url: &str) -> Result<Self, Error> {
        if !connector_url.starts_with("http://") && !connector_url.starts_with("https://") {
            Err(ConnectorError::InvalidURL)?;
        }

        // Strip trailing slash if present (all paths need to be '/'-prefixed
        if connector_url.chars().last() == Some('/') {
            connector_url = &connector_url[..connector_url.len() - 1];
        }

        let connector = Self {
            http: Client::new(),
            url: connector_url.to_owned(),
        };

        if connector.status()?.status == "OK" {
            Ok(connector)
        } else {
            Err(ConnectorError::ConnectionFailed { url: connector.url }.into())
        }
    }

    /// GET /connector/status returning the result as connector::Status
    pub fn status(&self) -> Result<Status, Error> {
        let response = String::from_utf8(self.get("/connector/status")?)?;

        let mut status: Option<&str> = None;
        let mut serial: Option<&str> = None;
        let mut version: Option<&str> = None;
        let mut pid: Option<u16> = None;

        for line in response.split("\n") {
            if line.is_empty() {
                continue;
            }

            let mut fields = line.split("=");

            let key = fields.next().ok_or_else(|| ConnectorError::ResponseError {
                description: "couldn't parse key from status line".to_owned(),
            })?;

            let value = fields.next().ok_or_else(|| ConnectorError::ResponseError {
                description: "couldn't parse value from status line".to_owned(),
            })?;

            if fields.next() != None {
                Err(ConnectorError::ResponseError {
                    description: "unexpected additional data in status line!".to_owned(),
                })?;
            }

            match key {
                "status" => status = Some(value),
                "serial" => serial = Some(value),
                "version" => version = Some(value),
                "pid" => {
                    pid = Some(value.parse().map_err(|_| ConnectorError::ResponseError {
                        description: "bad PID value in status response!".to_owned(),
                    })?)
                }
                _ => (),
            }
        }

        Ok(Status {
            status: status
                .ok_or_else(|| ConnectorError::ResponseError {
                    description: "no status in status response".to_owned(),
                })?
                .to_owned(),
            serial: serial
                .ok_or_else(|| ConnectorError::ResponseError {
                    description: "no serial in status response".to_owned(),
                })?
                .to_owned(),
            version: version
                .ok_or_else(|| ConnectorError::ResponseError {
                    description: "no version in status response".to_owned(),
                })?
                .to_owned(),
            pid: pid.ok_or_else(|| ConnectorError::ResponseError {
                description: "no PID in status response".to_owned(),
            })?,
        })
    }

    /// Open a new session to the HSM, authenticating with the given keypair
    pub fn create_session(&self, auth_key_id: KeyID, keys: IdentityKeys) -> Result<Session, Error> {
        let host_challenge = Challenge::random();
        Session::new(self, &host_challenge, auth_key_id, keys)
    }

    /// Open a new session to the HSM, authenticating with a given password
    pub fn create_session_from_password(
        &self,
        auth_key_id: KeyID,
        password: &str,
    ) -> Result<Session, Error> {
        let keys =
            IdentityKeys::derive_from_password(password.as_bytes(), PBKDF2_SALT, PBKDF2_ITERATIONS);
        self.create_session(auth_key_id, keys)
    }

    /// POST /connector/api requesting a given command type be performed with a given payload
    pub(crate) fn command(
        &self,
        cmd: CommandType,
        mut payload: Vec<u8>,
    ) -> Result<Response, Error> {
        if payload.len() > u16::MAX as usize {
            Err(ConnectorError::RequestError {
                description: format!("oversized payload: {}", payload.len()),
            })?;
        }

        let mut body = Vec::with_capacity(3 + payload.len());
        body.push(cmd as u8);
        body.write_u16::<BigEndian>(payload.len() as u16)?;
        body.append(&mut payload);

        let response_bytes = self.post("/connector/api", body)?;
        Response::parse(response_bytes)
    }

    /// Make an HTTP GET request to the yubihsm-connector
    fn get(&self, path: &str) -> Result<Vec<u8>, Error> {
        let mut response = self.http.get(&self.url_for(path)?).send()?;
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
        if !path.starts_with("/") {
            Err(ConnectorError::InvalidURL)?;
        }

        Ok(format!("{}{}", self.url, path))
    }
}

// Handle responses from Reqwest
fn handle_http_response(response: &mut HttpResponse) -> Result<Vec<u8>, Error> {
    if response.status() != StatusCode::Ok {
        Err(ConnectorError::ResponseError {
            description: format!("unexpected HTTP status: {}", response.status()),
        })?;
    }

    let mut body = Vec::new();
    response.read_to_end(&mut body)?;

    Ok(body)
}
