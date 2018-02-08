//! Client for yubihsm-connector

use failure::Error;
use reqwest::{Client, StatusCode};
use std::io::Read;

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

    /// Make an HTTP GET request to the yubihsm-connector
    pub fn get(&self, path: &str) -> Result<Vec<u8>, Error> {
        // All paths must start with '/'
        if !path.starts_with("/") {
            Err(ConnectorError::InvalidURL)?;
        }

        let url = format!("{}{}", self.url, path);
        let mut response = self.http.get(&url).send()?;

        if response.status() != StatusCode::Ok {
            Err(ConnectorError::ResponseError {
                description: format!("unexpected HTTP status: {}", response.status()),
            })?;
        }

        let mut body = Vec::new();
        response.read_to_end(&mut body)?;

        Ok(body)
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
}

#[cfg(test)]
mod tests {
    use super::Connector;

    const DEFAULT_CONNECTOR_URL: &str = "http://127.0.0.1:12345";

    #[test]
    fn test_connect() {
        Connector::open(DEFAULT_CONNECTOR_URL).unwrap_or_else(|err| {
            panic!("cannot open connection to yubihsm-connector: {:?}", err)
        });
    }
}
