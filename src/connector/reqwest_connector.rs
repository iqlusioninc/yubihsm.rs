//! yubihsm-connector client implemented using the reqwest HTTP library

use std::io::Read;

use failure::Error;
use reqwest::{Client, StatusCode};
use reqwest::Response as HttpResponse;
use reqwest::header::{ContentType, UserAgent};

use super::{Connector, ConnectorError, Status, USER_AGENT};

/// reqwest-based yubihsm-connector client
pub struct ReqwestConnector {
    http: Client,
    url: String,
}

impl Connector for ReqwestConnector {
    /// Open a connection to a yubihsm-connector
    fn open(mut connector_url: &str) -> Result<Self, Error> {
        if !connector_url.starts_with("http://") && !connector_url.starts_with("https://") {
            Err(ConnectorError::InvalidURL)?;
        }

        // Strip trailing slash if present (all paths need to be '/'-prefixed
        if connector_url.ends_with('/') {
            connector_url = &connector_url[..connector_url.len() - 1];
        }

        Ok(Self {
            http: Client::new(),
            url: connector_url.to_owned(),
        })
    }

    /// GET /connector/status returning the result as connector::Status
    fn status(&mut self) -> Result<Status, Error> {
        let http_response = self.get("/connector/status")?;
        let status = String::from_utf8(http_response)?;
        Status::parse(&status)
    }

    /// POST /connector/api with a given command message
    fn send_command(&mut self, cmd: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.post("/connector/api", cmd)
    }
}

impl ReqwestConnector {
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
