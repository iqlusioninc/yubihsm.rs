use reqwest::{Client, StatusCode};
use std::io::Read;

/// yubihsm-connector client
pub struct Connector {
    http: Client,
    url: String,
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
    pub fn open(mut connector_url: &str) -> Self {
        if connector_url.chars().last() == Some('/') {
            connector_url = &connector_url[..connector_url.len() - 1];
        }

        let connector = Self {
            http: Client::new(),
            url: connector_url.to_owned(),
        };

        if connector.status().status != "OK" {
            panic!("bad connector status")
        }

        connector
    }

    /// Make an HTTP GET request to the yubihsm-connector
    pub fn get(&self, path: &str) -> Vec<u8> {
        let url = format!("{}{}", self.url, path);
        let mut response = self.http.get(&url).send().expect("HTTP request failed");

        if response.status() != StatusCode::Ok {
            panic!("unexpected HTTP status: {}", response.status())
        }

        let mut body = Vec::new();
        response
            .read_to_end(&mut body)
            .expect("HTTP body read failed");

        body
    }

    /// GET /connector/status returning the result as connector::Status
    pub fn status(&self) -> Status {
        let response = String::from_utf8(self.get("/connector/status")).expect("invalid UTF-8!");

        let mut status: Option<&str> = None;
        let mut serial: Option<&str> = None;
        let mut version: Option<&str> = None;
        let mut pid: Option<u16> = None;

        for line in response.split("\n") {
            if line.is_empty() {
                continue;
            }

            let mut fields = line.split("=");
            let key = fields.next().expect("couldn't parse key!");
            let value = fields.next().expect("couldn't parse value!");

            if fields.next() != None {
                panic!("Unexpected additional data in line!")
            }

            match key {
                "status" => status = Some(value),
                "serial" => serial = Some(value),
                "version" => version = Some(value),
                "pid" => pid = Some(value.parse().expect("PID with value 0-65535")),
                _ => (),
            }
        }

        Status {
            status: status.expect("no status in response!").to_owned(),
            serial: serial.expect("no serial in response!").to_owned(),
            version: version.expect("no version in response!").to_owned(),
            pid: pid.expect("no pid in response!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Connector;

    const DEFAULT_CONNECTOR_URL: &str = "http://127.0.0.1:12345";

    #[test]
    fn test_connect() {
        Connector::open(DEFAULT_CONNECTOR_URL);
    }
}
