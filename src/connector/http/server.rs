//! HTTP server which provides a `yubihsm-connector` compatible API.
//!
//! This is useful for when you'd like an application to talk to the YubiHSM2
//! directly, but still make use of utilities like `yubihsm-shell`.
//!
//! It's primarily intended for when a Rust application accessing the YubiHSM2
//! via USB would like to share access to it via HTTP.

// TODO(tarcieri): HTTPS support (needs `openssl`, would prefer `rustls`).
// The main use case is on localhost anyway so support is debatable

use super::config::HttpConfig;
use crate::{
    connector::{
        Connector, Error,
        ErrorKind::{AddrInvalid, RequestError},
        Message,
    },
    uuid,
};
use anomaly::format_err;
use std::{io, process, time::Instant};
use tiny_http as http;

/// `yubihsm-connector` compatible HTTP server
pub struct Server {
    /// Address to bind to
    addr: String,

    /// Port to listen on
    port: u16,

    /// HTTP server
    server: http::Server,

    /// YubiHSM2 connector
    connector: Connector,
}

impl Server {
    /// Create a new HTTP service which provides access to the YubiHSM2
    pub fn new(config: &HttpConfig, connector: Connector) -> Result<Server, Error> {
        let server = http::Server::http(format!("{}:{}", &config.addr, config.port))
            .map_err(|e| format_err!(AddrInvalid, "couldn't create HTTP server: {}", e))?;

        info!(
            "yubihsm::http-server[{}:{}]: listening for connections",
            &config.addr, config.port
        );

        Ok(Self {
            addr: config.addr.clone(),
            port: config.port,
            server,
            connector,
        })
    }

    /// Run the server's main loop, processing incoming requests
    pub fn run(&self) -> Result<(), Error> {
        loop {
            self.handle_request()?;
        }
    }

    /// Handle an incoming HTTP request
    pub fn handle_request(&self) -> Result<(), Error> {
        let mut request = self.server.recv()?;

        let response = match *request.method() {
            http::Method::Get => match request.url() {
                "/connector/status" => Some(self.status()?),
                _ => None,
            },
            http::Method::Post => match request.url() {
                "/connector/api" => Some(self.api(&mut request)?),
                _ => None,
            },
            _ => None,
        }
        .unwrap_or_else(|| {
            http::Response::new(
                http::StatusCode::from(404),
                vec![],
                io::Cursor::new(vec![]),
                None,
                None,
            )
        });

        request.respond(response)?;
        Ok(())
    }

    /// `GET /connector/status` - status page
    fn status(&self) -> Result<http::Response<io::Cursor<Vec<u8>>>, Error> {
        info!(
            "yubihsm::http-server[{}:{}]: GET /connector/status",
            &self.addr, self.port
        );

        let status = [
            ("status", "OK"),
            ("serial", "*"),
            ("version", env!("CARGO_PKG_VERSION")),
            ("pid", &process::id().to_string()),
            ("address", &self.addr),
            ("port", &self.port.to_string()),
        ];

        let body = status
            .iter()
            .map(|(k, v)| [*k, *v].join("\n"))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(http::Response::from_string(body))
    }

    /// `POST /connector/api` - send message to the YubiHSM 2
    fn api(
        &self,
        request: &mut http::Request,
    ) -> Result<http::Response<io::Cursor<Vec<u8>>>, Error> {
        let mut body = Vec::new();
        request.as_reader().read_to_end(&mut body)?;

        let command_msg = Message::from(body);
        let command = command_msg
            .clone()
            .parse()
            .map_err(|e| format_err!(RequestError, "couldn't parse request message: {}", e))?;

        let started_at = Instant::now();
        let response_msg = self.connector.send_message(uuid::new_v4(), command_msg)?;

        let session = command
            .session_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".to_owned());

        info!(
            "yubihsm::http-server[{}:{}]: POST /connector/api - session:{} cmd:{:?} t:{}ms",
            &self.addr,
            self.port,
            &session,
            command.command_type,
            started_at.elapsed().as_millis()
        );

        Ok(http::Response::from_data(response_msg.as_ref()))
    }
}
