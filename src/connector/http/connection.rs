//! Persistent HTTP connection to `yubihsm-connector`
//!
//! This module implements a small, minimalistic HTTP client designed
//! specifically to work with `yubihsm-connector`.
//!
//! TODO: HTTPS support: https://github.com/tendermint/yubihsm-rs/issues/37

use std::{
    fmt::Write as FmtWrite,
    io::Write as IoWrite,
    net::{TcpStream, ToSocketAddrs},
    str,
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

use super::{HttpConfig, ResponseReader, USER_AGENT};
use connector::{Connection, ConnectionError, ConnectionErrorKind::*};

/// Connection to YubiHSM via HTTP requests to `yubihsm-connector`.
///
/// The `yubihsm-connector` service is a small HTTP(S) service which exposes a
/// YubiHSM2 to a network, allowing several clients using it concurrently.
///
/// This connection communicates with a YubiHSM2 via `yubihsm-connector`. For
/// more information on `yubihsm-connector`, see:
///
/// <https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/>
pub struct HttpConnection {
    /// Host we're configured to connect to (i.e. the "Host" HTTP header)
    host: String,

    /// Socket to `yubihsm-connector` process
    socket: Mutex<TcpStream>,
}

// TODO: use clippy's scoped lints once they work on stable
#[allow(unknown_lints, renamed_and_removed_lints, write_with_newline)]
impl HttpConnection {
    /// Open a connection to a `yubihsm-connector` process
    pub(crate) fn open(config: &HttpConfig) -> Result<Self, ConnectionError> {
        let host = format!("{}:{}", config.addr, config.port);
        let timeout = Duration::from_millis(config.timeout_ms);

        // Resolve DNS, and for now pick the first available address
        // TODO: round robin DNS support?
        let socketaddr = &host.to_socket_addrs()?.next().ok_or_else(|| {
            err!(
                AddrInvalid,
                "couldn't resolve DNS for {}",
                host.split(':').next().unwrap()
            )
        })?;

        let socket = TcpStream::connect_timeout(socketaddr, timeout)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        Ok(Self {
            host,
            socket: Mutex::new(socket),
        })
    }

    /// Make an HTTP GET request to the yubihsm-connector
    pub(super) fn get(&self, path: &str) -> Result<Vec<u8>, ConnectionError> {
        let mut request = String::new();

        write!(request, "GET {} HTTP/1.1\r\n", path)?;
        write!(request, "Host: {}\r\n", self.host)?;
        write!(request, "User-Agent: {}\r\n", USER_AGENT)?;
        write!(request, "Content-Length: 0\r\n\r\n")?;

        let mut socket = self.socket.lock().unwrap();

        let request_start = Instant::now();
        socket.write_all(request.as_bytes())?;

        let response = ResponseReader::read(&mut socket)?;
        let elapsed_time = Instant::now().duration_since(request_start);

        http_debug!(
            self,
            "method=GET path={} t={}ms",
            path,
            elapsed_time.as_secs() * 1000 + u64::from(elapsed_time.subsec_millis())
        );

        Ok(response.into())
    }

    /// Make an HTTP POST request to the yubihsm-connector
    pub(super) fn post(
        &self,
        path: &str,
        uuid: Uuid,
        mut body: Vec<u8>,
    ) -> Result<Vec<u8>, ConnectionError> {
        let mut headers = String::new();

        write!(headers, "POST {} HTTP/1.1\r\n", path)?;
        write!(headers, "Host: {}\r\n", self.host)?;
        write!(headers, "User-Agent: {}\r\n", USER_AGENT)?;
        write!(headers, "X-Request-ID: {}\r\n", uuid)?;
        write!(headers, "Content-Length: {}\r\n\r\n", body.len())?;

        // It's friendlier to Nagle's algorithm if we combine the request
        // headers and body, especially if the request fits in a single packet
        let mut request: Vec<u8> = headers.into();
        request.append(&mut body);

        let mut socket = self.socket.lock().unwrap();

        let request_start = Instant::now();
        socket.write_all(&request)?;

        let response = ResponseReader::read(&mut socket)?;
        let elapsed_time = Instant::now().duration_since(request_start);

        http_debug!(
            self,
            "method=POST path={} uuid={} t={}ms",
            path,
            uuid,
            elapsed_time.as_secs() * 1000 + u64::from(elapsed_time.subsec_millis())
        );

        Ok(response.into())
    }
}

impl Connection for HttpConnection {
    /// `POST /connector/api` with a given command message
    fn send_message(&self, uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, ConnectionError> {
        self.post("/connector/api", uuid, cmd)
    }
}
