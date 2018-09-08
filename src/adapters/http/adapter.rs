use std::{
    fmt::Write as FmtWrite,
    io::Write as IoWrite,
    net::{TcpStream, ToSocketAddrs},
    str,
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

use super::{status::CONNECTOR_STATUS_OK, ConnectorStatus, HttpConfig, ResponseReader, USER_AGENT};
use adapters::{
    Adapter, AdapterError,
    AdapterErrorKind::{AddrInvalid, ConnectionFailed},
};

/// HTTP(-ish) adapter which supports the minimal parts of the protocol
/// required to communicate with the yubihsm-connector service.
pub struct HttpAdapter {
    /// Host we're configured to connect to (i.e. the "Host" HTTP header)
    host: String,

    /// Socket to `yubihsm-connector` process
    socket: Mutex<TcpStream>,
}

impl Adapter for HttpAdapter {
    type Config = HttpConfig;

    /// Open a connection to a `yubihsm-connector` process
    fn open(config: &Self::Config) -> Result<Self, AdapterError> {
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

    /// Check that `yubihsm-connector` is available and returning status `OK`
    fn healthcheck(&self) -> Result<(), AdapterError> {
        let status = self.status()?;

        if status.message == CONNECTOR_STATUS_OK {
            Ok(())
        } else {
            fail!(
                ConnectionFailed,
                "bad status message from yubihsm-connector: {}",
                &status.message
            );
        }
    }

    /// `POST /connector/api` with a given command message
    fn send_message(&self, uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        self.post("/connector/api", uuid, cmd)
    }
}

// TODO: use clippy's scoped lints once they work on stable
#[allow(unknown_lints, renamed_and_removed_lints, write_with_newline)]
impl HttpAdapter {
    /// GET `/connector/status` returning `adapters::http::ConnectorStatus`
    pub fn status(&self) -> Result<ConnectorStatus, AdapterError> {
        let http_response = self.get("/connector/status")?;
        ConnectorStatus::parse(str::from_utf8(&http_response)?)
    }

    /// Make an HTTP GET request to the yubihsm-connector
    fn get(&self, path: &str) -> Result<Vec<u8>, AdapterError> {
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
    fn post(&self, path: &str, uuid: Uuid, mut body: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
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
