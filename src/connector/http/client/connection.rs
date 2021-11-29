//! Connections to HTTP servers

use std::{
    fmt::Write as FmtWrite,
    io::Write,
    net::{TcpStream, ToSocketAddrs},
    ops::DerefMut,
    string::String,
    sync::Mutex,
    time::Duration,
    vec::Vec,
};

use super::{error::Error, path::PathBuf, request, response, HTTP_VERSION, USER_AGENT};

/// Default timeout in milliseconds (20 seconds)
const DEFAULT_TIMEOUT_MS: u64 = 20000;

/// Options when building a `Connection`
pub struct ConnectionOptions {
    timeout: Duration,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

/// HTTP connection to a remote host
pub struct Connection {
    /// Host header to send in HTTP requests
    host: String,

    /// Open TCP socket to remote host
    socket: Mutex<TcpStream>,
}

impl Connection {
    /// Create a new connection to an HTTP server
    pub fn open(addr: &str, port: u16, opts: &ConnectionOptions) -> Result<Self, Error> {
        let host = format!("{}:{}", addr, port);

        let socketaddr = &host.to_socket_addrs()?.next().ok_or_else(|| {
            err!(
                AddrInvalid,
                "couldn't resolve DNS for {}",
                host.split(':').next().unwrap()
            )
        })?;

        // TODO: better timeout handling?
        let socket = TcpStream::connect_timeout(socketaddr, opts.timeout)?;
        socket.set_read_timeout(Some(opts.timeout))?;
        socket.set_write_timeout(Some(opts.timeout))?;

        Ok(Self {
            host,
            socket: Mutex::new(socket),
        })
    }

    /// Make an HTTP POST request to the given path
    pub fn post<P: Into<PathBuf>>(
        &self,
        into_path: P,
        body: &request::Body,
    ) -> Result<response::Body, Error> {
        let path = into_path.into();
        let mut headers = String::new();

        writeln!(headers, "POST {} {}\r", path, HTTP_VERSION)?;
        writeln!(headers, "Host: {}\r", self.host)?;
        writeln!(headers, "User-Agent: {}\r", USER_AGENT)?;
        writeln!(headers, "Content-Length: {}\r", body.0.len())?;
        writeln!(headers, "\r")?;

        // Make a Nagle-friendly request by combining headers and body
        let mut request: Vec<u8> = headers.into();
        request.extend_from_slice(body.0.as_slice());

        let mut socket = self.socket.lock().unwrap();
        socket.write_all(&request)?;

        let response_body = response::Reader::new(socket.deref_mut())?.into_body();
        Ok(response_body)
    }
}
