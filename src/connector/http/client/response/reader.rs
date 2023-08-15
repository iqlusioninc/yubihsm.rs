//! Read HTTP responses from an `io::Read`

#![allow(clippy::manual_strip)]

use super::Body;
use crate::connector::http::client::Error;
use std::{io::Read, str, vec::Vec};

const TRANSFER_ENCODING_HEADER: &str = "Transfer-Encoding: ";
const HEADER_DELIMITER: &[u8] = b"\r\n\r\n";
const HTTP_SUCCESS_STATUS: &str = "HTTP/1.1 200 OK";
const CONTENT_LENGTH_HEADER: &str = "Content-Length: ";

/// Maximum response size we can parse.
// TODO: we shouldn't have a max, or at least one this small
const MAX_RESPONSE_SIZE: usize = 65536;

/// Read HTTP responses from the server
pub struct Reader {
    /// Internal buffer
    buffer: Vec<u8>,

    /// Position within the response
    pos: usize,

    /// Offset into the body we've ready so far
    body_offset: Option<usize>,

    /// Total length of the response content
    content_length: usize,
}

impl Reader {
    /// Create a new `response::Reader` that consumes a response body from a socket
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(readable: &mut dyn Read) -> Result<Self, Error> {
        // TODO: better buffering
        let mut buffer = Self {
            buffer: vec![0u8; MAX_RESPONSE_SIZE],
            pos: 0,
            body_offset: None,
            content_length: 0,
        };

        buffer.read_headers(readable)?;
        buffer.read_body(readable)?;

        Ok(buffer)
    }

    /// Convert this `response::Reader` into a `response::Body`
    pub(crate) fn into_body(self) -> Body {
        let body_offset = self
            .body_offset
            .expect("we should've already read the body");

        Body(Vec::from(&self.buffer[body_offset..self.pos]))
    }

    /// Fill the internal buffer with data from the socket
    fn fill_buffer(&mut self, readable: &mut dyn Read) -> Result<usize, Error> {
        let nbytes = readable.read(self.buffer.as_mut())?;
        self.pos += nbytes;

        // See: https://doc.rust-lang.org/src/std/io/mod.rs.html#571
        // On Linux, read method will call the recv syscall for a TcpStream,
        // where returning zero indicates the connection was shut down correctly
        if nbytes == 0 {
            fail!(
                ResponseError,
                "read {} bytes, the remote connection was likely shutdown",
                nbytes
            );
        }

        Ok(nbytes)
    }

    /// Read the response headers
    fn read_headers(&mut self, readable: &mut dyn Read) -> Result<(), Error> {
        assert!(self.body_offset.is_none(), "already read headers!");

        loop {
            self.fill_buffer(readable)?;

            // Scan for the header delimiter
            // TODO: real parser
            let mut offset = 0;
            while self.buffer[offset..].len() > HEADER_DELIMITER.len() {
                if self.buffer[offset..].starts_with(HEADER_DELIMITER) {
                    self.body_offset = Some(offset + HEADER_DELIMITER.len());
                    break;
                } else {
                    offset += 1;
                }
            }

            if self.body_offset.is_some() {
                break;
            } else if self.pos + 1 >= MAX_RESPONSE_SIZE {
                fail!(
                    ResponseError,
                    "exceeded {}-byte response limit reading headers",
                    MAX_RESPONSE_SIZE
                );
            }
        }

        self.parse_headers()
    }

    /// Parse the response headers
    fn parse_headers(&mut self) -> Result<(), Error> {
        let body_offset = self.body_offset.unwrap();
        let header_str = str::from_utf8(&self.buffer[..body_offset])?;
        let mut header_iter = header_str.split("\r\n");

        match header_iter.next() {
            Some(HTTP_SUCCESS_STATUS) => (),
            Some(status) => fail!(
                ResponseError,
                "unexpected HTTP response status: \"{}\"",
                status
            ),
            None => fail!(ResponseError, "HTTP response status line missing!"),
        }

        for header in header_iter {
            if header.starts_with(CONTENT_LENGTH_HEADER) {
                let content_length: usize = header[CONTENT_LENGTH_HEADER.len()..].parse()?;

                if MAX_RESPONSE_SIZE - body_offset < content_length {
                    fail!(
                        ResponseError,
                        "response body length too large for buffer ({} bytes)",
                        content_length
                    );
                }

                self.content_length = content_length;
            } else if header.starts_with(TRANSFER_ENCODING_HEADER) {
                let transfer_encoding = &header[TRANSFER_ENCODING_HEADER.len()..];
                fail!(
                    ResponseError,
                    "connection sent unsupported transfer encoding: {}",
                    transfer_encoding
                );
            }
        }

        Ok(())
    }

    /// Read the response body into the internal buffer
    fn read_body(&mut self, readable: &mut dyn Read) -> Result<(), Error> {
        let body_end =
            self.content_length + self.body_offset.expect("not ready to read the body yet");

        while self.pos < body_end {
            self.fill_buffer(readable)?;
        }

        Ok(())
    }
}
