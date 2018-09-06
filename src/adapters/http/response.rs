use std::{io::Read, net::TcpStream, str};

use super::MAX_RESPONSE_SIZE;
use adapters::{AdapterError, AdapterErrorKind::ResponseError};

/// The Transfer-Encoding Header
const TRANSFER_ENCODING_HEADER: &str = "Transfer-Encoding: ";

/// Delimiter string that separates HTTP headers from bodies
const HEADER_DELIMITER: &[u8] = b"\r\n\r\n";

/// HTTP response status indicating success
const HTTP_SUCCESS_STATUS: &str = "HTTP/1.1 200 OK";

/// The Content-Length Header
const CONTENT_LENGTH_HEADER: &str = "Content-Length: ";

/// Buffered reader for short (i.e. 8kB or less) HTTP responses
pub(super) struct ResponseReader {
    /// Data buffer
    buffer: [u8; MAX_RESPONSE_SIZE],

    /// Position inside of the data buffer
    pos: usize,

    /// Position at which the body begins
    body_offset: Option<usize>,

    /// Length of the body (if we're received it)
    content_length: usize,
}

impl ResponseReader {
    /// Create a new response buffer
    pub fn read(socket: &mut TcpStream) -> Result<Self, AdapterError> {
        let mut buffer = Self {
            buffer: [0u8; MAX_RESPONSE_SIZE],
            pos: 0,
            body_offset: None,
            content_length: 0,
        };

        buffer.read_headers(socket)?;
        buffer.read_body(socket)?;

        Ok(buffer)
    }

    /// Read some data into the internal buffer
    fn fill_buffer(&mut self, socket: &mut TcpStream) -> Result<usize, AdapterError> {
        let nbytes = socket.read(&mut self.buffer[..])?;
        self.pos += nbytes;
        Ok(nbytes)
    }

    /// Read the HTTP response headers
    fn read_headers(&mut self, socket: &mut TcpStream) -> Result<(), AdapterError> {
        assert!(self.body_offset.is_none(), "already read headers!");

        loop {
            self.fill_buffer(socket)?;

            // Scan the buffer for the header delimiter
            // TODO: this is less efficient than it should be
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

    /// Parse the HTTP headers, extracting the Content-Length
    fn parse_headers(&mut self) -> Result<(), AdapterError> {
        let body_offset = self.body_offset.unwrap();
        let header_str = str::from_utf8(&self.buffer[..body_offset])?;

        let mut header_iter = header_str.split("\r\n");

        // Ensure we got a 200 OK status
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
                    "adapter sent unsupported transfer encoding: {}",
                    transfer_encoding
                );
            }
        }

        Ok(())
    }

    /// Read the response body into the internal buffer
    fn read_body(&mut self, socket: &mut TcpStream) -> Result<(), AdapterError> {
        let body_end =
            self.content_length + self.body_offset.expect("not ready to read the body yet");

        while self.pos < body_end {
            self.fill_buffer(socket)?;
        }

        Ok(())
    }
}

impl Into<Vec<u8>> for ResponseReader {
    fn into(self) -> Vec<u8> {
        let body_offset = self
            .body_offset
            .expect("we should've already read the body");

        Vec::from(&self.buffer[body_offset..self.pos])
    }
}
