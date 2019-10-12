//! Persistent HTTP connection to `yubihsm-connector`

use super::config::HttpConfig;
use crate::connector::{self, Connection};
use uuid::Uuid;

// TODO: send user agent string
// User-Agent string to supply
// pub const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));

/// Connection to YubiHSM via HTTP requests to `yubihsm-connector`.
///
/// The `yubihsm-connector` service is a small HTTP(S) service which exposes a
/// YubiHSM 2 to a network, allowing several clients using it concurrently.
///
/// This connection communicates with a YubiHSM 2 via `yubihsm-connector`. For
/// more information on `yubihsm-connector`, see:
///
/// <https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/>
pub struct HttpConnection {
    /// HTTP connection
    connection: harp::Connection,
}

impl HttpConnection {
    /// Open a connection to a `yubihsm-connector` service
    pub(crate) fn open(config: &HttpConfig) -> Result<Self, connector::Error> {
        let connection = harp::Connection::open(&config.addr, config.port, &Default::default())?;

        Ok(HttpConnection { connection })
    }

    /// Make an HTTP POST request to a `yubihsm-connector` service
    pub(super) fn post(
        &self,
        path: &str,
        _uuid: Uuid,
        body: &[u8],
    ) -> Result<Vec<u8>, connector::Error> {
        // TODO: send UUID as `X-Request-ID` header, zero copy body creation
        Ok(self
            .connection
            .post(path, &harp::request::Body::new(body))?
            .into_vec())
    }
}

impl Connection for HttpConnection {
    /// `POST /connector/api` with a given command message
    fn send_message(
        &self,
        uuid: Uuid,
        cmd: connector::Message,
    ) -> Result<connector::Message, connector::Error> {
        self.post("/connector/api", uuid, cmd.as_ref())
            .map(Into::into)
    }
}
