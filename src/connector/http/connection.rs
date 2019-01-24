//! Persistent HTTP connection to `yubihsm-connector`

use gaunt;
use uuid::Uuid;

use super::config::HttpConfig;
use crate::connector::{Connection, ConnectionError};

/// Connection to YubiHSM via HTTP requests to `yubihsm-connector`.
///
/// The `yubihsm-connector` service is a small HTTP(S) service which exposes a
/// YubiHSM2 to a network, allowing several clients using it concurrently.
///
/// This connection communicates with a YubiHSM2 via `yubihsm-connector`. For
/// more information on `yubihsm-connector`, see:
///
/// <https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/>
pub struct HttpConnection(gaunt::Connection);

// TODO: use clippy's scoped lints once they work on stable
#[allow(unknown_lints, renamed_and_removed_lints, write_with_newline)]
impl HttpConnection {
    /// Open a connection to a `yubihsm-connector` service
    pub(crate) fn open(config: &HttpConfig) -> Result<Self, ConnectionError> {
        Ok(HttpConnection(gaunt::Connection::new(
            &config.addr,
            config.port,
            &Default::default(),
        )?))
    }

    /// Make an HTTP GET request to a `yubihsm-connector` service
    pub(super) fn get(&self, path: &str) -> Result<Vec<u8>, ConnectionError> {
        Ok(self.0.get(path, &Default::default())?.into_vec())
    }

    /// Make an HTTP POST request to a `yubihsm-connector` service
    pub(super) fn post(
        &self,
        path: &str,
        _uuid: Uuid,
        body: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        // TODO: send UUID as `X-Request-ID` header, zero copy body creation
        Ok(self
            .0
            .post(path, &gaunt::request::Body::from(body))?
            .into_vec())
    }
}

impl Connection for HttpConnection {
    /// `POST /connector/api` with a given command message
    fn send_message(&self, uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, ConnectionError> {
        self.post("/connector/api", uuid, &cmd)
    }
}
