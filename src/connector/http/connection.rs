//! Persistent HTTP connection to `yubihsm-connector`

use std::io::Read;
use std::time::Duration;
#[cfg(feature = "_tls")]
use std::sync::Arc;
#[cfg(feature = "native-tls")]
use native_tls::{Certificate, TlsConnector};
#[cfg(feature = "rustls")]
use rustls::ClientConfig;
use ureq::{Agent, AgentBuilder};
use super::{config::HttpConfig};
use crate::connector::{self, Connection};
use uuid::Uuid;

const MAX_BODY_SIZE: u64 = 1024 ^ 3;/*1MB*/
const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));

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
    agent: Agent,

    base_url: String,
}

impl HttpConnection {
    /// Open a connection to a `yubihsm-connector` service
    pub(crate) fn open(config: &HttpConfig) -> Result<Self, connector::Error> {
        let mut agent = AgentBuilder::new()
            .timeout(Duration::from_millis(config.timeout_ms))
            .user_agent(USER_AGENT);

        #[cfg(feature = "native-tls")]
        if config.tls {
            agent = agent.tls_connector(Arc::new(build_tls_connector(config)?));
        }

        #[cfg(feature = "rustls")]
        if config.tls {
            agent = agent.tls_config(Arc::new(build_tls_config(config)?));
        }

        Ok(HttpConnection {
            agent: agent.build(),
            base_url: format!("{config}"),
        })
    }

    /// Make an HTTP POST request to a `yubihsm-connector` service
    pub(super) fn post(
        &self,
        path: &str,
        uuid: Uuid,
        body: &[u8],
    ) -> Result<Vec<u8>, connector::Error> {
        let response = self.agent.post(&format!("{}{}", self.base_url, path))
            .set("X-Request-ID", &uuid.to_string())
            .send_bytes(body)?;

        let mut data = response.header("Content-Length")
            .and_then(|len| len.parse::<usize>().ok())
            .map(|len| Vec::with_capacity(len))
            .unwrap_or(Vec::new());

        response.into_reader().take(MAX_BODY_SIZE).read_to_end(&mut data)?;
        Ok(data)
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

#[cfg(feature = "native-tls")]
fn build_tls_connector(config: &HttpConfig) -> Result<TlsConnector, connector::Error> {
    use std::fs;
    use crate::connector::ErrorKind;

    let mut builder = TlsConnector::builder();

    if let Some(path) = config.cacert.as_ref() {
        let data = fs::read(path)?;
        let cert = Certificate::from_pem(&data)
            .map_err(|e| ErrorKind::IoError.context(e))?;

        builder.add_root_certificate(cert);
    }

    builder.build()
        .map_err(|e| ErrorKind::IoError.context(e).into())
}

#[cfg(feature = "rustls")]
pub fn build_tls_config(config: &HttpConfig) -> Result<ClientConfig, connector::Error> {
    use std::fs::File;
    use std::io::BufReader;
    use rustls::RootCertStore;
    use crate::connector::ErrorKind;

    match config.cacert.as_ref() {
        None => Ok(rustls_platform_verifier::tls_config()),
        Some(cert_path) => {
            let mut root_store = RootCertStore::empty();
            let mut reader = BufReader::new(File::open(cert_path)?);
            for cert in rustls_pemfile::certs(&mut reader) {
                root_store.add(cert?)
                    .map_err(|e| ErrorKind::IoError.context(e))?;
            }
            Ok(ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth())
        }
    }
}
