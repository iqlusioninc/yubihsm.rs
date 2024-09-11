//! Persistent HTTP connection to `yubihsm-connector`

use super::config::HttpConfig;
use crate::connector::{self, Connection};
use std::io::Read;
use std::time::Duration;
#[cfg(feature = "_tls")]
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};
use ureq::Agent;
use uuid::Uuid;

const MAX_BODY_SIZE: u64 = 1024 ^ 3; /*1MB*/
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
        let builder = Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(config.timeout_ms)))
            .user_agent(USER_AGENT);

        #[cfg(feature = "_tls")]
        let mut builder = builder;

        #[cfg(feature = "_tls")]
        if config.tls {
            builder = builder.tls_config(build_tls_config(config)?);
        }

        Ok(HttpConnection {
            agent: builder.build().into(),
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
        let response = self
            .agent
            .post(&format!("{}{}", self.base_url, path))
            .header("X-Request-ID", &uuid.to_string())
            .send(body)?;

        let mut data = response
            .headers()
            .get("Content-Length")
            .and_then(|len| len.to_str().ok())
            .and_then(|len| len.parse().ok())
            .map(|len| Vec::with_capacity(len))
            .unwrap_or(Vec::new());

        response
            .into_body()
            .as_reader()
            .take(MAX_BODY_SIZE)
            .read_to_end(&mut data)?;
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

#[cfg(feature = "_tls")]
fn build_tls_config(config: &HttpConfig) -> Result<TlsConfig, connector::Error> {
    use crate::connector::ErrorKind;
    use std::fs;
    use std::sync::Arc;

    // to avoid clippy error when running with --all-features
    // use _provider as `rustls` and `native-tls` should be exclusive

    #[cfg(feature = "native-tls")]
    let _provider = TlsProvider::NativeTls;

    #[cfg(feature = "rustls")]
    let _provider = TlsProvider::Rustls;

    let certs = match config.cacert.as_ref() {
        Some(path) => {
            let data = fs::read(path)?;
            let cert = Certificate::from_pem(&data).map_err(|e| ErrorKind::IoError.context(e))?;

            RootCerts::Specific(Arc::new(vec![cert]))
        }
        None => RootCerts::PlatformVerifier,
    };

    Ok(TlsConfig::builder()
        .provider(_provider)
        .root_certs(certs)
        .build())
}
