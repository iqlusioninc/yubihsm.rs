//! HTTPS connector regression tests.
//!
//! These do not need a `yubihsm-connector`: they only need the TLS connector to
//! actually get built, which happens once a TCP connection is established.

#![cfg(feature = "_tls")]

use std::net::TcpListener;
use yubihsm::connector::HttpConfig;

/// Accept and immediately drop connections, so ureq gets far enough to build
/// its TLS connector and apply the root-certificate choice.
fn dead_tls_listener() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });

    port
}

/// With no `cacert` configured we verify against the OS trust store. Under
/// rustls that requires `ureq/platform-verifier`; without it ureq panics with
/// "Rustls + PlatformVerifier requires feature: platform-verifier" rather than
/// returning an error. The default HTTPS path must not panic.
#[test]
fn https_without_cacert_returns_an_error_rather_than_panicking() {
    let config = HttpConfig {
        addr: "127.0.0.1".to_owned(),
        port: dead_tls_listener(),
        tls: true,
        cacert: None,
        timeout_ms: 2000,
    };

    let connector = yubihsm::Connector::http(&config);
    let result = connector.send_message(uuid::Uuid::nil(), vec![0x06, 0x00, 0x00].into());

    assert!(
        result.is_err(),
        "handshake against a dead listener should fail, not succeed"
    );
}
