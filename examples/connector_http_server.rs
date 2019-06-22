//! `yubihsm-connector` compatible HTTP server example.
//!
//! This exposes an HTTP server which provides an API that is compatible with
//! the `yubihsm-connector` executable which comes with the YubiHSM SDK.
//!
//! It allows utilities like `yubihsm-shell` or other things written with
//! `libyubihsm` to function in tandem with a Rust application
//! communicating directly with the YubiHSM2 over USB.

fn main() {
    println!("opening USB connection to yubihsm");
    let connector = yubihsm::Connector::usb(&Default::default());

    // http://127.0.0.1:12345
    let http_config = yubihsm::connector::HttpConfig::default();

    println!(
        "starting server at http://{}:{}",
        &http_config.addr, http_config.port
    );

    let server = yubihsm::connector::http::Server::new(&http_config, connector).unwrap();

    println!("server started! connect by running:\n");
    println!("    $ yubihsm-shell");
    println!("    yubihsm> connect");
    println!("    yubihsm> session open 1 <password>");

    server.run().unwrap();
}
