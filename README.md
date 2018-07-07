# yubihsm.rs

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT/Apache2 licensed][license-image]

[crate-image]: https://img.shields.io/crates/v/yubihsm.svg
[crate-link]: https://crates.io/crates/yubihsm
[docs-image]: https://docs.rs/yubihsm/badge.svg
[docs-link]: https://docs.rs/yubihsm/
[build-image]: https://circleci.com/gh/tendermint/yubihsm-rs.svg?style=shield
[build-link]: https://circleci.com/gh/tendermint/yubihsm-rs
[license-image]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg

Pure Rust reimplementation of [libyubihsm] providing an end-to-end encrypted
connection and command interface to [YubiHSM2] devices from [Yubico].

[Documentation][docs-link]

[libyubihsm]: https://developers.yubico.com/YubiHSM2/Component_Reference/libyubihsm/
[YubiHSM2]: https://www.yubico.com/products/yubihsm/
[Yubico]: https://www.yubico.com/

## About

This is a pure-Rust client library for [YubiHSM2] devices. It implements a
subset of the functionality found in the closed-source Yubico SDK and
communicates with the [yubihsm-connector] service: an HTTP(S) server which
sends the commands to the YubiHSM2 hardware device over USB.

Note that this is **NOT** an official Yubico project and is in no way supported
or endorsed by Yubico (although whoever runs their Twitter account
[thinks it's awesome]).

[yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/
[thinks it's awesome]: https://twitter.com/Yubico/status/971186516796915712

## Prerequisites

This crate builds on Rust 1.27+ and by default uses SIMD features
which require the following RUSTFLAGS:

```
RUSTFLAGS=-Ctarget-feature=+aes`
```

You can configure your `~/.cargo/config` to always pass these flags:

```toml
[build]
rustflags = ["-Ctarget-feature=+aes"]
```

## Supported Commands

* [Blink]: Blink the YubiHSM2's LEDs (to identify it)
* [Delete Object]: Delete an object of the given ID and type
* [Echo]: Have the card echo an input message
* [Generate Asymmetric Key]: Generate a new asymmetric key within the `YubiHSM2`
* [Get Device Info]: Get information about the `YubiHSM2` like software versions and algorithms
* [Get Logs]: Obtain the audit log for the `YubiHSM2`
* [Get Object Info]: Get information about an object
* [Get Pubkey]: Get the public key for an asymmetric private key stored on the device
* [List Objects]: List objects visible from the current session
* [Sign Data ECDSA]: Compute an ECDSA signature using an HSM-backed private key
* [Sign Data EdDSA]: Compute an Ed25519 signature using an HSM-backed private key

[Blink]: https://docs.rs/yubihsm/latest/yubihsm/commands/blink/fn.blink.html
[Delete Object]: https://docs.rs/yubihsm/latest/yubihsm/commands/delete_object/fn.delete_object.html
[Echo]: https://docs.rs/yubihsm/latest/yubihsm/commands/echo/fn.echo.html
[Generate Asymmetric Key]: https://docs.rs/yubihsm/latest/yubihsm/commands/generate_asymmetric_key/fn.generate_asymmetric_key.html
[Get Device Info]: https://docs.rs/yubihsm/latest/yubihsm/commands/get_device_info/fn.get_device_info.html
[Get Logs]: https://docs.rs/yubihsm/latest/yubihsm/commands/get_logs/fn.get_logs.html
[Get Object Info]: https://docs.rs/yubihsm/latest/yubihsm/commands/get_object_info/fn.get_object_info.html
[Get Pubkey]: https://docs.rs/yubihsm/latest/yubihsm/commands/get_pubkey/fn.get_pubkey.html
[List Objects]: https://docs.rs/yubihsm/latest/yubihsm/commands/list_objects/fn.list_objects.html
[Sign Data ECDSA]: https://docs.rs/yubihsm/latest/yubihsm/commands/sign_ecdsa/fn.sign_ecdsa_sha2.html
[Sign Data EdDSA]: https://docs.rs/yubihsm/latest/yubihsm/commands/sign_eddsa/fn.sign_ed25519.html

Adding support for additional commands is easy! See the `Contributing` section.

## Getting Started

The following documentation describes the most important parts of this crate's API:

* [Session]: end-to-end encrypted connection with the YubiHSM. You'll need an active one to do anything.
* [commands]: commands supported by the YubiHSM2 (i.e. main functionality)

[Session]: https://docs.rs/yubihsm/latest/yubihsm/session/struct.Session.html
[commands]: https://docs.rs/yubihsm/latest/yubihsm/commands/index.html

Here is an example of how to create a `Session` by connecting to a [yubihsm-connector]
process, and then performing an Ed25519 signature:

```rust
extern crate yubihsm;
use yubihsm::Session;

// Default host, port, auth key ID, and password for yubihsm-connector
let mut session = Session::create_from_password(
     "http://127.0.0.1:12345",
     1,
     "password",
     true
).unwrap();

// Note: You'll need to create this key first. Run the following from yubihsm-shell:
// `generate asymmetric 0 100 ed25519_test_key 1 asymmetric_sign_eddsa ed25519`
let signature = yubihsm::sign_ed25519(&session, 100, "Hello, world!").unwrap();
println!("Ed25519 signature: {:?}", signature);
```

## Contributing

If there are additional [YubiHSM2 commands] you would like to use but aren't
presently supported, adding them is very easy, and PRs are welcome!

The YubiHSM2 uses a simple, bincode-like message format, which largely consists
of fixed-width integers, bytestrings, and bitfields. This crate implements a
[Serde-based message parser] which can automatically parse command/response
messages used by the HSM derived from a corresponding Rust struct describing
their structure.

Here's a list of steps necessary to implement a new command type:

1. Find the command you wish to implement on the [YubiHSM2 commands] page, and
   study the structure of the command (i.e. request) and response
2. Create a new module under the [commands] module which matches the name
   of the command and implements the `Command` and `Response` traits.
3. (Optional) Implement the command in [mockhsm/commands.rs] and write an
   [integration test]

[YubiHSM2 commands]: https://developers.yubico.com/YubiHSM2/Commands/
[Serde-based message parser]: https://github.com/tendermint/yubihsm-rs/tree/master/src/serializers
[commands]: https://github.com/tendermint/yubihsm-rs/tree/master/src/commands
[mockhsm/mod.rs]: https://github.com/tendermint/yubihsm-rs/blob/master/src/mockhsm/mod.rs
[integration test]:  https://github.com/tendermint/yubihsm-rs/blob/master/tests/integration.rs

## Testing

This crate allows you to run the integration test suite in two different ways:
live testing against a real YubiHSM2 device, and simulated testing using
a MockHSM service which reimplements some YubiHSM2 functionality in software.

### `cargo test --features=integration`: test live against a YubiHSM2 device

This mode assumes you have a YubiHSM2 hardware device, have downloaded the
[YubiHSM2 SDK] for your platform, and are running a **yubihsm-connector**
process listening on localhost on the default port of 12345.

The YubiHSM2 device should be in the default factory state. To reset it to this
state, either use the [yubihsm-shell reset] command or press on the YubiHSM2 for
10 seconds immediately after inserting it.

You can confirm the tests are running live against the YubiHSM2 by the LED
blinking rapidly for 1 second.

**NOTE THAT THESE TESTS ARE DESTRUCTIVE: DO NOT RUN THEM AGAINST A YUBIHSM2
WHICH CONTAINS KEYS YOU CARE ABOUT**

[YubiHSM2 SDK]: https://developers.yubico.com/YubiHSM2/Releases/
[yubihsm-shell reset]: https://developers.yubico.com/YubiHSM2/Commands/Reset.html

### `cargo test --features=mockhsm`: simulated tests against a mock HSM

This mode is useful for when you don't have access to physical YubiHSM2
hardware, such as CI environments.

## License

**yubihsm.rs** is distributed under the terms of both the MIT license and
the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
