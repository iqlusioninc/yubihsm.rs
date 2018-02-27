# yubihsm-client.rs

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT/Apache2 licensed][license-image]

[crate-image]: https://img.shields.io/crates/v/yubihsm-client.svg
[crate-link]: https://crates.io/crates/yubihsm-client
[docs-image]: https://docs.rs/yubihsm-client/badge.svg
[docs-link]: https://docs.rs/yubihsm-client/
[build-image]: https://secure.travis-ci.org/tarcieri/yubihsm-client.svg?branch=master
[build-link]: https://travis-ci.org/tarcieri/yubihsm-client
[license-image]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg

An experimental pure Rust reimplementation of [libyubihsm] providing an
interface to [YubiHSM2] devices from [Yubico].

[libyubihsm]: https://developers.yubico.com/YubiHSM2/Component_Reference/libyubihsm/
[YubiHSM2]: https://www.yubico.com/products/yubihsm/
[Yubico]: https://www.yubico.com/

## About

This is a pure-Rust crate for interfacing with YubiHSM2 devices.

It presently reimplements a small subset of the of the functionality of
**libyubihsm**, a closed-source C library which acts as a libcurl-based HTTP(S)
client and sends commands to the [yubihsm-connector] process, which implements
an HTTP(S) server which sends the commands to the YubiHSM2 hardware device over USB.

**libyubihsm** can be difficult to work with because it is shipped as a
platform-specific dynamic library which needs its own special versions of
libcurl and OpenSSL.

**yubihsm-client** is a pure-Rust reimplementation of a similar HTTP(S) client
library for **yubihsm-connector** based on documentation provided by Yubico.
It implements an encrypted connection to the YubiHSM2 using
[GlobalPlatform Secure Channel Protocol "03"] implemented using AES crates
from the [RustCrypto GitHub Organization].

The [reqwest] crate is used to make HTTP(S) requests to **yubihsm-connector**.

[yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/
[GlobalPlatform Secure Channel Protocol "03"]: https://www.globalplatform.org/specificationscard.asp
[RustCrypto GitHub Organization]: https://github.com/RustCrypto
[reqwest]: https://github.com/seanmonstar/reqwest

## Status

Currently working:

* Creating encrypted sessions with YubiHSM2
* Authenticating to YubiHSM2
* The [Echo Command], which you can use to send "Hello, world!"

Not working:

* Anything actually useful

[Echo Command]: https://developers.yubico.com/YubiHSM2/Commands/Echo.html

## Testing

This crate allows you to run the integration test suite in two different ways:
live testing against a real YubiHSM2 device, and simulated testing using
a MockHSM service which reimplements some YubiHSM2 functionality in software.

### `cargo test`: test live against a YubiHSM2 device

This mode assumes you have a YubiHSM2 hardware device, have downloaded the
[YubiHSM2 SDK] for your platform, and are running a **yubihsm-connector**
process listening on localhost on the default port of 12345.

The YubiHSM2 device should be in the default factory state. To reset it to this
state, either use the [yubihsm-shell reset] command or press on the YubiHSM2 for
10 seconds immediately after inserting it.

[YubiHSM2 SDK]: https://developers.yubico.com/YubiHSM2/Releases/
[yubihsm-shell reset]: https://developers.yubico.com/YubiHSM2/Commands/Reset.html

### `cargo test --features=mockhsm`: simulated tests against a mock HSM

This mode is useful for when you don't have access to physical YubiHSM2
hardware, such as CI environments.

## License

**yubihsm-client** is distributed under the terms of both the MIT license and
the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
