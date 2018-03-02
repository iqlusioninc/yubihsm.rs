# yubihsm-client.rs

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT/Apache2 licensed][license-image]

[crate-image]: https://img.shields.io/crates/v/yubihsm-client.svg
[crate-link]: https://crates.io/crates/yubihsm-client
[docs-image]: https://docs.rs/yubihsm-client/badge.svg
[docs-link]: https://docs.rs/yubihsm-client/
[build-image]: https://circleci.com/gh/tendermint/yubihsm-client.svg?style=shield
[build-link]: https://circleci.com/gh/tendermint/yubihsm-client
[license-image]: https://img.shields.io/badge/license-MIT/Apache2.0-blue.svg

An experimental pure Rust reimplementation of [libyubihsm] providing an
interface to [YubiHSM2] devices from [Yubico].

[libyubihsm]: https://developers.yubico.com/YubiHSM2/Component_Reference/libyubihsm/
[YubiHSM2]: https://www.yubico.com/products/yubihsm/
[Yubico]: https://www.yubico.com/

## About

This is a pure-Rust client which supports interfacing with YubiHSM2 devices
over an encrypted channel.

It presently reimplements a small subset of the of the functionality of
**libyubihsm**, a closed-source C library which acts as a libcurl-based HTTP(S)
client and sends commands to the [yubihsm-connector] process, which implements
an HTTP(S) server which sends the commands to the YubiHSM2 hardware device over
USB.

Note that this is **NOT** an official Yubico project and is in no way supported
or endorsed by Yubico.

[yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/

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

**NOTE THAT THESE TESTS ARE DESTRUCTIVE: DO NOT RUN THEM AGAINST A YUBIHSM2
WHICH CONTAINS KEYS YOU CARE ABOUT**

[YubiHSM2 SDK]: https://developers.yubico.com/YubiHSM2/Releases/
[yubihsm-shell reset]: https://developers.yubico.com/YubiHSM2/Commands/Reset.html

### `cargo test --features=mockhsm`: simulated tests against a mock HSM

This mode is useful for when you don't have access to physical YubiHSM2
hardware, such as CI environments.

## License

**yubihsm-client** is distributed under the terms of both the MIT license and
the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
