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

An experimental pure Rust reimplementation of [libyubihsm] providing an
interface to [YubiHSM2] devices from [Yubico].

[Documentation][docs-link] (**NOTE:** temporarily broken, should be fixed soon!)

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

Initial support for creating encrypted channels to a YubiHSM2 via
**yubihsm-connector** is complete, along with authenticating to the
YubiHSM2 via a password/authentication key.

The following commands are presently supported:

* [Authenticate Session](https://developers.yubico.com/YubiHSM2/Commands/Authenticate_Session.html)
* [Create Session](https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html)
* [Delete Object](https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html)
* [Echo](https://developers.yubico.com/YubiHSM2/Commands/Echo.html)
* [Generate Asymmetric Key](https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html)
* [Get Object Info](https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html)
* [Get Pubkey](https://developers.yubico.com/YubiHSM2/Commands/Get_Pubkey.html)
* [List Objects](https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html)
* [Session Message](https://developers.yubico.com/YubiHSM2/Commands/Session_Message.html)
* [Sign Data EdDSA](https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Eddsa.html) i.e. Ed25519 signatures

# Build Notes

This crate depends on the `aesni` crate, which uses the new "stdsimd" API
(which recently landed in nightly) to invoke hardware AES instructions via
`core::arch`.

To access these features, you will need both a relatively recent
Rust nightly and to pass the following as RUSTFLAGS:

```
RUSTFLAGS=-C target-feature=+aes`
```

You can configure your `~/.cargo/config` to always pass these flags:

```toml
[build]
rustflags = ["-C", "target-feature=+aes"]
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
2. Add a struct which matches the structure of the command to [commands.rs]
3. Add an additional struct which matches the response structure to [responses.rs]
4. Add a wrapper function to [session.rs] which constructs the command message,
   performs the command, and returns the corresponding response struct.
5. (Optional) Implement the command in [mockhsm.rs] and write an
   [integration test]

Here is an [example PR that implements Ed25519 signing] you can study to see
what the above steps look like in practice.

[YubiHSM2 commands]: https://developers.yubico.com/YubiHSM2/Commands/
[Serde-based message parser]: https://github.com/tendermint/yubihsm-rs/tree/master/src/serializers
[commands.rs]: https://github.com/tendermint/yubihsm-rs/blob/master/src/commands.rs
[responses.rs]: https://github.com/tendermint/yubihsm-rs/blob/master/src/responses.rs
[session.rs]: https://github.com/tendermint/yubihsm-rs/blob/master/src/session.rs
[mockhsm.rs]: https://github.com/tendermint/yubihsm-rs/blob/master/src/mockhsm.rs
[integration test]:  https://github.com/tendermint/yubihsm-rs/blob/master/tests/integration.rs
[example PR that implements Ed25519 signing]: https://github.com/tendermint/yubihsm-rs/pull/11/files

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
