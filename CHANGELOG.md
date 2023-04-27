# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.42.0 (2023-04-27)
### Added
- Impl `signature::hazmat::PrehashSigner` for ECDSA signer ([#362])
- Impl `signature::Keypair` trait for ECDSA signer ([#364])
- Implement recoverable signatures for ECDSA/secp256k1 ([#408])

### Changed
- Bump tiny_http to 0.12 ([#372])
- Bump asymmetric crypto dependencies; MSRV 1.65 ([#406])
  - `ecdsa` v0.16
  - `ed25519` v2
  - `ed25519-dalek` v2.0.0-pre.0
  - `k256` v0.13
  - `p256` v0.13
  - `p384` v0.13
  - `pbkdf2` v0.12
  - `rsa` v0.9 ([#437])
  - `signature` v2
- Bump `bitflags` dependency to v2.0 ([#409])

[#362]: https://github.com/iqlusioninc/yubihsm.rs/pull/362
[#364]: https://github.com/iqlusioninc/yubihsm.rs/pull/364
[#372]: https://github.com/iqlusioninc/yubihsm.rs/pull/372
[#406]: https://github.com/iqlusioninc/yubihsm.rs/pull/406
[#408]: https://github.com/iqlusioninc/yubihsm.rs/pull/408
[#409]: https://github.com/iqlusioninc/yubihsm.rs/pull/409
[#437]: https://github.com/iqlusioninc/yubihsm.rs/pull/437

## 0.41.0 (2022-08-02)
### Changed
- Bump `uuid` to v1.0 ([#321])
- Bump asymmetric crypto dependencies; MSRV 1.57 ([#325])
- Bump symmetric crate dependencies ([#337])
  - `aes` v0.8
  - `ccm` v0.5
  - `cmac` v0.7
  - Replace `block-modes` with `cbc` v0.1

[#321]: https://github.com/iqlusioninc/yubihsm.rs/pull/321
[#325]: https://github.com/iqlusioninc/yubihsm.rs/pull/325
[#337]: https://github.com/iqlusioninc/yubihsm.rs/pull/337

## 0.40.0 (2021-12-15)
### Added
- Support for `decrypt_oaep` command ([#277])

### Changed
- Bump `rusb` to 0.9.0 ([#249])
- Bump `pbkdf2` to 0.9.0 ([#244])
- Upgrade to Rust 2021 edition; MSRV 1.56 ([#258])
- Replace `chrono` with the `time` crate ([#271])
- Replace `lazy_static` with `once_cell` ([#272])
- Default USB timeout is now 30 seconds to accomodate RSA commands ([#274])
- Bump `ed25519` dependency to v1.3 ([#274])
- Bump `ecdsa` to v0.13 ([#289])
- Bump `k256` to v0.10 ([#289])
- Bump `p256` to v0.10 ([#289])
- Bump `p384` to v0.9 ([#289])

### Fixed
- Potential session mutex re-entrancy bug ([#273])

### Removed
- `criterion` benchmarks ([#234])
- `harp` dependency ([#259])
- `anomaly` dependency ([#264])
- Session auto-close in `Drop` handler ([#265])

[#234]: https://github.com/iqlusioninc/yubihsm.rs/pull/234
[#244]: https://github.com/iqlusioninc/yubihsm.rs/pull/244
[#249]: https://github.com/iqlusioninc/yubihsm.rs/pull/249
[#258]: https://github.com/iqlusioninc/yubihsm.rs/pull/258
[#259]: https://github.com/iqlusioninc/yubihsm.rs/pull/259
[#264]: https://github.com/iqlusioninc/yubihsm.rs/pull/264
[#265]: https://github.com/iqlusioninc/yubihsm.rs/pull/265
[#271]: https://github.com/iqlusioninc/yubihsm.rs/pull/271
[#272]: https://github.com/iqlusioninc/yubihsm.rs/pull/272
[#273]: https://github.com/iqlusioninc/yubihsm.rs/pull/273
[#274]: https://github.com/iqlusioninc/yubihsm.rs/pull/274
[#277]: https://github.com/iqlusioninc/yubihsm.rs/pull/277
[#289]: https://github.com/iqlusioninc/yubihsm.rs/pull/289

## 0.39.0 (2021-06-09)
### Changed
- Bump `rusb` to 0.8.0 ([#170])
- Bump `aes` to v0.7 ([#183])
- Bump `aead` to v0.4 ([#183])
- Bump `ccm` to v0.4 ([#183])
- Bump `cmac` to v0.6 ([#183])
- Bump `hmac` to v0.11 ([#183])
- Bump `pbkdf2` to v0.8 ([#183])
- Bump `ecdsa` crate to v0.12 ([#207])
- Bump `k256` crate to v0.9 ([#207])
- Bump `p256` crate to v0.9 ([#207])
- Bump `p384` crate to v0.8 ([#207])
- MSRV 1.51+ ([#207])

[#170]: https://github.com/iqlusioninc/yubihsm.rs/pull/170
[#183]: https://github.com/iqlusioninc/yubihsm.rs/pull/183
[#207]: https://github.com/iqlusioninc/yubihsm.rs/pull/207

## 0.38.0 (2021-02-02)
### Changed
- Bump `tiny_http` dependency to 0.8.0; fixes `RUSTSEC-2020-0031` ([#158])
- Bump `pbkdf2` dependency to v0.7 ([#162])

[#158]: https://github.com/iqlusioninc/yubihsm.rs/pull/158
[#162]: https://github.com/iqlusioninc/yubihsm.rs/pull/162

## 0.37.0 (2020-12-22)
### Changed
- Bump `ecdsa` crate to v0.10 ([#141])
- Bump `k256` crate to v0.7 ([#141])
- Bump `p256` crate to v0.7 ([#141])
- Bump `p384` crate to v0.7 ([#141])

[#141]: https://github.com/iqlusioninc/yubihsm.rs/pull/141

## 0.36.0 (2020-12-07)
### Changed
- Bump `ecdsa` crate dependency to v0.9; MSRV 1.46+ ([#130])

[#130]: https://github.com/iqlusioninc/yubihsm.rs/pull/130

## 0.35.0 (2020-10-19)
### Added
- Support for k256::ecdsa::recoverable::Signature ([#95])

### Changed
- Bump RustCrypto dependencies ([#82], [#116])

### Removed
- Signatory-based types ([#91])

[#116]: https://github.com/iqlusioninc/yubihsm.rs/pull/116
[#95]: https://github.com/iqlusioninc/yubihsm.rs/pull/95
[#91]: https://github.com/iqlusioninc/yubihsm.rs/pull/91
[#82]: https://github.com/iqlusioninc/yubihsm.rs/pull/82

## 0.34.0 (2020-06-18)
### Changed
- Update `signatory` to v0.20 ([#56])
- Update `aes`, `block-modes`, `cmac`, `hmac`, `pbkdf2`, `sha2` dependencies ([#55])

[#56]: https://github.com/iqlusioninc/yubihsm.rs/pull/56
[#55]: https://github.com/iqlusioninc/yubihsm.rs/pull/55

## 0.33.0 (2020-04-20)

- Upgrade to `signature` crate v1.0; `ecdsa` crate v0.5 ([#24])
- Bump `tiny_http` from 0.6 to 0.7 ([#23])

[#24]: https://github.com/iqlusioninc/yubihsm.rs/pull/24
[#23]: https://github.com/iqlusioninc/yubihsm.rs/pull/23

## 0.32.1 (2020-03-24)

- connector/usb: Use `rusb::Context` instead of `GlobalContext` ([#15])

[#15]: https://github.com/iqlusioninc/yubihsm.rs/pull/15

## 0.32.0 (2020-02-29)

- Rename `yolocrypto` feature to `untested` ([#5])
- MSRV 1.40+ ([#3])
- Update `anomaly` requirement from 0.1.2 to 0.2.0 ([#2])

[#2]: https://github.com/iqlusioninc/yubihsm.rs/pull/2
[#3]: https://github.com/iqlusioninc/yubihsm.rs/pull/3
[#5]: https://github.com/iqlusioninc/yubihsm.rs/pull/5

## 0.31.0 (2020-01-19)

- Upgrade `signatory` to v0.18 
- Use Anomaly for error handling 

## 0.30.0 (2019-12-11)

- Upgrade to `signatory` v0.17 

## 0.29.0 (2019-10-29)

- Upgrade to `signatory` v0.16; `zeroize` 1.0 

## 0.28.0 (2019-10-12)

- Replace `gaunt` with `harp` 
- Remove failure 
- connector: Switch from `libusb` to `rusb` 
- Upgrade to `signatory` v0.15 

## 0.27.0 (2019-08-11)

- Refactor `Algorithm` names to be camel case and subdivide RSA 
- ecdh: Initial support for Derive ECDH command 
- ssh: Initial support for the Sign SSH Certificate command 
- template: Add support for get/put commands 
- Rename `rsa-preview` cargo feature to `yolocrypto` 
- Upgrade to `signatory` v0.13 

## 0.26.4 (2019-06-24)

- Improve missing auth key errors 

## 0.26.3 (2019-06-24)

- `http-server`: Fix startup message 

## 0.26.2 (2019-06-24)

- `http-server`: Print listener info on startup 

## 0.26.1 (2019-06-22)

- Fix `http-server` import bug 

## 0.26.0 (2019-06-21)

- `http-server` feature: mimic yubihsm-connector functionality 

## 0.25.0 (2019-06-07)

- Upgrade to `signatory` v0.12 

## 0.24.0 (2019-06-04)

- Eliminate module name prefixes from error types 
- Upgrade to `zeroize` 0.9 
- Improve `yubihsm::Client`'s `reset_device_and_reconnect` API 
- Retry commands after session messages limits are exceeded 

## 0.23.0 (2019-05-20)

- Remove `byteorder` crate 
- 2018 edition idiom cleanups 
- setup: Support for (optionally) skipping initial device reset 
- Upgrade to `block-modes` v0.3 
- Upgrade to `zeroize` 0.8  
- Switch from `rand_os` to `getrandom` 

## 0.22.0 (2019-03-24)

- Integrate Signatory types 
- Make `yubihsm::client::Client` thread-safe 
- Move asymmetric algorithm modules into the toplevel 
- Fix parsing of wrap nonces 
- Make signatory a mandatory dependency 
- `rsa-preview` cargo feature 
- Factor device info/storage/wrap commands into public types 

## 0.21.0 (2019-02-26)

- Factor algorithms into their own Rust modules 
- Unify connectors as `struct Connector` 
- Integrate signatory-yubihsm 
- Refactor and rename `wrap::Message` and `wrap::Nonce` 
- Add `setup` module for initial YubiHSM2 provisioning 
- Eliminate redundant prefixes in type names 

## 0.20.0 (2019-02-12)

- Match Yubico's API changes from their latest SDK release 
- Upgrade `ring` crate to `v0.14`; switch to `rand_os` crate `v0.1` 
- Update to Rust 2018 edition 
- Upgrade `subtle` crate to `v2` 

## 0.19.2 (2018-11-27)

- `HttpConnector`: upgrade to `gaunt` v0.1.0
- Terminate sessions on encryption failures

## 0.19.1 (2018-10-21)

- `HttpConnector`: use `gaunt` for an HTTP client
- session: Catch panics which occur in drop handler

## 0.19.0 (2018-10-16)

- USB error message improvements
- Implement filter support for the List Objects command
- Upgrade to zeroize 0.4
- Derive Clone and Debug on all connectors
- Upgrade digest 0.8 (and all transitive dependencies)

## 0.18.1 (2018-10-03)

- `Cargo.toml`: Don't build the nightly feature on docs.rs

## 0.18.0 (2018-10-03)

- Use the zeroize crate
- `Session`: add `messages_sent()`
- API overhaul: eliminate adapter-related generics with trait objects

## 0.17.3 (2018-09-21)

- `UsbDevices`: rename `serials()` to `serial_numbers()`
- `serial_number.rs`: Manually impl `Serialize`, `Deserialize`, `Debug`, and `Display`

## 0.17.2 (2018-09-20)

- Export UsbConfig from crate root (when available)

## 0.17.1 (2018-09-19)

- UsbDevices: add `len()`, `is_empty()`, `as_slice()`, and `into_iter()`
- adapter/usb: Don't verbosely log every discovered YubiHSM2

## 0.17.0 (2018-09-19)

- Cargo.toml: update dependencies (aes, subtle, uuid)
- Make all names singular
- Expose more information about USB devices
- Add `serial_number()` method to `Session` and `Adapter` trait

## 0.16.1 (2018-09-17)

- Expand HSM error code support

## 0.16.0 (2018-09-12)

- Make `http` a cargo feature
- Rename `MockHSM` => `MockHsm`; export from crate root
- Factor HSM error handling into `HsmErrorKind`
- Refactor Algorithm and related types
- Decode detailed HSM errors from responses
- Implement Put Option commands
- Implement Get Option commands
- USB support. Rename `Connector` => `Adapter`

## 0.15.1 (2018-08-24)

- `http_connector.rs`: Derive Clone on HttpConfig

## 0.15.0 (2018-08-19)

- Add `yubihsm::sign_ecdsa_raw_digest()`

## 0.14.2 (2018-07-30)

- AsymmetricAlgorithm: fix typo in `EC_K256` conversion

## 0.14.1 (2018-07-29)

- Fix builds with the "doc" feature

## 0.14.0 (2018-07-29)

- Initial RSASSA-PKCS#1v1.5 and PSS support
- Test SecureChannel MAC verification failure (fixes #14)
- Initial reconnect support
- Support debug output using the `log` crate
- Handle session timeouts
- Handle NUL (i.e. `\0`) byte in label before UTF-8 conversion
- `derive(Clone)` for `WrapMessage`
- ObjectType json deserialization helper

## 0.13.0 (2018-07-14)

- Implement `set_log_index` command
- Implement `generate_hmac_key`, `hmac`, and `verify_hmac` commands
- Remove dependency on rand 0.4.x
- Simplify and remove unnecessary response types

## 0.12.0 (2018-07-14)

This release includes significant refactoring and API changes, in addition
to adding support for several commands.

- Support multiple connections to MockHSM
- `AuthKey` type (and MockHSM support for `put_auth_key`)
- Implement `get_opaque` command
- Implement `reset` command
- Implement `get_pseudo_random` command
- Factor `ObjectHandle` and `ObjectInfo` into `object` module
- Implement `storage_status` command
- Have `generate_*` and `put_*` commands return an `ObjectId`
- Refactor `object` module into modules for each type
- Implement wrapping: export, import, wrap, unwrap, generate wrap key
- Implement `close_session` command
- Implement `attest_asymmetric` command
- Implement `put_*` commands
- Factor all commands into their own individual modules
- Implement `sign_ecdsa_sha2` command
- Implement `get_logs` command
- Implement `device_info` command

## 0.11.2 (2018-07-04)

- Use subtle crate for constant time equality

## 0.11.1 (2018-07-04)

- Upgrade to rand 0.5

## 0.11.0 (2018-07-04)

- Factor command methods from `Session` into `commands.rs`
- Implement SignDataECDSA command

## 0.10.1 (2018-07-02)

- Add a `nightly` feature

## 0.10.0 (2018-06-28)

- Use the `aes` crate
- Support Rust stable (1.27+)

## 0.9.0 (2018-05-19)

- Error handling overhaul
- Export HttpConfig from crate toplevel

## 0.8.0 (2018-04-12)

- Integrated HttpConnector

## 0.7.3 (2018-04-05)

- Mark Connector as Sync-safe

## 0.7.2 (2018-03-31)

- Upgrade ed25519-dalek, sha2, and pbkdf2 crates

## 0.7.1 (2018-03-27)

- Improve DefaultConnector handling

## 0.7.0 (2018-03-27)

- Rename AbstractSession -> Session (by using default generic arg)

## 0.6.0 (2018-03-20)

- Make MockHSM (and therefore all Connectors) Send-safe
- Expose connector status as an (Abstract)Session method

## 0.5.0 (2018-03-20)

- Convert `MockHSM` into a `yubihsm::Connector`

## 0.4.0 (2018-03-20)

- Refactor `Session` and `Connector`

## 0.3.0 (2018-03-20)

- Have `Session`s own `Connector`s

## 0.2.0 (2018-03-12)

- Ensure command data is smaller than the YubiHSM2's buffer
- Implement Blink command

## 0.1.1 (2018-03-07)

- Fixes for docs.rs build

## 0.1.0 (2018-03-06)

- Initial release
