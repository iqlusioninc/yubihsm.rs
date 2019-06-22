## [0.26.0] (2019-06-07)

- `http-server` feature: mimic yubihsm-connector functionality ([#213])

## [0.25.0] (2019-06-07)

- Upgrade to `signatory` v0.12 ([#211])

## [0.24.0] (2019-06-04)

- Eliminate module name prefixes from error types ([#209])
- Upgrade to zeroize 0.9 ([#208])
- Improve `yubihsm::Client`'s `reset_device_and_reconnect` API ([#204])
- Retry commands after session messages limits are exceeded ([#203])

## [0.23.0] (2019-05-20)

- Remove `byteorder` crate ([#201])
- 2018 edition idiom cleanups ([#200])
- setup: Support for (optionally) skipping initial device reset ([#199])
- Upgrade to `block-modes` v0.3 ([#198])
- Upgrade to `zeroize` 0.8 ([#197]) 
- Switch from `rand_os` to `getrandom` ([#195])

## [0.22.0] (2019-03-24)

- Integrate Signatory types ([#192])
- Make `yubihsm::client::Client` thread-safe ([#191])
- Move asymmetric algorithm modules into the toplevel ([#190])
- Fix parsing of wrap nonces ([#188])
- Make signatory a mandatory dependency ([#186])
- `rsa-preview` cargo feature ([#185])
- Factor device info/storage/wrap commands into public types ([#184])

## [0.21.0] (2019-02-26)

- Factor algorithms into their own Rust modules ([#180])
- Unify connectors as `struct Connector` ([#179])
- Integrate signatory-yubihsm ([#176])
- Refactor and rename `wrap::Message` and `wrap::Nonce` ([#175])
- Add `setup` module for initial YubiHSM2 provisioning ([#174])
- Eliminate redundant prefixes in type names ([#173])

## [0.20.0] (2019-02-12)

- Match Yubico's API changes from their latest SDK release ([#167])
- Upgrade `ring` crate to `v0.14`; switch to `rand_os` crate `v0.1` ([#166])
- Update to Rust 2018 edition ([#164])
- Upgrade `subtle` crate to `v2` ([#163])

## [0.19.2] (2018-11-27)

- `HttpConnector`: upgrade to `gaunt` v0.1.0 (#157)
- Terminate sessions on encryption failures (#154)

## [0.19.1] (2018-10-21)

- `HttpConnector`: use `gaunt` for an HTTP client (#152)
- session: Catch panics which occur in drop handler. (#151)

## [0.19.0] (2018-10-16)

- USB error message improvements (#149)
- Implement filter support for the List Objects command (#148)
- Upgrade to zeroize 0.4 (#147)
- Derive Clone and Debug on all connectors (#145)
- Upgrade digest 0.8 (and all transitive dependencies) (#144)

## [0.18.1] (2018-10-03)

- `Cargo.toml`: Don't build the nightly feature on docs.rs (#140)

## [0.18.0] (2018-10-03)

- Use the zeroize crate (#138)
- `Session`: add `messages_sent()` (#136)
- API overhaul: eliminate adapter-related generics with trait objects (#131)

## [0.17.3] (2018-09-21)

- `UsbDevices`: rename `serials()` to `serial_numbers()` (#129)
- `serial_number.rs`: Manually impl `Serialize`, `Deserialize`, `Debug`, and
  `Display` (#128)

## [0.17.2] (2018-09-20)

- Export UsbConfig from crate root (when available) (#126)

## [0.17.1] (2018-09-19)

- UsbDevices: add `len()`, `is_empty()`, `as_slice()`, and `into_iter()` (#124)
- adapter/usb: Don't verbosely log every discovered YubiHSM2 (#123)

## [0.17.0] (2018-09-19)

- Cargo.toml: update dependencies (aes, subtle, uuid) (#121)
- Make all names singular (#120)
- Expose more information about USB devices (#119)
- Add `serial_number()` method to `Session` and `Adapter` trait (#118)

## [0.16.1] (2018-09-17)

- Expand HSM error code support. (#116)

## [0.16.0] (2018-09-12)

- Make 'http' a cargo feature (#112)
- Rename `MockHSM` => `MockHsm`; export from crate root (#111)
- Factor HSM error handling into `HsmErrorKind` (#110)
- Refactor Algorithm and related types (#109)
- Decode detailed HSM errors from responses (#107)
- Implement Put Option commands (#106)
- Implement Get Option commands (#101)
- USB support. Rename `Connector` => `Adapter` (#97)

## [0.15.1] (2018-08-24)

- `http_connector.rs`: Derive Clone on HttpConfig (#93)

## [0.15.0] (2018-08-19)

- Add `yubihsm::sign_ecdsa_raw_digest()` (#91)

## [0.14.2] (2018-07-30)

- AsymmetricAlgorithm: fix typo in `EC_K256` conversion (#90)

## [0.14.1] (2018-07-29)

- Fix builds with the "doc" feature (#89)

## [0.14.0] (2018-07-29)

- Initial RSASSA-PKCS#1v1.5 and PSS support (#88)
- Test SecureChannel MAC verification failure (fixes #14) (#87)
- Initial reconnect support (#86)
- Support debug output using the `log` crate (#84)
- Handle session timeouts (#83)
- Handle NUL (i.e. `\0`) byte in label before UTF-8 conversion (fixes #81) (#82)
- `derive(Clone)` for `WrapMessage` (#80)
- ObjectType json deserialization helper (#79)

## [0.13.0] (2018-07-14)

- Implement `set_log_index` command (#77)
- Implement `generate_hmac_key`, `hmac`, and `verify_hmac` commands (#76)
- Remove dependency on rand 0.4.x (#75)
- Simplify and remove unnecessary response types (#74)

## [0.12.0] (2018-07-14)

This release includes significant refactoring and API changes, in addition
to adding support for several commands.

- Support multiple connections to MockHSM (#73)
- `AuthKey` type (and MockHSM support for `put_auth_key`) (#69)
- Implement `get_opaque` command (#67)
- Implement `reset` command (#66)
- Implement `get_pseudo_random` command (#65)
- Factor `ObjectHandle` and `ObjectInfo` into `object` module (#64)
- Implement `storage_status` command (#63)
- Have `generate_*` and `put_*` commands return an `ObjectId` (#62)
- Refactor `object` module into modules for each type (#61)
- Implement wrapping: export, import, wrap, unwrap, generate wrap key (#60)
- Implement `close_session` command (#56)
- Implement `attest_asymmetric` command (#55)
- Implement `put_*` commands (#53)
- Factor all commands into their own individual modules (#51)
- Implement `sign_ecdsa_sha2` command (#50)
- Implement `get_logs` command (#49)
- Implement `device_info` command (#48)

## [0.11.2] (2018-07-04)

- Use subtle crate for constant time equality (#47)

## [0.11.1] (2018-07-04)

- Upgrade to rand 0.5 (#46)

## [0.11.0] (2018-07-04)

- Factor command methods from `Session` into `commands.rs` (#45)
- Implement SignDataECDSA command (#44)

## [0.10.1] (2018-07-02)

- Add a `nightly` feature (#43)

## [0.10.0] (2018-06-28)

- Use the `aes` crate (#42)
- Support Rust stable (1.27+) (#41)

## [0.9.0] (2018-05-19)

- Error handling overhaul (#39)
- Export HttpConfig from crate toplevel (#38)

## [0.8.0] (2018-04-12)

- Integrated HttpConnector (#36)

## [0.7.3] (2018-04-05)

- Mark Connector as Sync-safe (#34)

## [0.7.2] (2018-03-31)

- Upgrade ed25519-dalek, sha2, and pbkdf2 crates (#33)

## [0.7.1] (2018-03-27)

- Improve DefaultConnector handling (#32)

## [0.7.0] (2018-03-27)

- Rename AbstractSession -> Session (by using default generic arg) (#31)

## [0.6.0] (2018-03-20)

- Make MockHSM (and therefore all Connectors) Send-safe (#30)
- Expose connector status as an (Abstract)Session method (#29)

## [0.5.0] (2018-03-20)

- Convert `MockHSM` into a `yubihsm::Connector` (#28)

## [0.4.0] (2018-03-20)

- Refactor `Session` and `Connector` (#25)

## [0.3.0] (2018-03-20)

- Have `Session`s own `Connector`s (#24)

## [0.2.0] (2018-03-12)

- Ensure command data is smaller than the YubiHSM2's buffer (#22)
- Implement Blink command (#20)

## [0.1.1] (2018-03-07)

- Fixes for docs.rs build

## 0.1.0 (2018-03-06)

- Initial release

[0.26.0]: https://github.com/tendermint/yubihsm-rs/pull/214
[#213]: https://github.com/tendermint/yubihsm-rs/pull/213
[0.25.0]: https://github.com/tendermint/yubihsm-rs/pull/212
[#211]: https://github.com/tendermint/yubihsm-rs/pull/211
[0.24.0]: https://github.com/tendermint/yubihsm-rs/pull/210
[#209]: https://github.com/tendermint/yubihsm-rs/pull/209
[#208]: https://github.com/tendermint/yubihsm-rs/pull/208
[#204]: https://github.com/tendermint/yubihsm-rs/pull/204
[#203]: https://github.com/tendermint/yubihsm-rs/pull/203
[0.23.0]: https://github.com/tendermint/yubihsm-rs/pull/202
[#201]: https://github.com/tendermint/yubihsm-rs/pull/201
[#200]: https://github.com/tendermint/yubihsm-rs/pull/200
[#199]: https://github.com/tendermint/yubihsm-rs/pull/199
[#198]: https://github.com/tendermint/yubihsm-rs/pull/198
[#197]: https://github.com/tendermint/yubihsm-rs/pull/197
[#195]: https://github.com/tendermint/yubihsm-rs/pull/195
[0.22.0]: https://github.com/tendermint/yubihsm-rs/pull/194
[#192]: https://github.com/tendermint/yubihsm-rs/pull/192
[#191]: https://github.com/tendermint/yubihsm-rs/pull/191
[#190]: https://github.com/tendermint/yubihsm-rs/pull/190
[#188]: https://github.com/tendermint/yubihsm-rs/pull/188
[#186]: https://github.com/tendermint/yubihsm-rs/pull/186
[#185]: https://github.com/tendermint/yubihsm-rs/pull/185
[#184]: https://github.com/tendermint/yubihsm-rs/pull/184
[0.21.0]: https://github.com/tendermint/yubihsm-rs/pull/183
[#180]: https://github.com/tendermint/yubihsm-rs/pull/180
[#179]: https://github.com/tendermint/yubihsm-rs/pull/179
[#176]: https://github.com/tendermint/yubihsm-rs/pull/176
[#175]: https://github.com/tendermint/yubihsm-rs/pull/175
[#174]: https://github.com/tendermint/yubihsm-rs/pull/174
[#173]: https://github.com/tendermint/yubihsm-rs/pull/173
[0.20.0]: https://github.com/tendermint/yubihsm-rs/pull/172
[#167]: https://github.com/tendermint/yubihsm-rs/pull/167
[#166]: https://github.com/tendermint/yubihsm-rs/pull/166
[#164]: https://github.com/tendermint/yubihsm-rs/pull/164
[#163]: https://github.com/tendermint/yubihsm-rs/pull/163
[0.19.2]: https://github.com/tendermint/yubihsm-rs/pull/159
[0.19.1]: https://github.com/tendermint/yubihsm-rs/pull/153
[0.19.0]: https://github.com/tendermint/yubihsm-rs/pull/150
[0.18.1]: https://github.com/tendermint/yubihsm-rs/pull/141
[0.18.0]: https://github.com/tendermint/yubihsm-rs/pull/139
[0.17.3]: https://github.com/tendermint/yubihsm-rs/pull/130
[0.17.2]: https://github.com/tendermint/yubihsm-rs/pull/127
[0.17.1]: https://github.com/tendermint/yubihsm-rs/pull/125
[0.17.0]: https://github.com/tendermint/yubihsm-rs/pull/122
[0.16.1]: https://github.com/tendermint/yubihsm-rs/pull/117
[0.16.0]: https://github.com/tendermint/yubihsm-rs/pull/114
[0.15.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.14.2...v0.15.0
[0.14.2]: https://github.com/tendermint/yubihsm-rs/compare/v0.14.1...v0.14.2
[0.14.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.11.2...v0.12.0
[0.11.2]: https://github.com/tendermint/yubihsm-rs/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.7.3...v0.8.0
[0.7.3]: https://github.com/tendermint/yubihsm-rs/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/tendermint/yubihsm-rs/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.1.0...v0.1.1
