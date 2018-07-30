## [0.14.2] (2018-07-30)

[0.14.2]: https://github.com/tendermint/yubihsm-rs/compare/v0.14.1...v0.14.2

* [#90](https://github.com/tendermint/yubihsm-rs/pull/90)
  AsymmetricAlgorithm: fix typo in `EC_K256` conversion.

## [0.14.1] (2018-07-29)

[0.14.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.14.0...v0.14.1

* [#89](https://github.com/tendermint/yubihsm-rs/pull/89)
  Fix builds with the "doc" feature.

## [0.14.0] (2018-07-29)

[0.14.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.13.0...v0.14.0

* [#88](https://github.com/tendermint/yubihsm-rs/pull/88)
  Initial RSASSA-PKCS#1v1.5 and PSS support.

* [#87](https://github.com/tendermint/yubihsm-rs/pull/87)
  Test SecureChannel MAC verification failure (fixes #14).

* [#86](https://github.com/tendermint/yubihsm-rs/pull/86)
  Initial reconnect support.

* [#84](https://github.com/tendermint/yubihsm-rs/pull/84)
  Support debug output using the `log` crate.

* [#83](https://github.com/tendermint/yubihsm-rs/pull/83)
  Handle session timeouts.

* [#82](https://github.com/tendermint/yubihsm-rs/pull/82)
  Handle NUL (i.e. `\0`) byte in label before UTF-8 conversion (fixes #81)

* [#80](https://github.com/tendermint/yubihsm-rs/pull/80)
  `derive(Clone)` for `WrapMessage`.

* [#79](https://github.com/tendermint/yubihsm-rs/pull/79)
  ObjectType json deserialization helper (u64).

## [0.13.0] (2018-07-14)

[0.13.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.12.0...v0.13.0

* [#77](https://github.com/tendermint/yubihsm-rs/pull/77)
  Implement `set_log_index` command.

* [#76](https://github.com/tendermint/yubihsm-rs/pull/77)
  Implement `generate_hmac_key`, `hmac`, and `verify_hmac` commands.

* [#75](https://github.com/tendermint/yubihsm-rs/pull/75)
  Remove dependency on rand 0.4.x.

* [#74](https://github.com/tendermint/yubihsm-rs/pull/74)
  Simplify and remove unnecessary response types.

## [0.12.0] (2018-07-14)

[0.12.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.11.2...v0.12.0

This release includes significant refactoring and API changes, in addition
to adding support for several commands.

* [#73](https://github.com/tendermint/yubihsm-rs/pull/73)
  Support multiple connections to MockHSM.

* [#69](https://github.com/tendermint/yubihsm-rs/pull/69)
  `AuthKey` type (and MockHSM support for `put_auth_key`).
  
* [#67](https://github.com/tendermint/yubihsm-rs/pull/67)
  Implement `get_opaque` command.

* [#66](https://github.com/tendermint/yubihsm-rs/pull/66)
  Implement `reset` command.

* [#65](https://github.com/tendermint/yubihsm-rs/pull/65)
  Implement `get_pseudo_random` command.

* [#64](https://github.com/tendermint/yubihsm-rs/pull/64)
  Factor `ObjectHandle` and `ObjectInfo` into `object` module.

* [#63](https://github.com/tendermint/yubihsm-rs/pull/63)
  Implement `storage_status` command.

* [#62](https://github.com/tendermint/yubihsm-rs/pull/62)
  Have `generate_*` and `put_*` commands return an `ObjectId`.

* [#61](https://github.com/tendermint/yubihsm-rs/pull/61)
  Refactor `object` module into modules for each type.

* [#60](https://github.com/tendermint/yubihsm-rs/pull/60)
  Implement wrapping: export, import, wrap, unwrap, generate wrap key.

* [#56](https://github.com/tendermint/yubihsm-rs/pull/56)
  Implement `close_session` command.

* [#55](https://github.com/tendermint/yubihsm-rs/pull/55)
  Implement `attest_asymmetric` command.

* [#53](https://github.com/tendermint/yubihsm-rs/pull/53)
  Implement `put_*` commands.

* [#51](https://github.com/tendermint/yubihsm-rs/pull/51)
  Factor all commands into their own individual modules.

* [#50](https://github.com/tendermint/yubihsm-rs/pull/50)
  Implement `sign_ecdsa_sha2` command.

* [#49](https://github.com/tendermint/yubihsm-rs/pull/49)
  Implement `get_logs` command.

* [#48](https://github.com/tendermint/yubihsm-rs/pull/48)
  Implement `device_info` command.

## [0.11.2] (2018-07-04)

[0.11.2]: https://github.com/tendermint/yubihsm-rs/compare/v0.11.1...v0.11.2

* [#47](https://github.com/tendermint/yubihsm-rs/pull/47)
  Use subtle crate for constant time equality.

## [0.11.1] (2018-07-04)

[0.11.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.11.0...v0.11.1

* [#46](https://github.com/tendermint/yubihsm-rs/pull/46)
  Upgrade to rand 0.5.

## [0.11.0] (2018-07-04)

[0.11.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.10.1...v0.11.0

* [#45](https://github.com/tendermint/yubihsm-rs/pull/45)
  Factor command methods from `Session` into `commands.rs`.

* [#44](https://github.com/tendermint/yubihsm-rs/pull/44)
  Implement SignDataECDSA command.

## [0.10.1] (2018-07-02)

[0.10.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.10.0...v0.10.1

* [#43](https://github.com/tendermint/yubihsm-rs/pull/43)
  Add a `nightly` feature.

## [0.10.0] (2018-06-28)

[0.10.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.9.0...v0.10.0

* [#42](https://github.com/tendermint/yubihsm-rs/pull/42)
  Use the `aes` crate.

* [#41](https://github.com/tendermint/yubihsm-rs/pull/41)
  Support Rust stable (1.27+).

## [0.9.0] (2018-05-19)

[0.9.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.8.0...v0.9.0

* [#39](https://github.com/tendermint/yubihsm-rs/pull/39)
  Error handling overhaul.

* [#38](https://github.com/tendermint/yubihsm-rs/pull/38)
  Export HttpConfig from crate toplevel.

## [0.8.0] (2018-04-12)

[0.8.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.7.3...v0.8.0

* [#36](https://github.com/tendermint/yubihsm-rs/pull/36)
  Integrated HttpConnector.

## [0.7.3] (2018-04-05)

[0.7.3]: https://github.com/tendermint/yubihsm-rs/compare/v0.7.2...v0.7.3

* [#34](https://github.com/tendermint/yubihsm-rs/pull/34)
  Mark Connector as Sync-safe.

## [0.7.2] (2018-03-31)

[0.7.2]: https://github.com/tendermint/yubihsm-rs/compare/v0.7.1...v0.7.2

* [#33](https://github.com/tendermint/yubihsm-rs/pull/33)
  Upgrade ed25519-dalek, sha2, and pbkdf2 crates.

## [0.7.1] (2018-03-27)

[0.7.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.7.0...v0.7.1

* [#32](https://github.com/tendermint/yubihsm-rs/pull/32)
  Improve DefaultConnector handling.

## [0.7.0] (2018-03-27)

[0.7.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.6.0...v0.7.0

* [#31](https://github.com/tendermint/yubihsm-rs/pull/31)
  Rename AbstractSession -> Session (by using default generic arg).

## [0.6.0] (2018-03-20)

[0.6.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.5.0...v0.6.0

* [#30](https://github.com/tendermint/yubihsm-rs/pull/30)
  Make MockHSM (and therefore all Connectors) Send-safe.

* [#29](https://github.com/tendermint/yubihsm-rs/pull/29)
  Expose connector status as an (Abstract)Session method.

## [0.5.0] (2018-03-20)

[0.5.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.4.0...v0.5.0

* [#28](https://github.com/tendermint/yubihsm-rs/pull/28)
  Convert `MockHSM` into a `yubihsm::Connector`.

## [0.4.0] (2018-03-20)

[0.4.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.3.0...v0.4.0

* [#25](https://github.com/tendermint/yubihsm-rs/pull/25)
  Refactor `Session` and `Connector`.

## [0.3.0] (2018-03-20)

[0.3.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.2.0...v0.3.0

* [#24](https://github.com/tendermint/yubihsm-rs/pull/24)
  Have `Session`s own `Connector`s.

## [0.2.0] (2018-03-12)

[0.2.0]: https://github.com/tendermint/yubihsm-rs/compare/v0.1.1...v0.2.0

* [#22](https://github.com/tendermint/yubihsm-rs/pull/22)
  Ensure command data is smaller than the YubiHSM2's buffer.

* [#20](https://github.com/tendermint/yubihsm-rs/pull/22)
  Implement Blink command.

## [0.1.1] (2018-03-07)

[0.1.1]: https://github.com/tendermint/yubihsm-rs/compare/v0.1.0...v0.1.1

* Fixes for docs.rs build

## 0.1.0 (2018-03-06)

* Initial release
