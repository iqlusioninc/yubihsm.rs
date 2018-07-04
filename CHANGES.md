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
