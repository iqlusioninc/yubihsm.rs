<img src="https://raw.githubusercontent.com/iqlusioninc/yubihsm.rs/main/img/logo.png" width="150" height="110">

# yubihsm.rs

[![crate][crate-image]][crate-link] [![Docs][docs-image]][docs-link] [![Build Status][build-image]][build-link] [![Dependency Status][deps-image]][deps-link] ![Apache2/MIT licensed][license-image] ![MSRV][rustc-image]

Pure Rust client for [YubiHSM 2] devices from [Yubico].

[Documentation][docs-link]

## About

This is a pure-Rust client library for [YubiHSM 2] devices which implements
most the functionality of the [libyubihsm] C library from Yubico's YubiHSM SDK.
It provides two backends for communicating with YubiHSMs:

- [HTTP][http-connector]: communicate with YubiHSM via the `yubihsm-connector`
  process from the Yubico SDK.
- [USB][usb-connector]: communicate directly with the YubiHSM over USB using
  the [rusb] crate.

The [yubihsm::Client] type provides access to [HSM commands][command].

This is **NOT** an official Yubico project and is in no way supported
or endorsed by Yubico (although whoever runs their Twitter account
[thinks it's awesome]).

*NOTE: Looking for a YubiKey library instead of YubiHSM? Check out
[yubikey-piv.rs] instead.*

## Minimum Supported Rust Version

This crate requires Rust **1.57** or newer.

## Supported Commands

**NOTE:** If there's a command on this list you'd like to use which isn't presently
supported, please open an issue requesting support.

| [Command]                      | Impl'd | [MockHSM] | Description |
|--------------------------------|--------|-----------|-------------|
| [Authenticate Session]         | ✅     | ✅        | Authenticate to HSM with password or encryption key |
| [Blink Device]                 | ✅     | ✅        | Blink the HSM's LEDs (to identify it) |
| [Change Authentication Key]    | ⛔     | ⛔        | Replace the authentication key used to create current session |
| [Close Session]                | ✅     | ✅        | Terminate an encrypted session with the HSM |
| [Create OTP AEAD]              | ⛔     | ⛔        | Create a Yubico OTP AEAD |
| [Create Session]               | ✅     | ✅        | Initiate a new encrypted session with the HSM |
| [Decrypt OAEP]                 | ✅     | ⛔        | Decrypt data encrypted with RSA-OAEP |
| [Decrypt OTP]                  | ⛔     | ⛔        | Decrypt a Yubico OTP, obtaining counters and timer info |
| [Decrypt PKCS1]                | ⛔     | ⛔        | Decrypt data encrypted with RSA-PKCS#1v1.5 |
| [Delete Object]                | ✅     | ✅        | Delete an object of the given ID and type |
| [Derive ECDH]                  | ⚠️      | ⛔        | Compute Elliptic Curve Diffie-Hellman using HSM-backed key |
| [Device Info]                  | ✅     | ✅        | Get information about the HSM |
| [Echo]                         | ✅     | ✅        | Echo a message sent to the HSM |
| [Export Wrapped]               | ✅     | ✅        | Export an object from the HSM in encrypted form|
| [Generate Asymmetric Key]      | ✅     | ✅        | Randomly generate new asymmetric key in the HSM |
| [Generate HMAC Key]            | ✅     | ✅        | Randomly generate HMAC key in the HSM |
| [Generate OTP AEAD Key]        | ⛔     | ⛔        | Randomly generate AES key for Yubico OTP authentication |
| [Generate Wrap Key]            | ✅     | ✅        | Randomly generate AES key for exporting/importing objects |
| [Get Log Entries]              | ✅     | ✅        | Obtain the audit log for the HSM |
| [Get Object Info]              | ✅     | ✅        | Get information about an object |
| [Get Opaque]                   | ✅     | ✅        | Get an opaque bytestring from the HSM |
| [Get Option]                   | ✅     | ✅        | Get HSM auditing settings |
| [Get Pseudo Random]            | ✅     | ✅        | Get random data generated by the HSM's internal PRNG |
| [Get Public key]               | ✅     | ✅        | Get public key for an HSM-backed asymmetric private key |
| [Get Storage Info]             | ✅     | ✅        | Fetch information about currently free storage |
| [Get SSH Template]             | ✅     | ⛔        | Fetch SSH certificate template object from the HSM |
| [Import Wrapped]               | ✅     | ✅        | Import an encrypted key into the HSM |
| [List Objects]                 | ✅     | ✅        | List objects visible from the current session |
| [Put Asymmetric Key]           | ✅     | ✅        | Put an existing asymmetric key into the HSM |
| [Put Authentication Key]       | ✅     | ✅        | Put YubiHSM authentication key into the HSM |
| [Put HMAC Key]                 | ✅     | ✅        | Put an HMAC key into the HSM |
| [Put Opaque]                   | ✅     | ✅        | Put an opaque bytestring into the HSM |
| [Put OTP AEAD Key]             | ✅     | ⛔        | Put a Yubico OTP key into the HSM |
| [Put SSH Template]             | ✅     | ⛔        | Put SSH certificate template object into the HSM |
| [Put Wrap Key]                 | ✅     | ✅        | Put an AES keywrapping key into the HSM |
| [Randomize OTP AEAD]           | ⛔     | ⛔        | Randomly generate a Yubico OTP AEAD |
| [Reset Device]                 | ✅     | ✅        | Reset the HSM back to factory default settings |
| [Rewrap OTP AEAD]              | ⛔     | ⛔        | Re-wrap a Yubico OTP AEAD from one key to another |
| [Session Message]              | ✅     | ✅        | Send an encrypted message to the HSM |
| [Set Log Index]                | ✅     | ✅        | Mark log messages in the HSM as consumed |
| [Set Option]                   | ✅     | ✅        | Change HSM auditing settings |
| [Sign Attestation Certificate] | ✅     | ⛔        | Create X.509 certificate for asymmetric key |
| [Sign ECDSA]                   | ✅     | ✅        | Compute an ECDSA signature using HSM-backed key |
| [Sign EdDSA]                   | ✅     | ✅        | Compute an Ed25519 signature using HSM-backed key |
| [Sign HMAC]                    | ✅     | ✅        | Perform an HMAC operation using an HSM-backed key |
| [Sign PKCS1]                   | ⚠️      | ⛔        | Compute an RSASSA-PKCS#1v1.5 signature using HSM-backed key |
| [Sign PSS]                     | ⚠️      | ⛔        | Compute an RSASSA-PSS signature using HSM-backed key |
| [Sign SSH Certificate]         | ⚠️      | ⛔        | Sign an SSH certificate request |
| [Unwrap Data]                  | ✅     | ⛔        | Decrypt data encrypted using a wrap key |
| [Verify HMAC]                  | ✅     | ✅        | Verify that an HMAC tag for given data is valid |
| [Wrap Data]                    | ✅     | ⛔        | Encrypt data using a wrap key |

|    | Status                   |
|----|--------------------------|
| ✅ | Supported                |
| ⚠️ | Partial/Untested Support |
| ⛔ | Unsupported              |

NOTE: Commands marked ⚠️ have not been properly tested and may contain bugs or
not work at all. They are disabled by default: to use them you must enable the
`untested` cargo feature. If you do get them to work, please open an issue
(or PR) reporting success so we can promote them to ✅.

## Testing

This crate allows you to run the [integration test] suite in three different ways:

- Live testing against a real YubiHSM2 device:
  - via HTTP
  - via USB
- simulated testing using [MockHSM] which implements some YubiHSM2 functionality

### `cargo test`: test YubiHSM2 live over HTTP via `yubihsm-connector`

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

### `cargo test --features=usb`: test YubiHSM2 live via USB

Adding the `usb` cargo feature builds in USB connector support in addition to
HTTP connector, and also runs the test suite live via USB rather than using
the `yubihsm-connector` process.

**ALSO NOTE THAT THESE TESTS ARE DESTRUCTIVE: DO NOT RUN THEM AGAINST A
YUBIHSM2 WHICH CONTAINS KEYS YOU CARE ABOUT**

### `cargo test --features=mockhsm`: simulated tests against a mock HSM

This mode is useful for when you don't have access to physical YubiHSM2
hardware, such as CI environments.

## License

**yubihsm.rs** is distributed under the terms of both the MIT license and
the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/yubihsm
[crate-link]: https://crates.io/crates/yubihsm
[docs-image]: https://docs.rs/yubihsm/badge.svg
[docs-link]: https://docs.rs/yubihsm/
[build-image]: https://github.com/iqlusioninc/yubihsm.rs/workflows/CI/badge.svg?branch=main&event=push
[build-link]: https://github.com/iqlusioninc/yubihsm.rs/actions?query=workflow:CI
[deps-image]: https://deps.rs/repo/github/iqlusioninc/yubihsm.rs/status.svg
[deps-link]: https://deps.rs/repo/github/iqlusioninc/yubihsm.rs
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg

[//]: # (general links)

[libyubihsm]: https://github.com/Yubico/yubihsm-shell/blob/master/lib/README.adoc
[YubiHSM 2]: https://www.yubico.com/products/yubihsm/
[Yubico]: https://www.yubico.com/
[yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/
[http-connector]: https://docs.rs/yubihsm/latest/yubihsm/connector/struct.Connector.html#method.http
[usb-connector]: https://docs.rs/yubihsm/latest/yubihsm/connector/struct.Connector.html#method.usb
[yubihsm::Client]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html
[command]: https://developers.yubico.com/YubiHSM2/Commands/
[rusb]: https://github.com/a1ien/rusb
[thinks it's awesome]: https://twitter.com/Yubico/status/971186516796915712
[yubikey-piv.rs]: https://github.com/iqlusioninc/yubikey-piv.rs
[YubiHSM2 commands]: https://developers.yubico.com/YubiHSM2/Commands/
[Serde-based message parser]: https://github.com/iqlusioninc/yubihsm.rs/tree/main/src/serialization
[commands]: https://github.com/iqlusioninc/yubihsm.rs/tree/main/src/command
[integration test]:  https://github.com/iqlusioninc/yubihsm.rs/blob/main/tests/integration.rs
[MockHSM]: https://docs.rs/yubihsm/latest/yubihsm/mockhsm/struct.MockHsm.html
[YubiHSM2 SDK]: https://developers.yubico.com/YubiHSM2/Releases/
[yubihsm-shell reset]: https://developers.yubico.com/YubiHSM2/Commands/Reset_Device.html

[//]: # (YubiHSM2 commands)

[Authenticate Session]: https://developers.yubico.com/YubiHSM2/Commands/Authenticate_Session.html
[Blink Device]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.blink_device
[Change Authentication Key]: https://developers.yubico.com/YubiHSM2/Commands/Change_Authentication_Key.html
[Close Session]: https://developers.yubico.com/YubiHSM2/Commands/Close_Session.html
[Create OTP AEAD]: https://developers.yubico.com/YubiHSM2/Commands/Create_Otp_Aead.html
[Create Session]: https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html
[Derive ECDH]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.derive_ecdh
[Decrypt OAEP]: https://developers.yubico.com/YubiHSM2/Commands/Decrypt_Oaep.html
[Decrypt OTP]: https://developers.yubico.com/YubiHSM2/Commands/Decrypt_Otp.html
[Decrypt PKCS1]: https://developers.yubico.com/YubiHSM2/Commands/Decrypt_Pkcs1.html
[Delete Object]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.delete_object
[Device Info]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.device_info
[Echo]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.echo
[Export Wrapped]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.export_wrapped
[Generate Asymmetric Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.generate_asymmetric_key
[Generate HMAC Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.generate_hmac_key
[Generate OTP AEAD Key]: https://developers.yubico.com/YubiHSM2/Commands/Generate_Otp_Aead_Key.html
[Generate Wrap Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.generate_wrap_key
[Get Log Entries]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_log_entries
[Get Object Info]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_object_info
[Get Opaque]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_opaque
[Get Option]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_command_audit_option
[Get Pseudo Random]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_pseudo_random
[Get Public Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_pubkey
[Get Storage Info]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.storage_info
[Get SSH Template]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_template
[Import Wrapped]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.import_wrapped
[List Objects]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.list_objects
[Put Asymmetric Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_asymmetric_key
[Put Authentication Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_auth_key
[Put HMAC Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_hmac_key
[Put Opaque]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_opaque
[Put OTP AEAD Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_otp_aead_key
[Put SSH Template]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_template
[Put Wrap Key]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_wrap_key
[Randomize OTP AEAD]: https://developers.yubico.com/YubiHSM2/Commands/Randomize_Otp_Aead.html
[Reset Device]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.reset_device
[Rewrap OTP AEAD]: https://developers.yubico.com/YubiHSM2/Commands/Rewrap_Otp_Aead.html
[Session Message]: https://developers.yubico.com/YubiHSM2/Commands/Session_Message.html
[Set Log Index]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.set_log_index
[Set Option]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.set_audit_option
[Sign Attestation Certificate]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.sign_attestation_certificate
[Sign ECDSA]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.sign_ecdsa
[Sign EdDSA]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.sign_ed25519
[Sign HMAC]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.sign_hmac
[Sign PKCS1]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.sign_rsa_pkcs1v15_sha256
[Sign PSS]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.sign_rsa_pss_sha256
[Sign SSH Certificate]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.sign_ssh_certificate
[Unwrap Data]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.unwrap_data
[Verify HMAC]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.verify_hmac
[Wrap Data]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.wrap_data
