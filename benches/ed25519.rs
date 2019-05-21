//! Ed25519 signing performance benchmark

#![deny(warnings)]

use criterion::{criterion_group, criterion_main, Criterion};
use yubihsm;

const EXAMPLE_MESSAGE: &[u8] =
    b"The Edwards-curve Digital Signature yubihsm::AsymmetricAlgorithm  (EdDSA) is a \
    variant of Schnorr's signature system with (possibly twisted) Edwards curves.";

const BENCH_KEY_ID: yubihsm::object::Id = 999;

fn clear_key_slot(hsm: &mut yubihsm::Client) {
    let _ = hsm.delete_object(BENCH_KEY_ID, yubihsm::object::Type::AsymmetricKey);

    assert!(hsm
        .get_object_info(BENCH_KEY_ID, yubihsm::object::Type::AsymmetricKey)
        .is_err());
}

/// Create a public key for use in a test
fn generate_key(hsm: &mut yubihsm::Client) {
    clear_key_slot(hsm);

    let key_id = hsm
        .generate_asymmetric_key(
            BENCH_KEY_ID,
            "ed25519 benchmark key".into(),
            yubihsm::Domain::DOM1,
            yubihsm::Capability::SIGN_EDDSA,
            yubihsm::asymmetric::Algorithm::Ed25519,
        )
        .unwrap_or_else(|e| panic!("error generating asymmetric key: {}", e));

    assert_eq!(key_id, BENCH_KEY_ID);
}

fn sign_ed25519(c: &mut Criterion) {
    #[cfg(not(feature = "usb"))]
    let connector = yubihsm::Connector::http(&Default::default());

    #[cfg(feature = "usb")]
    let connector = yubihsm::Connector::usb(&Default::default());

    let mut hsm = yubihsm::Client::open(connector, Default::default(), true).unwrap();
    generate_key(&mut hsm);

    c.bench_function("ed25519 signing", move |b| {
        b.iter(|| {
            if let Err(e) = hsm.sign_ed25519(BENCH_KEY_ID, EXAMPLE_MESSAGE) {
                eprintln!("error performing ed25519 signature: {}", e);
            }
        })
    });
}

criterion_group!(ed25519, sign_ed25519);
criterion_main!(ed25519);
