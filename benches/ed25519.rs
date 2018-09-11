//! Ed25519 signing performance benchmark

#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate yubihsm;

use criterion::Criterion;

const EXAMPLE_MESSAGE: &[u8] =
    b"The Edwards-curve Digital Signature yubihsm::AsymmetricAlgorithm  (EdDSA) is a \
    variant of Schnorr's signature system with (possibly twisted) Edwards curves.";

const BENCH_KEY_ID: yubihsm::ObjectId = 999;

#[cfg(not(feature = "usb"))]
fn init_yubihsm_session() -> yubihsm::HttpSession {
    yubihsm::HttpSession::create(Default::default(), Default::default(), true).unwrap()
}

#[cfg(feature = "usb")]
fn init_yubihsm_session() -> yubihsm::UsbSession {
    yubihsm::UsbSession::create(Default::default(), Default::default(), true).unwrap()
}

fn clear_key_slot<A>(session: &mut yubihsm::Session<A>)
where
    A: yubihsm::Adapter,
{
    let _ = yubihsm::delete_object(session, BENCH_KEY_ID, yubihsm::ObjectType::AsymmetricKey);
    assert!(
        yubihsm::get_object_info(session, BENCH_KEY_ID, yubihsm::ObjectType::AsymmetricKey)
            .is_err()
    );
}

/// Create a public key for use in a test
fn generate_key<A>(session: &mut yubihsm::Session<A>)
where
    A: yubihsm::Adapter,
{
    clear_key_slot(session);

    let key_id = yubihsm::generate_asymmetric_key(
        session,
        BENCH_KEY_ID,
        "ed25519 benchmark key".into(),
        yubihsm::Domain::DOM1,
        yubihsm::Capability::ASYMMETRIC_SIGN_EDDSA,
        yubihsm::AsymmetricAlg::Ed25519,
    ).unwrap_or_else(|e| panic!("error generating asymmetric key: {}", e));

    assert_eq!(key_id, BENCH_KEY_ID);
}

fn sign_ed25519(c: &mut Criterion) {
    let mut session = init_yubihsm_session();
    generate_key(&mut session);

    c.bench_function("ed25519 signing", move |b| {
        b.iter(|| yubihsm::sign_ed25519(&mut session, BENCH_KEY_ID, EXAMPLE_MESSAGE).unwrap())
    });
}

criterion_group!(ed25519, sign_ed25519);
criterion_main!(ed25519);
