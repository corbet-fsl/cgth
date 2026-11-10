//! Genuine retained native R2 evidence through the complete Gather boundary.
//! The configured fixture issuer exercises G1 owners, not CPLC issuance policy.
#![cfg(all(feature = "accounting", not(target_arch = "wasm32")))]

use cgth::accounting::{AccountGather, Configuration, PublicRecord, Read, Replacement};
use cgth::{Error, Gather, clkp, cmbl, cmmr, cswb, cthl};
use cmmr::{Clock, Store};
use ed25519_dalek::Signer as _;
use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[path = "accounting/coverage.rs"]
mod coverage;
#[path = "accounting/fixture.rs"]
mod fixture;
#[path = "accounting/g1.rs"]
mod g1;
#[path = "accounting/lookup.rs"]
mod lookup;
#[path = "accounting/refusals.rs"]
mod refusals;
#[cfg(feature = "issuer")]
#[path = "accounting/rooms.rs"]
mod rooms;
use fixture::Fixture;
use g1::{G1, ORIGIN, clean};

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
struct RandomTokens;
impl cswb::Tokens for RandomTokens {
    fn next(&self) -> Result<[u8; 16], cswb::Error> {
        use ckmg::Entropy;
        let mut token = [0; 16];
        ckmg::SystemEntropy
            .fill(&mut token)
            .map_err(|_| cswb::Error::Invalid)?;
        Ok(token)
    }
}
type Memory = Arc<cmmr::Memory<Time>>;
type Complete = AccountGather<Memory, Time, RandomTokens, cthl::MemoryStore>;
type Board = cswb::Switchboard<Memory, Time, RandomTokens>;

fn member(byte: u8) -> String {
    data_encoding::HEXLOWER.encode(&[byte; 48])
}
fn board(store: Memory, clock: Time, native: &Fixture) -> Board {
    cswb::Switchboard::new(
        store,
        clock,
        RandomTokens,
        native.material.community.clone(),
        cswb::Limits {
            lease_ms: 300_000,
            publication_bytes: cpfl::MAX_PROFILE_BYTES,
            ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
        },
    )
    .unwrap()
}
fn complete(native: &Fixture, records: usize) -> (Complete, Memory, Time) {
    let clock = Time(Arc::new(AtomicU64::new(native.now * 1000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new(&native.material.community, "native-accounting").unwrap(),
            cmmr::Limits {
                records,
                value_bytes: 1024 * 1024,
                batch: 4,
                indexes_per_record: 4,
                page: 8,
                ttl_ms: 600_000,
            },
            clock.clone(),
        )
        .unwrap(),
    );
    let presence = board(store.clone(), clock.clone(), native);
    let throttle = cthl::Throttle::new(
        &native.material.community,
        [(
            "entry",
            cthl::Limit::new(1000, Duration::from_secs(1)).unwrap(),
        )],
        cthl::MemoryStore::new(NonZeroUsize::new(1024).unwrap()),
    )
    .unwrap();
    let rooms = cmbl::Assembly::new(
        store.clone(),
        native.material.community.clone(),
        "native-accounting".into(),
        cmbl::Limits {
            connections: 8,
            relay_messages: 8,
            message_bytes: 4096,
            lifetime_ms: 10_000,
            proof_bytes: 4096,
            operation_receipts: 16,
        },
    )
    .unwrap();
    let lookup = clkp::Lookup::new(
        store.clone(),
        RandomTokens,
        clkp::LookupLimits {
            candidates: 3,
            publication_bytes: cpfl::MAX_PROFILE_BYTES * 3,
        },
    )
    .unwrap();
    let gather = Gather::new(presence, throttle, rooms, lookup);
    let complete = AccountGather::new(
        gather,
        Configuration {
            community: native.material.community.clone(),
            period_key: g1::PERIOD_KEY.into(),
            period_seconds: native.trusted_period_seconds,
        },
        native.native(),
        cblc::verification::ExtensionLimits {
            global_burst: 1000,
            subject_burst: 1000,
            replenish: Duration::from_secs(1),
            maximum_keys: NonZeroUsize::new(32).unwrap(),
        },
        clock.clone(),
    )
    .unwrap();
    (complete, store, clock)
}
fn entry_signature(g1: &G1, native: &Fixture, challenge: &cswb::Challenge) -> Vec<u8> {
    g1.device
        .sign(&cswb::challenge_message(
            ORIGIN,
            &native.material.community,
            challenge,
            &g1.publication.signed,
        ))
        .to_bytes()
        .to_vec()
}
fn possession(
    g1: &G1,
    session: &cswb::Session,
    action: &str,
    nonce: u8,
    body: &[u8],
) -> cswb::Possession {
    let nonce = [nonce; 16];
    cswb::Possession {
        nonce,
        signature: g1
            .device
            .sign(&cswb::request_message(
                ORIGIN, action, session, &nonce, body,
            ))
            .to_bytes()
            .to_vec(),
    }
}
async fn authorize(
    gather: &mut Complete,
    g1: &mut G1,
    session: &cswb::Session,
    now: u64,
    action: &str,
    nonce: u8,
    body: &[u8],
) -> cgth::accounting::Authorized {
    let possession = possession(g1, session, action, nonce, body);
    gather
        .authorize(
            cswb::RequestProof {
                origin: ORIGIN,
                session,
                action,
                body,
                possession: &possession,
            },
            &g1.verification(now),
            &clean,
        )
        .await
        .unwrap()
}
async fn enter(
    gather: &mut Complete,
    g1: &mut G1,
    native: &Fixture,
) -> (cswb::Session, cswb::Live) {
    let publication = g1.publication.clone();
    let challenge = gather
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let context: czkp::record::Context = serde_json::from_slice(&challenge.payload).unwrap();
    let presentation = native.presentation(context);
    let signature = entry_signature(g1, native, &challenge);
    gather
        .admit(
            cswb::EntryProof {
                origin: ORIGIN,
                challenge: &challenge,
                signature: &signature,
                publication: &publication,
            },
            &presentation,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn real_native_entry_retains_exact_record_and_rechecks_reads_and_replacement() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let (mut gather, store, clock) = complete(&native, 64);
    let (session, live) = enter(&mut gather, &mut g1, &native).await;
    let authorized = authorize(
        &mut gather,
        &mut g1,
        &session,
        native.now,
        "read",
        1,
        b"read-body",
    )
    .await;
    assert_eq!(authorized.binding().member, member(7));
    assert_eq!(
        authorized.authority_until(),
        native.record.epoch.expires_at * 1000
    );
    let retained = store
        .get(&cswb::attendance_key(
            &member(7),
            &g1.device.verifying_key().to_bytes(),
        ))
        .await
        .unwrap()
        .unwrap();
    let row: serde_json::Value = serde_json::from_slice(&retained.value).unwrap();
    let bytes: Vec<u8> = serde_json::from_value(row["attachment"]["bytes"].clone()).unwrap();
    let public: PublicRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(public.record, native.record);
    assert_eq!(public.proof, native.proof);
    assert!(
        !row["attachment"]
            .as_object()
            .unwrap()
            .contains_key("context")
    );
    let read = gather
        .read(
            Read {
                session: &session,
                current: &authorized,
            },
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(read.revision, live.revision);
    assert_eq!(read.publication.signed, g1.publication.signed);

    let renewed = gather
        .heartbeat(
            Read {
                session: &session,
                current: &authorized,
            },
            live.revision,
            &g1.verification(native.now),
        )
        .await
        .unwrap();
    assert_ne!(renewed.revision, live.revision);
    let authorized = authorize(
        &mut gather,
        &mut g1,
        &session,
        native.now,
        "replace",
        2,
        b"replace-body",
    )
    .await;
    let mut replacement = G1::new(&native, &member(7), 2, 10_000).await;
    let new_publication = replacement.publication.clone();
    let replaced = gather
        .replace(
            Replacement {
                read: Read {
                    session: &session,
                    current: &authorized,
                },
                expected: renewed.revision,
                publication: &new_publication,
                record: &public,
                accepting_waves: None,
            },
            &replacement.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(replaced.publication.signed, new_publication.signed);
    // The old exact row capability cannot read a later same-generation update.
    assert!(
        gather
            .read(
                Read {
                    session: &session,
                    current: &authorized
                },
                &replacement.verification(native.now),
                &clean
            )
            .await
            .is_err()
    );
    let current = authorize(
        &mut gather,
        &mut replacement,
        &session,
        native.now,
        "read",
        3,
        b"current-body",
    )
    .await;
    assert_eq!(
        gather
            .read(
                Read {
                    session: &session,
                    current: &current
                },
                &replacement.verification(native.now),
                &clean
            )
            .await
            .unwrap()
            .revision,
        replaced.revision
    );
    // Signature, Charter and credential remain valid at the record's exclusive
    // epoch expiry. The actual accounting owner must independently refuse it.
    clock
        .0
        .store(native.record.epoch.expires_at * 1000, Ordering::SeqCst);
    assert!(
        gather
            .read(
                Read {
                    session: &session,
                    current: &current
                },
                &replacement.verification(native.record.epoch.expires_at),
                &clean
            )
            .await
            .is_err()
    );
}
