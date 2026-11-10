//! The plain `Gather` routing surface over real presence, lookup, quota and room owners.
//! The signed material is the same retained fixture and G1 construction the accounting
//! boundary tests use; here every call goes through `Gather` itself, never `AccountGather`.
#![cfg(all(feature = "accounting", not(target_arch = "wasm32")))]

use cgth::{Error, Gather, clkp, cmbl, cmmr, cswb, cthl};
use cmmr::Clock;
use ed25519_dalek::Signer as _;
use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[allow(dead_code)]
#[path = "accounting/fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "accounting/g1.rs"]
mod g1;
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
type Plain = Gather<Memory, Time, RandomTokens, cthl::MemoryStore>;

fn member(byte: u8) -> String {
    data_encoding::HEXLOWER.encode(&[byte; 48])
}
fn memory(community: &str, scope: &str, clock: &Time) -> Memory {
    Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new(community, scope).unwrap(),
            cmmr::Limits {
                records: 64,
                value_bytes: 1024 * 1024,
                batch: 4,
                indexes_per_record: 4,
                page: 8,
                ttl_ms: 600_000,
            },
            clock.clone(),
        )
        .unwrap(),
    )
}
fn plain(native: &Fixture) -> (Plain, Memory, Time) {
    let community = &native.material.community;
    let clock = Time(Arc::new(AtomicU64::new(native.now * 1000)));
    let store = memory(community, "gather-routing", &clock);
    let presence = cswb::Switchboard::new(
        store.clone(),
        clock.clone(),
        RandomTokens,
        community.clone(),
        cswb::Limits {
            lease_ms: 300_000,
            publication_bytes: cpfl::MAX_PROFILE_BYTES,
            ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
        },
    )
    .unwrap();
    let throttle = cthl::Throttle::new(
        community,
        [(
            "entry",
            cthl::Limit::new(1000, Duration::from_secs(1)).unwrap(),
        )],
        cthl::MemoryStore::new(NonZeroUsize::new(1024).unwrap()),
    )
    .unwrap();
    let rooms = cmbl::Assembly::new(
        store.clone(),
        community.clone(),
        "gather-routing".into(),
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
    (Gather::new(presence, throttle, rooms, lookup), store, clock)
}
async fn enter(gather: &Plain, g1: &mut G1, native: &Fixture) -> (cswb::Session, cswb::Live) {
    let publication = g1.publication.clone();
    let challenge = gather
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let signature = g1
        .device
        .sign(&cswb::challenge_message(
            ORIGIN,
            &native.material.community,
            &challenge,
            &publication.signed,
        ))
        .to_bytes();
    gather
        .admit(
            cswb::EntryProof {
                origin: ORIGIN,
                challenge: &challenge,
                signature: &signature,
                publication: &publication,
            },
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap()
}
async fn authorize(
    gather: &Plain,
    g1: &mut G1,
    session: &cswb::Session,
    now: u64,
    nonce: u8,
) -> cswb::Current {
    let (action, body) = ("read", b"gather-routing".as_slice());
    let nonce = [nonce; 16];
    let possession = cswb::Possession {
        nonce,
        signature: g1
            .device
            .sign(&cswb::request_message(
                ORIGIN, action, session, &nonce, body,
            ))
            .to_bytes()
            .to_vec(),
    };
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

#[tokio::test]
async fn presence_lookup_and_room_listing_route_to_their_owners() {
    let native = Fixture::load();
    let (gather, _store, _clock) = plain(&native);
    let mut alice = G1::new(&native, &member(7), 1, 10_000).await;
    let mut bob = G1::new(&native, &member(8), 1, 10_000).await;
    let (alice_session, alice_live) = enter(&gather, &mut alice, &native).await;
    let (bob_session, _) = enter(&gather, &mut bob, &native).await;
    let current = authorize(&gather, &mut alice, &alice_session, native.now, 1).await;
    let request = |cursor| clkp::PageRequest {
        session: &alice_session,
        current: &current,
        cursor,
        limit: 3,
    };

    // Lookup: the one other present member is a candidate; its watch cursor and
    // ciphertext come from the same Lookup child and the same presence rows.
    let matches = gather
        .page(request(None), &alice.verification(native.now), &clean)
        .await
        .unwrap();
    assert_eq!(matches.entries.len(), 1);
    assert_eq!(matches.entries[0].member, member(8));
    let delta = gather
        .watch(
            clkp::WatchRequest {
                session: &alice_session,
                current: &current,
                cursor: &matches.watch,
            },
            &alice.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert!(delta.upserts.is_empty() && delta.removed.is_empty());
    let ciphertext = gather
        .ciphertext(
            request(None),
            (&matches.entries[0].member, matches.entries[0].revision),
            &alice.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(ciphertext, bob.publication.ciphertext);
    // An unknown candidate and a refused request fail through the lookup owner.
    assert!(matches!(
        gather
            .ciphertext(
                request(None),
                (&member(9), 1),
                &alice.verification(native.now),
                &clean
            )
            .await,
        Err(Error::Lookup(_))
    ));
    assert!(matches!(
        gather
            .page(
                clkp::PageRequest {
                    session: &alice_session,
                    current: &current,
                    cursor: None,
                    limit: 0,
                },
                &alice.verification(native.now),
                &clean
            )
            .await,
        Err(Error::Lookup(clkp::LookupError::Invalid))
    ));

    // Presence: read, heartbeat, replacement, replace and re-entry.
    let read = gather.read(&alice_session, &current).await.unwrap();
    assert_eq!(read.revision, alice_live.revision);
    let renewed = gather
        .heartbeat(&alice_session, &current, alice_live.revision)
        .await
        .unwrap();
    assert_ne!(renewed.revision, alice_live.revision);
    assert_eq!(
        gather
            .read(&alice_session, &current)
            .await
            .unwrap()
            .revision,
        renewed.revision
    );
    let current = authorize(&gather, &mut alice, &alice_session, native.now, 2).await;
    let mut second = G1::new(&native, &member(7), 2, 10_000).await;
    let mut third = G1::new(&native, &member(7), 3, 10_000).await;
    let (second_publication, third_publication) =
        (second.publication.clone(), third.publication.clone());
    let replaced = gather
        .replacement(
            &alice_session,
            &current,
            &second_publication,
            &second.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let reentry = gather
        .replacement(
            &alice_session,
            &current,
            &third_publication,
            &third.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let stale = gather
        .replacement(
            &alice_session,
            &current,
            &third_publication,
            &third.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let live = gather
        .replace(&alice_session, &current, renewed.revision, replaced)
        .await
        .unwrap();
    assert_ne!(live.revision, renewed.revision);
    // The superseded revision cannot replace a second time.
    assert!(matches!(
        gather
            .replace(&alice_session, &current, renewed.revision, stale)
            .await,
        Err(Error::Presence(_))
    ));
    assert!(gather.depart(&alice_session).await.unwrap() > 0);
    assert!(gather.depart(&bob_session).await.unwrap() > 0);
    let (_, entered) = gather.enter(reentry).await.unwrap();
    assert!(entered.revision != live.revision);

    // Public room listing: nothing is listed in a fresh assembly.
    let page = gather.list_rooms(None, 4, native.now * 1000).await.unwrap();
    assert!(page.rooms.is_empty());
    assert!(page.next.is_none());
}

#[cfg(feature = "issuer")]
#[tokio::test]
async fn room_issuer_installation_and_issuance_guards_refuse_before_the_owner() {
    use cmbl::passes::{BlindRequest, issuer::BudgetedIssuer};

    let native = Fixture::load();
    let community = native.material.community.clone();
    let (mut gather, store, clock) = plain(&native);
    let now = native.now * 1000;
    let mut alice = G1::new(&native, &member(7), 1, 10_000).await;
    let (session, _) = enter(&gather, &mut alice, &native).await;
    let current = authorize(&gather, &mut alice, &session, native.now, 1).await;
    let request = BlindRequest {
        context: [0; 32],
        blinded: Vec::new(),
    };

    // No issuer yet: neither the descriptor nor a pass can come from this facade.
    assert_eq!(
        gather.room_epoch(now).await.err(),
        Some(Error::Rooms(cmbl::Error::ProofUnavailable))
    );
    assert_eq!(
        gather
            .issue_room_pass(&current, [1; 16], &request, now)
            .await,
        Err(Error::Rooms(cmbl::Error::ProofUnavailable))
    );
    // The sealed admission's own deadline outranks everything after it.
    assert_eq!(
        gather
            .issue_room_pass(&current, [1; 16], &request, current.authority_until())
            .await,
        Err(Error::Presence(cswb::Error::Expired))
    );

    let issuer = BudgetedIssuer::create(store, community.clone(), 1, now, now + 300_000, 4)
        .await
        .unwrap();
    gather.install_room_issuer(issuer).unwrap();
    assert_eq!(gather.room_epoch(now).await.unwrap().community, community);
    // A second issuer in the same incarnation is a conflict and replaces nothing.
    let second = BudgetedIssuer::create(
        memory(&community, "second-incarnation", &clock),
        community.clone(),
        2,
        now,
        now + 300_000,
        4,
    )
    .await
    .unwrap();
    assert_eq!(
        gather.install_room_issuer(second),
        Err(Error::Rooms(cmbl::Error::Conflict))
    );
    assert_eq!(gather.room_epoch(now).await.unwrap().epoch, 1);

    // An issuer of another community never issues for this member.
    let (mut foreign, _, _) = plain(&native);
    let other = BudgetedIssuer::create(
        memory("other-community", "foreign", &clock),
        "other-community".into(),
        1,
        now,
        now + 300_000,
        4,
    )
    .await
    .unwrap();
    foreign.install_room_issuer(other).unwrap();
    assert_eq!(
        foreign
            .issue_room_pass(&current, [1; 16], &request, now)
            .await,
        Err(Error::Rooms(cmbl::Error::Refused))
    );
}
