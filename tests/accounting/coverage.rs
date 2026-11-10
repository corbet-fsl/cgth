//! The complete owner's guarded refusal arms at the accounting boundary:
//! configuration, retained record evidence, read cuts and room authority.
//! Genuine retained R2 evidence from the fixture only; every refusal is
//! asserted by its exact variant, never by a bare `is_err`.
use super::*;
use cgth::accounting::{
    AccountGather, Authorized, CiphertextRequest, PageRequest, RoomConfiguration,
};

/// The one test clock. Every `now()` observes `base` for the first `held`
/// calls and `base + jump` afterwards, so a single request can be given a
/// clock that crosses a deadline mid-operation while the volatile store keeps
/// its own frozen clock.
#[derive(Clone)]
pub(super) struct Step {
    base: Arc<AtomicU64>,
    calls: Arc<AtomicU64>,
    held: Arc<AtomicU64>,
    jump: Arc<AtomicU64>,
    fail_at: Arc<AtomicU64>,
}
impl Step {
    pub(super) fn at(now: u64) -> Self {
        Self {
            base: Arc::new(AtomicU64::new(now)),
            calls: Arc::new(AtomicU64::new(0)),
            held: Arc::new(AtomicU64::new(u64::MAX)),
            jump: Arc::new(AtomicU64::new(0)),
            fail_at: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }
    /// Hold the first `held` observations, then advance by `jump` milliseconds.
    pub(super) fn script(&self, held: u64, jump: u64) {
        self.calls.store(0, Ordering::SeqCst);
        self.held.store(held, Ordering::SeqCst);
        self.jump.store(jump, Ordering::SeqCst);
        self.fail_at.store(u64::MAX, Ordering::SeqCst);
    }
    /// Fail the observation at `at` exactly, as an unavailable host clock does.
    pub(super) fn refuse_at(&self, at: u64) {
        self.calls.store(0, Ordering::SeqCst);
        self.held.store(u64::MAX, Ordering::SeqCst);
        self.jump.store(0, Ordering::SeqCst);
        self.fail_at.store(at, Ordering::SeqCst);
    }
}
impl Clock for Step {
    fn now(&self) -> Result<u64, cmmr::Error> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == self.fail_at.load(Ordering::SeqCst) {
            return Err(cmmr::Error::ClockRegression);
        }
        let base = self.base.load(Ordering::SeqCst);
        Ok(if call < self.held.load(Ordering::SeqCst) {
            base
        } else {
            base.saturating_add(self.jump.load(Ordering::SeqCst))
        })
    }
}

pub(super) type Owner = AccountGather<Memory, Step, RandomTokens, cthl::MemoryStore>;

pub(super) struct Ensemble {
    pub(super) owner: Owner,
    pub(super) store: Memory,
    pub(super) clock: Step,
    pub(super) wall: Time,
}

/// Trusted configuration the fixture community actually published.
pub(super) fn tuned(native: &Fixture) -> Configuration {
    Configuration {
        community: native.material.community.clone(),
        period_key: g1::PERIOD_KEY.into(),
        period_seconds: native.trusted_period_seconds,
    }
}

pub(super) fn open(
    native: &Fixture,
    records: usize,
    configuration: Configuration,
) -> Result<Ensemble, Error> {
    open_at(native, records, configuration, native.now * 1000)
}

fn open_at(
    native: &Fixture,
    records: usize,
    configuration: Configuration,
    now: u64,
) -> Result<Ensemble, Error> {
    let wall = Time(Arc::new(AtomicU64::new(now)));
    let clock = Step::at(now);
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
            wall.clone(),
        )
        .unwrap(),
    );
    let presence = cswb::Switchboard::new(
        store.clone(),
        clock.clone(),
        RandomTokens,
        native.material.community.clone(),
        cswb::Limits {
            lease_ms: 300_000,
            publication_bytes: cpfl::MAX_PROFILE_BYTES,
            ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
        },
    )
    .unwrap();
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
    let owner = AccountGather::new(
        gather,
        configuration,
        native.native(),
        cblc::verification::ExtensionLimits {
            global_burst: 1000,
            subject_burst: 1000,
            replenish: Duration::from_secs(1),
            maximum_keys: NonZeroUsize::new(32).unwrap(),
        },
        clock.clone(),
    )?;
    Ok(Ensemble {
        owner,
        store,
        clock,
        wall,
    })
}

pub(super) fn ensemble(native: &Fixture, records: usize) -> Ensemble {
    open(native, records, tuned(native)).unwrap()
}

pub(super) async fn enter_into(
    owner: &mut Owner,
    g1: &mut G1,
    native: &Fixture,
) -> (cswb::Session, cswb::Live) {
    let publication = g1.publication.clone();
    let challenge = owner
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let context: czkp::record::Context = serde_json::from_slice(&challenge.payload).unwrap();
    let presentation = native.presentation(context);
    let signature = entry_signature(g1, native, &challenge);
    owner
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

pub(super) async fn authorize_into(
    owner: &mut Owner,
    g1: &mut G1,
    session: &cswb::Session,
    now: u64,
    action: &str,
    nonce: u8,
    body: &[u8],
) -> Authorized {
    let possession = possession(g1, session, action, nonce, body);
    owner
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

/// One retention row written by the lower presence owner alone, so the
/// complete owner meets the exact evidence a higher boundary would retain.
pub(super) async fn planted(
    ensemble: &Ensemble,
    g1: &mut G1,
    native: &Fixture,
    attachment: Option<cswb::Attachment>,
) -> cswb::Session {
    let lower = board(ensemble.store.clone(), ensemble.wall.clone(), native);
    let publication = g1.publication.clone();
    let challenge = lower
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let signature = entry_signature(g1, native, &challenge);
    let prepared = lower
        .prepare_entry(
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
        .unwrap();
    lower
        .commit_entry(prepared, attachment, challenge.expires_at_ms)
        .await
        .unwrap()
        .0
}

pub(super) fn retained(native: &Fixture) -> Vec<u8> {
    serde_json::to_vec(&cgth::accounting::PublicRecord {
        record: native.record.clone(),
        proof: native.proof.clone(),
    })
    .unwrap()
}

pub(super) fn room_configuration(native: &Fixture) -> RoomConfiguration {
    RoomConfiguration {
        incarnation: "native-accounting".into(),
        epoch: 1,
        valid_from_ms: native.now * 1000,
        valid_until_ms: (native.now + 3) * 1000,
    }
}

/// One authenticated member whose own room issuer is already activated.
pub(super) async fn activated(native: &Fixture) -> (Ensemble, G1, cswb::Session, Authorized) {
    let mut ensemble = ensemble(native, 64);
    let mut g1 = G1::new(native, &member(7), 1, 10_000).await;
    let (session, _) = enter_into(&mut ensemble.owner, &mut g1, native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut g1,
        &session,
        native.now,
        "room",
        1,
        b"room",
    )
    .await;
    ensemble
        .owner
        .activate_rooms(
            ensemble.store.clone(),
            room_configuration(native),
            &current,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    (ensemble, g1, session, current)
}

// The owner's trusted configuration decides whether any operation can run at
// all. An empty period key and an unsupported period are refused at creation.
#[tokio::test]
async fn an_owner_without_a_period_key_or_supported_period_never_opens() {
    let native = Fixture::load();
    let mut absent = tuned(&native);
    absent.period_key = String::new();
    assert!(matches!(
        open(&native, 8, absent),
        Err(Error::AccountingUnavailable)
    ));
    let mut zero = tuned(&native);
    zero.period_seconds = 0;
    assert!(matches!(
        open(&native, 8, zero),
        Err(Error::AccountingUnavailable)
    ));
}

// Cheap quota precedes the caller's expensive verification, so the complete
// owner must route it to the configured child unchanged.
#[tokio::test]
async fn preflight_is_routed_to_the_configured_quota_owner() {
    let native = Fixture::load();
    let mut ensemble = ensemble(&native, 8);
    ensemble.owner.preflight(b"account", "entry").await.unwrap();
}

// A configured community or period that the sealed Charter does not name is
// refused before any retained record bytes are read.
#[tokio::test]
async fn a_foreign_community_or_period_never_reaches_record_evidence() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let mut foreign = tuned(&native);
    foreign.community = format!("{}.other", native.material.community);
    let mut key = tuned(&native);
    key.period_key = "absent.record_epoch_period_seconds".into();
    let mut seconds = tuned(&native);
    seconds.period_seconds = native.trusted_period_seconds + 1;
    for configuration in [foreign, key, seconds] {
        let mut ensemble = open(&native, 8, configuration).unwrap();
        let publication = g1.publication.clone();
        assert!(matches!(
            ensemble
                .owner
                .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
                .await,
            Err(Error::AccountingUnavailable)
        ));
    }
}

// An envelope from an earlier generation can neither read nor renew, a
// renewal that names another revision is stale, and the expiry pass is owns.
#[tokio::test]
async fn an_envelope_from_another_generation_is_refused_by_every_read() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(&native, 64);
    let ensemble = &mut ensemble;
    let (first, _) = enter_into(&mut ensemble.owner, &mut g1, &native).await;
    let (second, live) = enter_into(&mut ensemble.owner, &mut g1, &native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut g1,
        &second,
        native.now,
        "read",
        1,
        b"read",
    )
    .await;
    assert!(matches!(
        ensemble
            .owner
            .read(
                Read {
                    session: &first,
                    current: &current,
                },
                &g1.verification(native.now),
                &clean,
            )
            .await,
        Err(Error::Presence(cswb::Error::Stale))
    ));
    assert!(matches!(
        ensemble
            .owner
            .heartbeat(
                Read {
                    session: &first,
                    current: &current,
                },
                live.revision,
                &g1.verification(native.now),
            )
            .await,
        Err(Error::Presence(cswb::Error::Stale))
    ));
    assert!(matches!(
        ensemble
            .owner
            .heartbeat(
                Read {
                    session: &second,
                    current: &current,
                },
                cmmr::Revision([0; 16]),
                &g1.verification(native.now),
            )
            .await,
        Err(Error::Presence(cswb::Error::Stale))
    ));
    assert_eq!(ensemble.owner.expire().await.unwrap(), 0);
}

// A row retained by the lower presence owner with a record whose native proof
// does not verify cannot become accounting authority.
#[tokio::test]
async fn a_retained_record_whose_proof_fails_the_native_owner_cannot_authorize() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(&native, 64);
    let mut tampered = cgth::accounting::PublicRecord {
        record: native.record.clone(),
        proof: native.proof.clone(),
    };
    let changed = if tampered.proof.starts_with("00") {
        "01"
    } else {
        "00"
    };
    tampered.proof.replace_range(..2, changed);
    let attachment = cswb::Attachment::new(
        serde_json::to_vec(&tampered).unwrap(),
        native.record.epoch.expires_at * 1000,
    )
    .unwrap();
    let session = planted(&ensemble, &mut g1, &native, Some(attachment)).await;
    let possession = possession(&g1, &session, "read", 1, b"read");
    assert!(matches!(
        ensemble
            .owner
            .authorize(
                cswb::RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "read",
                    body: b"read",
                    possession: &possession,
                },
                &g1.verification(native.now),
                &clean,
            )
            .await,
        Err(Error::AccountingUnavailable)
    ));
}

// Every activation window is checked against the sealed common epoch, and an
// unsupported release constant cannot become a room issuer. The same window
// activated twice returns the original owner instead of a replacement.
#[tokio::test]
async fn a_room_configuration_outside_the_sealed_epoch_is_refused() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(&native, 64);
    let ensemble = &mut ensemble;
    let (session, _) = enter_into(&mut ensemble.owner, &mut g1, &native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut g1,
        &session,
        native.now,
        "room",
        1,
        b"room",
    )
    .await;
    let good = room_configuration(&native);
    let mut unnamed = good.clone();
    unnamed.epoch = 0;
    let mut homeless = good.clone();
    homeless.incarnation = String::new();
    let mut reversed = good.clone();
    reversed.valid_from_ms = good.valid_until_ms;
    let mut before_epoch = good.clone();
    before_epoch.valid_from_ms = (native.now - 16) * 1000;
    let mut after_now = good.clone();
    after_now.valid_from_ms = (native.now + 1) * 1000;
    let mut closed = good.clone();
    closed.valid_from_ms = (native.now - 5) * 1000;
    closed.valid_until_ms = native.now * 1000;
    for (configuration, why) in [
        (homeless, "no incarnation"),
        (unnamed, "epoch 0"),
        (reversed, "empty window"),
        (before_epoch, "before the common epoch"),
        (after_now, "starts in the future"),
        (closed, "already closed"),
    ] {
        assert!(
            matches!(
                ensemble
                    .owner
                    .activate_rooms(
                        ensemble.store.clone(),
                        configuration,
                        &current,
                        &g1.verification(native.now),
                        &clean
                    )
                    .await,
                Err(Error::AccountingUnavailable)
            ),
            "{why}"
        );
        assert!(
            ensemble
                .store
                .get("room-pass-issuer")
                .await
                .unwrap()
                .is_none(),
            "{why}"
        );
    }
    ensemble.owner.set_room_quota(0);
    assert!(matches!(
        ensemble
            .owner
            .activate_rooms(
                ensemble.store.clone(),
                good.clone(),
                &current,
                &g1.verification(native.now),
                &clean
            )
            .await,
        Err(Error::AccountingUnavailable)
    ));
    ensemble
        .owner
        .set_room_quota(crbk::FORUM_ROOM_PASSES_PER_EPOCH);
    ensemble
        .owner
        .activate_rooms(
            ensemble.store.clone(),
            good.clone(),
            &current,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    ensemble
        .owner
        .activate_rooms(
            ensemble.store.clone(),
            good,
            &current,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert!(
        ensemble
            .store
            .get("room-pass-issuer")
            .await
            .unwrap()
            .is_some()
    );
    // A current member's own envelope reads one page of the room listing.
    assert!(
        ensemble
            .owner
            .list_rooms(
                Read {
                    session: &session,
                    current: &current,
                },
                None,
                8,
                &g1.verification(native.now),
                &clean,
            )
            .await
            .is_ok()
    );
}

// ---- authenticated Charter revisions (a reseal, never a caller value) ----

#[derive(Default)]
pub(super) struct Change {
    forum: Option<bool>,
    record: Option<Option<czkp::record::Epoch>>,
    epoch: Option<u64>,
    starts_at: Option<u64>,
    expires_at: Option<u64>,
    digest: Option<[u8; 32]>,
}

fn signed(
    issuer: &mut csgn::Signer,
    kind: csgn::Kind,
    value: serde_json::Value,
    now: u64,
    deadline: u64,
) -> Vec<u8> {
    issuer
        .sign(kind, &serde_json::to_vec(&value).unwrap(), now, deadline)
        .unwrap()
}

/// Install one newer sealed Charter revision from the fixture issuer. Only the
/// named projection changes; every other signed value stays as published.
pub(super) fn reseal(g1: &mut G1, native: &Fixture, revision: u64, deadline: u64, change: Change) {
    use csgn::{Kind, SecretKey, Signer};
    let community = native.material.community.clone();
    let now = native.now;
    let policy_epoch = native.material.policy_epoch;
    let mut issuer = Signer::new(&community, SecretKey::from_seed(&mut [31; 32]), 1, 2000).unwrap();
    let mut book = crbk::Rulebook::default();
    if change.forum.unwrap_or(true) {
        crbk::define_forum_settings(&mut book).unwrap();
    }
    crbk::RecordEpochSettings::define(&mut book, g1::PERIOD_KEY).unwrap();
    book.set_community(
        g1::PERIOD_KEY,
        Some(serde_json::json!(native.trusted_period_seconds)),
    )
    .unwrap();
    crbk::RecordEpochSettings::validate_catalogue(&book, g1::PERIOD_KEY).unwrap();
    let mut settings = serde_json::to_value(book.resolve(&Default::default()).unwrap()).unwrap();
    settings["action/community.admit"] = serde_json::json!({"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]});
    let schema: cshm::Schema = serde_json::from_value(
        serde_json::json!({"community":community,"version":1,"public":[],"private":[]}),
    )
    .unwrap();
    let mut material = native.material.clone();
    material.revision = revision;
    if let Some(record) = change.record {
        material.record_epoch = record;
    }
    if let Some(descriptor) = material.record_epoch.as_mut() {
        if let Some(number) = change.epoch {
            descriptor.epoch = number;
        }
        if let Some(starts) = change.starts_at {
            descriptor.starts_at = starts;
        }
        if let Some(expires) = change.expires_at {
            descriptor.expires_at = expires;
        }
    }
    if let Some(digest) = change.digest {
        material.policy_digest = digest;
    }
    let mut feed = serde_json::json!({
        "revision": revision,
        "policy_epoch": policy_epoch,
        "key_ring": issuer.key_ring().to_cbor(),
        "balance": signed(&mut issuer, Kind::SettingsSnapshot, serde_json::to_value(&material).unwrap(), now, deadline),
    });
    let manifest = serde_json::json!({"purpose":"cplc.trust.v1","community":community,"revision":revision,"policy_epoch":policy_epoch,"key_ring":issuer.key_ring().to_cbor(),"schema_version":1,"balance_revision":revision});
    feed["manifest"] = serde_json::json!(signed(
        &mut issuer,
        Kind::SettingsSnapshot,
        manifest,
        now,
        deadline
    ));
    for (name, kind, content) in [
        ("settings", Kind::SettingsSnapshot, settings),
        ("schema", Kind::SchemaSnapshot, serde_json::json!(schema)),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            serde_json::json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        (
            "communities",
            Kind::CommunitiesSnapshot,
            serde_json::json!([community]),
        ),
        (
            "revocations",
            Kind::RevocationListSnapshot,
            serde_json::json!({"members":[],"devices":[]}),
        ),
    ] {
        feed[name] = serde_json::json!(signed(
            &mut issuer,
            kind,
            serde_json::json!({"community":community,"revision":revision,"policy_epoch":policy_epoch,"content":content}),
            now,
            deadline
        ));
    }
    g1.charter
        .install(&serde_json::to_vec(&feed).unwrap(), now)
        .unwrap();
}

// A newer signed balance never extends the exact record evidence an earlier
// operation retained: the cached record is rechecked against the sealed view.
#[tokio::test]
async fn a_charter_revision_after_the_record_check_refuses_the_retained_evidence() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(&native, 64);
    let ensemble = &mut ensemble;
    let (session, _) = enter_into(&mut ensemble.owner, &mut g1, &native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut g1,
        &session,
        native.now,
        "read",
        1,
        b"read",
    )
    .await;
    reseal(&mut g1, &native, 2, native.now + 300, Change::default());
    assert!(matches!(
        ensemble
            .owner
            .read(
                Read {
                    session: &session,
                    current: &current,
                },
                &g1.verification(native.now),
                &clean,
            )
            .await,
        Err(Error::AccountingUnavailable)
    ));
}

// Existing device authority replaces its own live row only for the exact
// revision, and only with a record whose native proof verifies.
#[tokio::test]
async fn a_replacement_names_the_live_revision_and_a_verifiable_record() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(&native, 64);
    let ensemble = &mut ensemble;
    let (session, live) = enter_into(&mut ensemble.owner, &mut g1, &native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut g1,
        &session,
        native.now,
        "replace",
        2,
        b"replace",
    )
    .await;
    let mut replacement = G1::new(&native, &member(7), 2, 10_000).await;
    let publication = replacement.publication.clone();
    let public = cgth::accounting::PublicRecord {
        record: native.record.clone(),
        proof: native.proof.clone(),
    };
    assert!(matches!(
        ensemble
            .owner
            .replace(
                Replacement {
                    read: Read {
                        session: &session,
                        current: &current,
                    },
                    expected: cmmr::Revision([0; 16]),
                    publication: &publication,
                    record: &public,
                    accepting_waves: None,
                },
                &replacement.verification(native.now),
                &clean,
            )
            .await,
        Err(Error::Presence(cswb::Error::Stale))
    ));
    let mut tampered = cgth::accounting::PublicRecord {
        record: native.record.clone(),
        proof: native.proof.clone(),
    };
    let changed = if tampered.proof.starts_with("00") {
        "01"
    } else {
        "00"
    };
    tampered.proof.replace_range(..2, changed);
    assert!(matches!(
        ensemble
            .owner
            .replace(
                Replacement {
                    read: Read {
                        session: &session,
                        current: &current,
                    },
                    expected: live.revision,
                    publication: &publication,
                    record: &tampered,
                    accepting_waves: None,
                },
                &replacement.verification(native.now),
                &clean,
            )
            .await,
        Err(Error::AccountingUnavailable)
    ));
}

fn anonymous() -> cmbl::Request {
    cmbl::Request {
        room: [8; 16],
        operation: [10; 16],
        action: cmbl::Action::Resume {
            connection: [9; 16],
        },
    }
}

// A sealed Charter that withdraws the common epoch cannot keep the original
// room issuer alive, and a restored epoch cannot revive it.
#[tokio::test]
async fn a_withdrawn_common_epoch_permanently_fences_the_room_owner() {
    let native = Fixture::load();
    let (mut ensemble, mut g1, _session, _current) = activated(&native).await;
    reseal(
        &mut g1,
        &native,
        2,
        native.now + 300,
        Change {
            record: Some(None),
            ..Default::default()
        },
    );
    let refused = ensemble
        .owner
        .room(&anonymous(), &[], &g1.verification(native.now))
        .await
        .err();
    assert!(
        matches!(refused, Some(Error::AccountingUnavailable)),
        "{refused:?}"
    );
    reseal(
        &mut g1,
        &native,
        3,
        native.now + 300,
        Change {
            record: Some(native.material.record_epoch.clone()),
            ..Default::default()
        },
    );
    let refused = ensemble
        .owner
        .room(&anonymous(), &[], &g1.verification(native.now))
        .await
        .err();
    assert!(
        matches!(refused, Some(Error::AccountingUnavailable)),
        "{refused:?}"
    );
}

// The common epoch descriptor, not a caller value, anchors the issuer: another
// authenticated descriptor fences it permanently.
#[tokio::test]
async fn another_epoch_descriptor_fences_the_room_owner() {
    let native = Fixture::load();
    let (mut ensemble, mut g1, _session, _current) = activated(&native).await;
    reseal(
        &mut g1,
        &native,
        2,
        native.now + 300,
        Change {
            epoch: Some(2),
            ..Default::default()
        },
    );
    let refused = ensemble
        .owner
        .room(&anonymous(), &[], &g1.verification(native.now))
        .await
        .err();
    assert!(
        matches!(refused, Some(Error::AccountingUnavailable)),
        "{refused:?}"
    );
    reseal(&mut g1, &native, 3, native.now + 300, Change::default());
    assert!(matches!(
        ensemble
            .owner
            .room(&anonymous(), &[], &g1.verification(native.now))
            .await,
        Err(Error::AccountingUnavailable)
    ));
}

// An authenticated policy digest that differs from the anchor's fences it.
#[tokio::test]
async fn another_authenticated_policy_digest_fences_the_room_owner() {
    let native = Fixture::load();
    let (mut ensemble, mut g1, _session, _current) = activated(&native).await;
    reseal(
        &mut g1,
        &native,
        2,
        native.now + 300,
        Change {
            digest: Some([9; 32]),
            ..Default::default()
        },
    );
    assert!(matches!(
        ensemble
            .owner
            .room(&anonymous(), &[], &g1.verification(native.now))
            .await,
        Err(Error::AccountingUnavailable)
    ));
}

// Candidates retained by the lower presence owner without verifiable record
// evidence are omitted before any observation reaches the result.
#[tokio::test]
async fn a_page_omits_candidates_without_verifiable_record_evidence() {
    let native = Fixture::load();
    let mut requester = G1::new(&native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(&native, 64);
    let ensemble = &mut ensemble;
    let (session, _) = enter_into(&mut ensemble.owner, &mut requester, &native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut requester,
        &session,
        native.now,
        "page",
        1,
        b"page",
    )
    .await;
    let until = native.record.epoch.expires_at * 1000;
    let mut bare = G1::new(&native, &member(8), 1, 10_000).await;
    planted(&ensemble, &mut bare, &native, None).await;
    let mut junk = G1::new(&native, &member(9), 1, 10_000).await;
    planted(
        &ensemble,
        &mut junk,
        &native,
        Some(cswb::Attachment::new(b"retained but opaque".to_vec(), until).unwrap()),
    )
    .await;
    let mut odd = G1::new(&native, "ab", 1, 10_000).await;
    planted(
        &ensemble,
        &mut odd,
        &native,
        Some(cswb::Attachment::new(retained(&native), until).unwrap()),
    )
    .await;
    let page = ensemble
        .owner
        .page(
            PageRequest {
                read: Read {
                    session: &session,
                    current: &current,
                },
                cursor: None,
                limit: 3,
            },
            &requester.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert!(page.entries.is_empty());
}

// One original publication is only disclosed for its own member, revision and
// reciprocal pair; the same member never reads itself.
#[tokio::test]
async fn a_ciphertext_request_names_its_own_member_and_revision() {
    let native = Fixture::load();
    let mut requester = G1::new(&native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(&native, 64);
    let ensemble = &mut ensemble;
    let (session, _) = enter_into(&mut ensemble.owner, &mut requester, &native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut requester,
        &session,
        native.now,
        "ciphertext",
        1,
        b"ciphertext",
    )
    .await;
    for revision in [1, 7] {
        assert!(matches!(
            ensemble
                .owner
                .ciphertext(
                    CiphertextRequest {
                        read: Read {
                            session: &session,
                            current: &current,
                        },
                        member: &member(7),
                        revision,
                    },
                    &requester.verification(native.now),
                    &clean,
                )
                .await,
            Err(Error::Lookup(clkp::LookupError::ResetRequired))
        ));
    }
}

// ---- one request observed by an advancing clock ----
//
// A host that observes a later time between two cuts of one request must not
// be able to finish it. Each test names which observation is late and asserts
// the exact refusal of the cut that observes it; every request is given fresh
// volatile state so the retained observation floor starts at the same time.

async fn reading(native: &Fixture, held: u64, jump: u64) -> Result<(), Error> {
    let mut g1 = G1::new(native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(native, 64);
    let (session, _) = enter_into(&mut ensemble.owner, &mut g1, native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut g1,
        &session,
        native.now,
        "read",
        1,
        b"read",
    )
    .await;
    ensemble.clock.script(held, jump);
    ensemble
        .owner
        .read(
            Read {
                session: &session,
                current: &current,
            },
            &g1.verification(native.now),
            &clean,
        )
        .await
        .map(|_| ())
}

// The second accounting cut observes the record window after the first one
// passed, and the presence cut observes the row deadline last.
#[tokio::test]
async fn a_read_refuses_the_cut_that_observes_a_later_time() {
    let native = Fixture::load();
    assert!(matches!(
        reading(&native, 2, 85_000).await,
        Err(Error::AccountingUnavailable)
    ));
    assert!(matches!(
        reading(&native, 8, 60_000).await,
        Err(Error::Presence(cswb::Error::Expired))
    ));
}

async fn beating(native: &Fixture, held: u64) -> Result<(), Error> {
    let mut g1 = G1::new(native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(native, 64);
    let (session, live) = enter_into(&mut ensemble.owner, &mut g1, native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut g1,
        &session,
        native.now,
        "read",
        1,
        b"read",
    )
    .await;
    ensemble.clock.script(held, 60_000);
    ensemble
        .owner
        .heartbeat(
            Read {
                session: &session,
                current: &current,
            },
            live.revision,
            &g1.verification(native.now),
        )
        .await
        .map(|_| ())
}

// Before the write the live row deadline is cut; after the write the renewed
// liveness deadline is cut, so a lease is never extended silently.
#[tokio::test]
async fn a_heartbeat_refuses_the_cut_that_observes_a_later_time() {
    let native = Fixture::load();
    assert!(matches!(
        beating(&native, 3).await,
        Err(Error::Presence(cswb::Error::Expired))
    ));
    assert!(matches!(
        beating(&native, 9).await,
        Err(Error::Presence(cswb::Error::Expired))
    ));
}

async fn challenging(native: &Fixture, held: u64) -> Result<(), Error> {
    let mut g1 = G1::new(native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(native, 64);
    let publication = g1.publication.clone();
    ensemble.clock.script(held, 60_000);
    ensemble
        .owner
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .map(|_| ())
}

// The context the service bounds for the device and the final cut that
// publishes it are separate observations of the same presence deadline.
#[tokio::test]
async fn a_challenge_refuses_the_cut_that_observes_a_later_time() {
    let native = Fixture::load();
    assert!(matches!(
        challenging(&native, 4).await,
        Err(Error::Presence(cswb::Error::TrustUnavailable))
    ));
    assert!(matches!(
        challenging(&native, 5).await,
        Err(Error::AccountingUnavailable)
    ));
}

async fn admitting(native: &Fixture, held: u64) -> Result<(), Error> {
    let mut g1 = G1::new(native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(native, 64);
    let publication = g1.publication.clone();
    let challenge = ensemble
        .owner
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let context: czkp::record::Context = serde_json::from_slice(&challenge.payload).unwrap();
    let presentation = native.presentation(context);
    let signature = entry_signature(&g1, &native, &challenge);
    ensemble.clock.script(held, 85_000);
    ensemble
        .owner
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
        .map(|_| ())
}

// The record window is cut before the commit, again after the commit, and the
// committed deadline is cut last. A single late observation refuses the entry.
#[tokio::test]
async fn an_admission_refuses_the_cut_that_observes_a_later_time() {
    let native = Fixture::load();
    let mut outcomes = Vec::new();
    for held in 0..=18u64 {
        let outcome = admitting(&native, held).await;
        let done = outcome.is_ok();
        outcomes.push(outcome.err());
        if done {
            break;
        }
    }
    let succeeded = outcomes.iter().rposition(|o| o.is_none());
    assert!(succeeded.is_some_and(|at| at > 4), "{outcomes:?}");
    assert!(
        outcomes
            .iter()
            .flatten()
            .any(|error| matches!(error, Error::AccountingUnavailable)),
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .flatten()
            .any(|error| matches!(error, Error::Presence(cswb::Error::Expired))),
        "{outcomes:?}"
    );
}

async fn replacing(native: &Fixture, held: u64) -> Result<(), Error> {
    let mut g1 = G1::new(native, &member(7), 1, 10_000).await;
    let mut replacement = G1::new(native, &member(7), 2, 10_000).await;
    let mut ensemble = ensemble(native, 64);
    let (session, live) = enter_into(&mut ensemble.owner, &mut g1, native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut g1,
        &session,
        native.now,
        "replace",
        2,
        b"replace",
    )
    .await;
    let publication = replacement.publication.clone();
    let public = cgth::accounting::PublicRecord {
        record: native.record.clone(),
        proof: native.proof.clone(),
    };
    ensemble.clock.script(held, 85_000);
    ensemble
        .owner
        .replace(
            Replacement {
                read: Read {
                    session: &session,
                    current: &current,
                },
                expected: live.revision,
                publication: &publication,
                record: &public,
                accepting_waves: None,
            },
            &replacement.verification(native.now),
            &clean,
        )
        .await
        .map(|_| ())
}

// The record window is cut before the replacement write and after it, and the
// replaced row's own deadline is cut last.
#[tokio::test]
async fn a_replacement_refuses_the_cut_that_observes_a_later_time() {
    let native = Fixture::load();
    let mut outcomes = Vec::new();
    for held in 0..=30u64 {
        let outcome = replacing(&native, held).await;
        let done = outcome.is_ok();
        outcomes.push(outcome.err());
        if done {
            break;
        }
    }
    let succeeded = outcomes.iter().rposition(|o| o.is_none());
    assert!(succeeded.is_some_and(|at| at > 4), "{outcomes:?}");
    assert!(
        outcomes
            .iter()
            .flatten()
            .any(|error| matches!(error, Error::AccountingUnavailable)),
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .flatten()
            .any(|error| matches!(error, Error::Presence(cswb::Error::Expired))),
        "{outcomes:?}"
    );
}

async fn paging(native: &Fixture, held: u64, jump: u64) -> Result<(), Error> {
    let mut requester = G1::new(native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(native, 64);
    let (session, _) = enter_into(&mut ensemble.owner, &mut requester, native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut requester,
        &session,
        native.now,
        "page",
        1,
        b"page",
    )
    .await;
    ensemble.clock.script(held, jump);
    ensemble
        .owner
        .page(
            PageRequest {
                read: Read {
                    session: &session,
                    current: &current,
                },
                cursor: None,
                limit: 3,
            },
            &requester.verification(native.now),
            &clean,
        )
        .await
        .map(|_| ())
}

// The associated record evidence of the requester is verified by the lookup
// owner against the same sealed record window, and its exact row deadline is
// cut at the evidence observation.
#[tokio::test]
async fn a_page_refuses_the_cut_that_observes_a_later_time() {
    let native = Fixture::load();
    // The evidence's own row deadline is observed after the record window.
    assert!(matches!(
        paging(&native, 13, 60_000).await,
        Err(Error::Lookup(clkp::LookupError::Associated))
    ));
    // The later record window is observed while the associated record is kept.
    assert!(matches!(
        paging(&native, 13, 85_000).await,
        Err(Error::Lookup(clkp::LookupError::Associated))
    ));
    // The sealed Charter deadline is observed at the evidence check.
    assert!(matches!(
        paging(&native, 13, 300_000).await,
        Err(Error::Lookup(clkp::LookupError::Associated))
    ));
    // The associated currentness cut observes the record window again.
    assert!(matches!(
        paging(&native, 15, 85_000).await,
        Err(Error::Lookup(clkp::LookupError::Associated))
    ));
}

async fn paging_unobservable(native: &Fixture, at: u64) -> Result<(), Error> {
    let mut requester = G1::new(native, &member(7), 1, 10_000).await;
    let mut ensemble = ensemble(native, 64);
    let (session, _) = enter_into(&mut ensemble.owner, &mut requester, native).await;
    let current = authorize_into(
        &mut ensemble.owner,
        &mut requester,
        &session,
        native.now,
        "page",
        1,
        b"page",
    )
    .await;
    ensemble.clock.refuse_at(at);
    ensemble
        .owner
        .page(
            PageRequest {
                read: Read {
                    session: &session,
                    current: &current,
                },
                cursor: None,
                limit: 3,
            },
            &requester.verification(native.now),
            &clean,
        )
        .await
        .map(|_| ())
}

// A host clock that cannot observe time refuses the whole read at whichever
// cut observes it: the record verification, its completion observation, and
// both observations of the associated currentness cut. No page is returned.
#[tokio::test]
async fn a_page_whose_clock_cannot_observe_time_is_refused() {
    let native = Fixture::load();
    let mut observed = Vec::new();
    for at in 13..=20u64 {
        let refused = paging_unobservable(&native, at).await.err();
        assert!(refused.is_some(), "{at}: no observation point failed");
        observed.push(refused);
    }
    assert!(
        observed
            .iter()
            .flatten()
            .any(|error| matches!(error, Error::Lookup(clkp::LookupError::Associated))),
        "{observed:?}"
    );
}

// Room authority: the final epoch recheck after the issuer answered observes
// the record window once more.
#[tokio::test]
async fn a_room_epoch_refuses_the_cut_that_observes_a_later_time() {
    let native = Fixture::load();
    let (mut ensemble, mut g1, _session, current) = activated(&native).await;
    ensemble.clock.script(23, 85_000);
    assert!(matches!(
        ensemble
            .owner
            .room_epoch(&current, &g1.verification(native.now), &clean)
            .await,
        Err(Error::AccountingUnavailable)
    ));
}

// The owner's own observation floor refuses a zero or out-of-range host time
// before any cut is attempted.
#[tokio::test]
async fn an_impossible_observed_time_is_refused() {
    let native = Fixture::load();
    for base in [0, cmmr::MAX_TIME + 1] {
        let mut ensemble = open_at(&native, 8, tuned(&native), base).unwrap();
        assert!(matches!(
            ensemble.owner.observed_now(),
            Err(Error::AccountingUnavailable)
        ));
    }
}

// A member binding that is not a canonical 48-byte pseudonym cannot name an
// accounting owner, so a retained row under it never becomes authority.
#[tokio::test]
async fn a_member_binding_that_is_not_a_pseudonym_cannot_authorize() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, "zz", 1, 10_000).await;
    let mut ensemble = ensemble(&native, 64);
    let session = planted(
        &ensemble,
        &mut g1,
        &native,
        Some(
            cswb::Attachment::new(retained(&native), native.record.epoch.expires_at * 1000)
                .unwrap(),
        ),
    )
    .await;
    let possession = possession(&g1, &session, "read", 1, b"read");
    assert!(matches!(
        ensemble
            .owner
            .authorize(
                cswb::RequestProof {
                    origin: ORIGIN,
                    session: &session,
                    action: "read",
                    body: b"read",
                    possession: &possession,
                },
                &g1.verification(native.now),
                &clean,
            )
            .await,
        Err(Error::AccountingUnavailable)
    ));
}

// Without an original activation there is no issuer to fence, and the same
// sealed-material refusal holds.
#[tokio::test]
async fn a_room_read_without_an_activation_is_refused() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let mut foreign = tuned(&native);
    foreign.community = format!("{}.other", native.material.community);
    let mut ensemble = open(&native, 64, foreign).unwrap();
    let refused = ensemble
        .owner
        .room(&anonymous(), &[], &g1.verification(native.now))
        .await
        .err();
    assert!(
        matches!(refused, Some(Error::AccountingUnavailable)),
        "{refused:?}"
    );
}

// The anonymous use rechecks the sealed epoch after the issuer answered, and
// the last observation of that cut refuses a later time.
#[tokio::test]
async fn a_room_read_refuses_the_cut_that_observes_a_later_time() {
    let native = Fixture::load();
    let (mut ensemble, mut g1, _session, _current) = activated(&native).await;
    ensemble.clock.script(3, 85_000);
    let refused = ensemble
        .owner
        .room(&anonymous(), &[], &g1.verification(native.now))
        .await
        .err();
    assert!(
        matches!(refused, Some(Error::AccountingUnavailable)),
        "{refused:?}"
    );
}

// The associated currentness cut reads the sealed record material and its
// current publication again, so a late observation is refused there too.
#[tokio::test]
async fn a_page_cuts_the_associated_currentness_window() {
    let native = Fixture::load();
    let mut observed = Vec::new();
    for at in 15..=18u64 {
        for jump in [300_000u64, 85_000] {
            let refused = paging(&native, at, jump).await.err();
            assert!(
                refused.is_some(),
                "{at}/{jump}: no observation point failed"
            );
            observed.push(refused);
        }
    }
    assert!(
        observed
            .iter()
            .flatten()
            .any(|error| matches!(error, Error::Lookup(clkp::LookupError::Associated))),
        "{observed:?}"
    );
}
