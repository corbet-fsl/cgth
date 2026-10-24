//! Genuine R2 member entry, original blind RSA issuance and anonymous Assembly.
use super::*;
use cgth::accounting::RoomConfiguration;

fn configuration(native: &Fixture) -> RoomConfiguration {
    RoomConfiguration {
        incarnation: "native-accounting".into(),
        epoch: 1,
        valid_from_ms: native.now * 1000,
        valid_until_ms: (native.now + 3) * 1000,
    }
}

// Actual fixture publication signer. Refreshing authenticated metadata changes
// neither the native proof nor its record descriptor or accounting policy.
fn refresh(g1: &mut G1, native: &Fixture, revision: u64) {
    refresh_record(g1, native, revision, None);
}
fn refresh_record(
    g1: &mut G1,
    native: &Fixture,
    revision: u64,
    record: Option<Option<czkp::record::Epoch>>,
) {
    use csgn::{Kind, SecretKey, Signer};
    let mut issuer = Signer::new(
        &native.material.community,
        SecretKey::from_seed(&mut [31; 32]),
        1,
        2000,
    )
    .unwrap();
    let mut feed = g1::feed(native, 10_000);
    feed["revision"] = revision.into();
    let balance_revision = if let Some(record) = record {
        let mut material = native.material.clone();
        material.revision += revision;
        material.record_epoch = record;
        feed["balance"] = serde_json::to_value(
            issuer
                .sign(
                    Kind::SettingsSnapshot,
                    &serde_json::to_vec(&material).unwrap(),
                    native.now,
                    native.now + 600,
                )
                .unwrap(),
        )
        .unwrap();
        Some(material.revision)
    } else {
        None
    };
    for (name, kind) in [
        ("manifest", Kind::SettingsSnapshot),
        ("settings", Kind::SettingsSnapshot),
        ("schema", Kind::SchemaSnapshot),
        ("schema_versions", Kind::SchemaSnapshot),
        ("communities", Kind::CommunitiesSnapshot),
        ("revocations", Kind::RevocationListSnapshot),
    ] {
        let bytes: Vec<u8> = serde_json::from_value(feed[name].clone()).unwrap();
        let signed = issuer.key_ring().verify(&bytes, kind, native.now).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(signed.payload()).unwrap();
        value["revision"] = revision.into();
        if name == "manifest" {
            if let Some(revision) = balance_revision {
                value["balance_revision"] = revision.into();
            }
        }
        feed[name] = serde_json::to_value(
            issuer
                .sign(
                    kind,
                    &serde_json::to_vec(&value).unwrap(),
                    native.now,
                    native.now + 600,
                )
                .unwrap(),
        )
        .unwrap();
    }
    g1.charter
        .install(&serde_json::to_vec(&feed).unwrap(), native.now)
        .unwrap();
}

#[tokio::test]
async fn native_member_issues_one_frozen_epoch_then_anonymous_room_survives_departure_until_expiry()
{
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let (mut gather, store, clock) = complete(&native, 64);
    let (session, _) = enter(&mut gather, &mut g1, &native).await;
    let current = authorize(
        &mut gather,
        &mut g1,
        &session,
        native.now,
        "room",
        1,
        b"room",
    )
    .await;
    let configuration = configuration(&native);
    let mut excessive = configuration.clone();
    excessive.valid_until_ms = current.authority_until() + 1;
    assert!(
        gather
            .activate_rooms(
                store.clone(),
                excessive,
                &current,
                &g1.verification(native.now),
                &clean
            )
            .await
            .is_err()
    );
    assert!(store.get("room-pass-issuer").await.unwrap().is_none());
    gather
        .activate_rooms(
            store.clone(),
            configuration.clone(),
            &current,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let epoch = gather
        .room_epoch(&current, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    assert_eq!(epoch.valid_until, configuration.valid_until_ms);
    let prepared = cmbl::passes::PreparedPass::new(&epoch, [8; 16], native.now * 1000).unwrap();
    let request = prepared.request();
    let signature = gather
        .issue_room_pass(
            &current,
            [9; 16],
            &request,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(
        signature,
        gather
            .issue_room_pass(
                &current,
                [9; 16],
                &request,
                &g1.verification(native.now),
                &clean
            )
            .await
            .unwrap()
    );
    let pass = prepared.finalize(&signature, native.now * 1000).unwrap();
    refresh(&mut g1, &native, 2);
    let refreshed = gather
        .room_epoch(&current, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    assert!(epoch == refreshed);
    let mut extension = configuration.clone();
    extension.valid_until_ms += 1;
    assert!(
        gather
            .activate_rooms(
                store.clone(),
                extension,
                &current,
                &g1.verification(native.now),
                &clean
            )
            .await
            .is_err()
    );
    gather
        .depart(
            Read {
                session: &session,
                current: &current,
            },
            &g1.verification(native.now),
        )
        .await
        .unwrap();
    assert!(
        store
            .get(&format!("swb_{}", member(7)))
            .await
            .unwrap()
            .is_none()
    );
    let connect = cmbl::Request {
        room: [8; 16],
        operation: [10; 16],
        action: cmbl::Action::Connect {
            connection: pass.connection(),
        },
    };
    let proof = pass
        .prove(&connect, "native-accounting", native.now * 1000)
        .unwrap();
    let result = gather
        .room(&connect, &proof, &g1.verification(native.now))
        .await
        .unwrap();
    assert_eq!(result.active_connections, 1);
    clock
        .0
        .store(configuration.valid_until_ms, Ordering::SeqCst);
    assert!(
        gather
            .room(
                &connect,
                &proof,
                &g1.verification(configuration.valid_until_ms / 1000)
            )
            .await
            .is_err()
    );
    // The host final cut must retain the time sampled inside the room owner,
    // even when a generic caller Clock does not keep its own observation floor.
    clock
        .0
        .store(configuration.valid_until_ms - 1, Ordering::SeqCst);
    assert!(gather.observed_now().is_err());
}

#[tokio::test]
async fn authenticated_room_allowance_change_permanently_fences_original_issuer() {
    allowance_change(3).await;
}

#[tokio::test]
async fn authenticated_unsupported_allowance_cannot_revive_original_issuer_after_restoration() {
    allowance_change(1025).await;
}

async fn allowance_change(changed_quota: u64) {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let (mut gather, store, _) = complete(&native, 64);
    let (session, _) = enter(&mut gather, &mut g1, &native).await;
    let current = authorize(
        &mut gather,
        &mut g1,
        &session,
        native.now,
        "room",
        1,
        b"room",
    )
    .await;
    gather
        .activate_rooms(
            store.clone(),
            configuration(&native),
            &current,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let anchor = store.get("room-pass-issuer").await.unwrap().unwrap();
    // A release with another room-pass constant restores over the original issuer.
    gather.set_room_quota(changed_quota);
    refresh(&mut g1, &native, 2);
    assert!(
        gather
            .room_epoch(&current, &g1.verification(native.now), &clean)
            .await
            .is_err()
    );
    gather.set_room_quota(crbk::FORUM_ROOM_PASSES_PER_EPOCH);
    refresh(&mut g1, &native, 3);
    assert!(
        gather
            .room_epoch(&current, &g1.verification(native.now), &clean)
            .await
            .is_err()
    );
    assert!(
        gather
            .activate_rooms(
                store.clone(),
                configuration(&native),
                &current,
                &g1.verification(native.now),
                &clean
            )
            .await
            .is_err()
    );
    let retained = store.get("room-pass-issuer").await.unwrap().unwrap();
    assert_eq!(retained.value, anchor.value);
    assert_eq!(retained.revision, anchor.revision);
}

#[tokio::test]
async fn signed_record_withdrawal_cannot_resurrect_original_anonymous_issuer() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let (mut gather, store, _) = complete(&native, 64);
    let (session, _) = enter(&mut gather, &mut g1, &native).await;
    let current = authorize(
        &mut gather,
        &mut g1,
        &session,
        native.now,
        "room",
        1,
        b"room",
    )
    .await;
    gather
        .activate_rooms(
            store.clone(),
            configuration(&native),
            &current,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let epoch = gather
        .room_epoch(&current, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let prepared = cmbl::passes::PreparedPass::new(&epoch, [8; 16], native.now * 1000).unwrap();
    let signature = gather
        .issue_room_pass(
            &current,
            [9; 16],
            &prepared.request(),
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let pass = prepared.finalize(&signature, native.now * 1000).unwrap();
    let command = cmbl::Request {
        room: [8; 16],
        operation: [10; 16],
        action: cmbl::Action::Connect {
            connection: pass.connection(),
        },
    };
    let proof = pass
        .prove(&command, "native-accounting", native.now * 1000)
        .unwrap();
    let anchor = store.get("room-pass-issuer").await.unwrap().unwrap();
    // A real signed owner withdrawal is observed on the anonymous path; no
    // member record is rechecked or invented to obtain this refusal.
    refresh_record(&mut g1, &native, 2, Some(None));
    assert!(
        gather
            .room(&command, &proof, &g1.verification(native.now))
            .await
            .is_err()
    );
    refresh_record(
        &mut g1,
        &native,
        3,
        Some(native.material.record_epoch.clone()),
    );
    assert!(
        gather
            .room(&command, &proof, &g1.verification(native.now))
            .await
            .is_err()
    );
    let retained = store.get("room-pass-issuer").await.unwrap().unwrap();
    assert_eq!(retained.value, anchor.value);
    assert_eq!(retained.revision, anchor.revision);
}
