//! Real signatures and proof bytes, with original pending/CAS state assertions.
use super::*;

fn pending_key(challenge: &cswb::Challenge) -> String {
    format!(
        "challenge_{}",
        data_encoding::HEXLOWER.encode(&challenge.token)
    )
}
fn proof<'a>(
    challenge: &'a cswb::Challenge,
    signature: &'a [u8],
    publication: &'a cswb::Publication,
) -> cswb::EntryProof<'a> {
    cswb::EntryProof {
        origin: ORIGIN,
        challenge,
        signature,
        publication,
    }
}

#[tokio::test]
async fn fresh_context_proof_and_device_mutations_leave_pending_retryable() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    let (mut gather, store, _) = complete(&native, 64);
    let publication = g1.publication.clone();
    let challenge = gather
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let context: czkp::record::Context = serde_json::from_slice(&challenge.payload).unwrap();
    assert_ne!(context.challenge, [0; 32]);
    let second = gather
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let other: czkp::record::Context = serde_json::from_slice(&second.payload).unwrap();
    assert_ne!(context.challenge, other.challenge);
    assert_ne!(challenge.token, second.token);
    let signature = entry_signature(&g1, &native, &challenge);
    let original = store.get(&pending_key(&challenge)).await.unwrap().unwrap();
    let mut wrong_context = context.clone();
    wrong_context.challenge[0] ^= 1;
    let wrong = native.presentation(wrong_context);
    assert!(matches!(
        gather
            .admit(
                proof(&challenge, &signature, &publication),
                &wrong,
                &g1.verification(native.now),
                &clean
            )
            .await,
        Err(Error::AccountingUnavailable)
    ));
    // The changed holder context has a genuine signature. It still cannot
    // replace the service-selected context bound in the device challenge.
    let presentation = native.presentation(context);
    let mut bad = presentation.clone();
    let changed = if bad.proof.starts_with("00") {
        "01"
    } else {
        "00"
    };
    bad.proof.replace_range(..2, changed);
    assert!(matches!(
        gather
            .admit(
                proof(&challenge, &signature, &publication),
                &bad,
                &g1.verification(native.now),
                &clean
            )
            .await,
        Err(Error::AccountingUnavailable)
    ));
    let mut bad_device = signature.clone();
    bad_device[0] ^= 1;
    assert!(matches!(
        gather
            .admit(
                proof(&challenge, &bad_device, &publication),
                &presentation,
                &g1.verification(native.now),
                &clean
            )
            .await,
        Err(Error::Presence(cswb::Error::DeviceUnavailable))
    ));
    assert!(store.get(&pending_key(&challenge)).await.unwrap().unwrap() == original);
    assert!(
        store
            .get(&cswb::attendance_key(
                &member(7),
                &g1.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_none()
    );
    let (_, live) = gather
        .admit(
            proof(&challenge, &signature, &publication),
            &presentation,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(live.publication.signed, publication.signed);
    assert_eq!(
        store
            .get(&pending_key(&challenge))
            .await
            .unwrap()
            .unwrap()
            .value,
        [0]
    );
    assert!(
        gather
            .admit(
                proof(&challenge, &signature, &publication),
                &presentation,
                &g1.verification(native.now),
                &clean
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn authenticated_other_member_cannot_reuse_original_record_owner() {
    let native = Fixture::load();
    let mut other = G1::new(&native, &member(8), 1, 10_000).await;
    let (mut gather, store, _) = complete(&native, 64);
    let publication = other.publication.clone();
    let challenge = gather
        .challenge(
            ORIGIN,
            &publication,
            &other.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let context = serde_json::from_slice(&challenge.payload).unwrap();
    let presentation = native.presentation(context);
    let signature = entry_signature(&other, &native, &challenge);
    assert!(matches!(
        gather
            .admit(
                proof(&challenge, &signature, &publication),
                &presentation,
                &other.verification(native.now),
                &clean
            )
            .await,
        Err(Error::AccountingUnavailable)
    ));
    assert!(
        store
            .get(&cswb::attendance_key(
                &member(8),
                &other.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_none()
    );
    assert_ne!(
        store
            .get(&pending_key(&challenge))
            .await
            .unwrap()
            .unwrap()
            .value,
        [0]
    );
}

#[tokio::test]
async fn long_pending_challenge_caps_actual_presentation_and_preserves_marker_lifetime() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 200_000).await;
    let (mut gather, store, clock) = complete(&native, 64);
    // A service clock carries a millisecond remainder, never a whole second. The
    // pending challenge keeps its exact millisecond deadline while the actual
    // presentation is capped to whole seconds; a clock starting on a second
    // boundary would make both deadlines equal (they are both second-aligned
    // from then on) and hide the strict cap asserted below.
    clock.0.store(native.now * 1000 + 250, Ordering::SeqCst);
    let publication = g1.publication.clone();
    let challenge = gather
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let context: czkp::record::Context = serde_json::from_slice(&challenge.payload).unwrap();
    assert_eq!(
        context.expires_at,
        (challenge.expires_at_ms / 1000)
            .min(native.record.epoch.expires_at)
            .min(native.now + native.material.policy.max_authorization_seconds)
            .min(native.material.policy.account.policy_valid_until)
    );
    assert!(context.expires_at * 1000 < challenge.expires_at_ms);
    let original = store.get(&pending_key(&challenge)).await.unwrap().unwrap();
    let presentation = native.presentation(context.clone());
    let signature = entry_signature(&g1, &native, &challenge);
    let (_, live) = gather
        .admit(
            proof(&challenge, &signature, &publication),
            &presentation,
            &g1.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(live.deadline, context.expires_at * 1000);
    let consumed = store.get(&pending_key(&challenge)).await.unwrap().unwrap();
    assert_eq!(consumed.value, [0]);
    assert_eq!(consumed.deadline, original.deadline);
    assert!(live.deadline < consumed.deadline.unix_ms());
}

#[tokio::test]
async fn real_capacity_failure_rolls_back_both_pending_and_attendance_rows() {
    let native = Fixture::load();
    let mut g1 = G1::new(&native, &member(7), 1, 10_000).await;
    // One real storage slot can hold the pending row but cannot atomically
    // retain its consumed marker and insert a second attendance row.
    let (mut gather, store, _) = complete(&native, 1);
    let publication = g1.publication.clone();
    let challenge = gather
        .challenge(ORIGIN, &publication, &g1.verification(native.now), &clean)
        .await
        .unwrap();
    let context = serde_json::from_slice(&challenge.payload).unwrap();
    let presentation = native.presentation(context);
    let signature = entry_signature(&g1, &native, &challenge);
    let original = store.get(&pending_key(&challenge)).await.unwrap().unwrap();
    assert!(matches!(
        gather
            .admit(
                proof(&challenge, &signature, &publication),
                &presentation,
                &g1.verification(native.now),
                &clean
            )
            .await,
        Err(Error::Presence(cswb::Error::Storage(cmmr::Error::Capacity)))
    ));
    assert!(store.get(&pending_key(&challenge)).await.unwrap().unwrap() == original);
    assert!(
        store
            .get(&cswb::attendance_key(
                &member(7),
                &g1.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_none()
    );
}
