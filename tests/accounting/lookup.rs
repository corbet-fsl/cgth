//! Lower G1 presence may retain opaque data; complete reads require real G2.
use super::*;

#[tokio::test]
async fn genuinely_signed_wrong_record_owner_is_omitted_before_cursor_seen() {
    let native = Fixture::load();
    let mut requester = G1::new(&native, &member(7), 1, 10_000).await;
    let mut candidate = G1::new(&native, &member(8), 1, 10_000).await;
    let (mut gather, store, clock) = complete(&native, 64);
    let (session, _) = enter(&mut gather, &mut requester, &native).await;
    let lower = board(store.clone(), clock, &native);
    let publication = candidate.publication.clone();
    let challenge = lower
        .challenge(
            ORIGIN,
            &publication,
            &candidate.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    let signature = entry_signature(&candidate, &native, &challenge);
    let prepared = lower
        .prepare_entry(
            cswb::EntryProof {
                origin: ORIGIN,
                challenge: &challenge,
                signature: &signature,
                publication: &publication,
            },
            &candidate.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    // This original lower port validates opaque syntax only. The retained proof
    // is genuine, but it belongs to the requester, not this authenticated member.
    let public = PublicRecord {
        record: native.record.clone(),
        proof: native.proof.clone(),
    };
    let attachment = cswb::Attachment::new(
        serde_json::to_vec(&public).unwrap(),
        native.record.epoch.expires_at * 1000,
    )
    .unwrap();
    let (candidate_session, _) = lower
        .commit_entry(prepared, Some(attachment), challenge.expires_at_ms)
        .await
        .unwrap();
    let current = authorize(
        &mut gather,
        &mut requester,
        &session,
        native.now,
        "page",
        1,
        b"page-body",
    )
    .await;
    let matches = gather
        .page(
            cgth::accounting::PageRequest {
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
    assert!(matches.entries.is_empty());
    let saved = store
        .get(&format!(
            "lkp_{}",
            data_encoding::HEXLOWER.encode(&matches.watch.0)
        ))
        .await
        .unwrap()
        .unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&saved.value).unwrap();
    assert!(saved["watch"]["seen"].as_array().unwrap().is_empty());
    // Removing omitted G2 evidence must never introduce its identity as a
    // departure: it was not disclosed or saved in the original checked window.
    lower.depart(&candidate_session).await.unwrap();
    let current = authorize(
        &mut gather,
        &mut requester,
        &session,
        native.now,
        "watch",
        2,
        b"watch-body",
    )
    .await;
    let delta = gather
        .watch(
            cgth::accounting::WatchRequest {
                read: Read {
                    session: &session,
                    current: &current,
                },
                cursor: &matches.watch,
            },
            &requester.verification(native.now),
            &clean,
        )
        .await
        .unwrap();
    assert!(delta.upserts.is_empty());
    assert!(delta.removed.is_empty());
}
