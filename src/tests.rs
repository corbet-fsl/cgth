use super::*;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
struct Time;
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(100)
    }
}
struct Random;
impl Tokens for Random {
    fn next(&self) -> Result<[u8; 16], cswb::Error> {
        Ok([7; 16])
    }
}

#[tokio::test]
async fn real_quota_and_volatile_children_remain_the_owners() {
    let storage = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("community", "boot").unwrap(),
            cmmr::Limits {
                records: 4,
                value_bytes: 4096,
                batch: 2,
                indexes_per_record: 2,
                page: 4,
                ttl_ms: 1000,
            },
            Time,
        )
        .unwrap(),
    );
    let presence = Switchboard::new(
        storage.clone(),
        Time,
        Random,
        "community".into(),
        cswb::Limits {
            lease_ms: 100,
            publication_bytes: 100,
            ciphertext_bytes: 100,
        },
    )
    .unwrap();
    let throttle = cthl::Throttle::new(
        "community",
        [(
            "challenge",
            cthl::Limit::new(1, Duration::from_secs(60)).unwrap(),
        )],
        cthl::MemoryStore::new(NonZeroUsize::new(10).unwrap()),
    )
    .unwrap();
    let rooms = cmbl::Assembly::new(
        storage.clone(),
        "community".into(),
        "boot".into(),
        cmbl::Limits {
            connections: 4,
            relay_messages: 4,
            message_bytes: 100,
            lifetime_ms: 100,
            proof_bytes: 100,
            operation_receipts: 16,
        },
    )
    .unwrap();
    let gather = Gather::new(presence, throttle, rooms);
    assert_eq!(
        gather.preflight(b"opaque-client", "challenge").await,
        Ok(())
    );
    assert_eq!(
        gather.preflight(b"opaque-client", "challenge").await,
        Err(Error::QuotaExceeded)
    );
    assert_eq!(
        gather.preflight(b"opaque-client", "unknown").await,
        Err(Error::QuotaUnavailable)
    );
    assert_eq!(
        gather.preflight(b"another-client", "challenge").await,
        Ok(())
    );
    assert_eq!(gather.expire().await, Ok(0));
    storage.close();
    assert_eq!(
        gather.expire().await,
        Err(Error::Presence(cswb::Error::Storage(cmmr::Error::Closed)))
    );
    fn send<T: Send>(future: T) -> T {
        future
    }
    let mut request = cmbl::Request {
        room: [1; 16],
        operation: [2; 16],
        action: cmbl::Action::Connect {
            connection: [3; 16],
        },
    };
    assert_eq!(
        send(gather.room(&request, b"proof", &cmbl::UnavailableProofs, 100)).await,
        Err(Error::Rooms(cmbl::Error::ProofUnavailable))
    );
    request.operation = [0; 16];
    assert_eq!(
        send(gather.room(&request, b"proof", &cmbl::UnavailableProofs, 100)).await,
        Err(Error::Rooms(cmbl::Error::Invalid))
    );
    assert_eq!(
        gather.room_handover(b"proof"),
        Err(Error::Rooms(cmbl::Error::ProofUnavailable))
    );
}
