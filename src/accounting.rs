//! Complete Forum record composition. The concrete native Balance owner checks
//! all accounting authority; Switchboard still owns G1, device possession and
//! atomic attendance. No verifier implementation arrives from a request.
use crate::{Error, Gather};
pub use cblc::{artifacts, verification};
use cblc::{
    record_verifier::{CharterBounds, RecordVerifier, VerifiedCachedRecord},
    verification::{ExtensionLimits, NativeExtensionVerifier},
};
use cmmr::{Clock, Store};
use cswb::{Current, Session, Tokens, Verification};
pub use czkp::record;
use czkp::record::{Context, Presentation, Record, Use};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

mod entry;
mod reads;
#[cfg(feature = "issuer")]
mod rooms;
pub use entry::Replacement;
pub use reads::{CiphertextRequest, PageRequest, WatchRequest};
#[cfg(feature = "issuer")]
pub use rooms::RoomConfiguration;

/// Trusted application configuration, independent of incoming records. The
/// publisher must define this exact catalogue key with RecordEpochSettings.
pub struct Configuration {
    pub community: String,
    pub period_key: String,
    pub period_seconds: u64,
}

/// Original public statement and proof, never fresh challenge authority. This
/// syntax is retained only in the expiring presence row, without private state.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRecord {
    pub record: Record,
    pub proof: String,
}

/// One device-authenticated operation plus genuine native record evidence.
/// Neither a wire decoder nor an unchecked constructor is provided.
pub struct Authorized {
    current: Current,
    session: Session,
    record: VerifiedCachedRecord,
    row: cswb::VerifiedPresence,
}
impl Authorized {
    pub fn binding(&self) -> &cswb::Binding {
        self.current.binding()
    }
    pub fn authority_until(&self) -> u64 {
        self.current.authority_until()
    }
}

pub struct Read<'a> {
    pub session: &'a Session,
    pub current: &'a Authorized,
}
impl Read<'_> {
    fn validate(&self) -> Result<(), Error> {
        if self.session != &self.current.session {
            return Err(Error::Presence(cswb::Error::Stale));
        }
        Ok(())
    }
}

/// Holds the original child owners and one concrete native verifier. Applications
/// retain their serial Charter guard through each operation's final await/cut.
pub struct AccountGather<S, C, R, Q> {
    gather: Gather<S, C, R, Q>,
    verifier: RecordVerifier,
    configuration: Configuration,
    clock: ObservedClock<C>,
    #[cfg(feature = "issuer")]
    room_authority: Option<rooms::RoomAuthority>,
    /// Room passes per member and common epoch of this release (a code constant).
    room_quota: u64,
}

struct ObservedClock<C> {
    clock: C,
    floor: AtomicU64,
}
impl<C: Clock> ObservedClock<C> {
    fn now(&self) -> Result<u64, Error> {
        let now = self.clock.now().map_err(|_| Error::AccountingUnavailable)?;
        if now == 0 || now > cmmr::MAX_TIME || now < self.floor.fetch_max(now, Ordering::SeqCst) {
            return Err(Error::AccountingUnavailable);
        }
        Ok(now)
    }
    fn seconds(&self) -> Result<u64, Error> {
        Ok(self.now()? / 1000)
    }
}

fn milliseconds(seconds: u64) -> Result<u64, Error> {
    seconds
        .checked_mul(1000)
        .filter(|v| *v <= cmmr::MAX_TIME)
        .ok_or(Error::AccountingUnavailable)
}

fn owner(binding: &cswb::Binding) -> Result<[u8; 32], Error> {
    // Only an already authenticated original member binding reaches here.
    let pseudonym: [u8; 48] = data_encoding::HEXLOWER
        .decode(binding.member.as_bytes())
        .map_err(|_| Error::AccountingUnavailable)?
        .try_into()
        .map_err(|_| Error::AccountingUnavailable)?;
    czkp::decode(&cblc::admission::member_id(&pseudonym)).map_err(|_| Error::AccountingUnavailable)
}

fn material<'a>(
    configuration: &Configuration,
    charter: &'a cchr::VerifiedCharter,
    now: u64,
) -> Result<(&'a cbcn::balance::Balance, CharterBounds), Error> {
    if charter.community() != configuration.community {
        return Err(Error::AccountingUnavailable);
    }
    let snapshot = charter
        .settings(now)
        .map_err(|_| Error::AccountingUnavailable)?;
    let period = crbk::RecordEpochSettings::from_snapshot(snapshot, &configuration.period_key)
        .map_err(|_| Error::AccountingUnavailable)?;
    if period.period_seconds != configuration.period_seconds {
        return Err(Error::AccountingUnavailable);
    }
    Ok((
        charter.balance().ok_or(Error::AccountingUnavailable)?,
        CharterBounds {
            policy_epoch: charter.policy_epoch(),
            valid_until: charter.valid_until(),
        },
    ))
}

impl<S, C, R, Q> AccountGather<S, C, R, Q> {
    /// Model a release whose room-pass constant differs from the one the original issuer was
    /// activated under (the only way the quota can change). Test fixture API.
    #[doc(hidden)]
    pub fn set_room_quota(&mut self, quota: u64) {
        self.room_quota = quota;
    }
}

impl<S: Store, C: Clock, R: Tokens, Q: cthl::Store> AccountGather<S, C, R, Q> {
    pub fn new(
        gather: Gather<S, C, R, Q>,
        configuration: Configuration,
        native: NativeExtensionVerifier,
        limits: ExtensionLimits,
        clock: C,
    ) -> Result<Self, Error> {
        if configuration.period_key.is_empty() {
            return Err(Error::AccountingUnavailable);
        }
        let verifier = RecordVerifier::new(
            configuration.community.clone(),
            configuration.period_seconds,
            native,
            limits,
        )
        .map_err(|_| Error::AccountingUnavailable)?;
        Ok(Self {
            gather,
            verifier,
            configuration,
            #[cfg(feature = "issuer")]
            room_authority: None,
            room_quota: crbk::FORUM_ROOM_PASSES_PER_EPOCH,
            clock: ObservedClock {
                clock,
                floor: AtomicU64::new(0),
            },
        })
    }

    pub async fn preflight(&self, key: &[u8], action: &str) -> Result<(), Error> {
        self.gather.preflight(key, action).await
    }

    /// Final host clock cut through this owner's retained interior observation
    /// floor. This is time only, never an admission or accounting capability.
    pub fn observed_now(&self) -> Result<u64, Error> {
        self.clock.now()
    }

    fn check(
        &mut self,
        current: &Authorized,
        verification: &Verification<'_>,
    ) -> Result<(), Error> {
        let now = self.clock.seconds()?;
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        if self.clock.now()? >= current.authority_until() {
            return Err(Error::AccountingUnavailable);
        }
        self.verifier
            .check_cached_current(&current.record, balance, bounds, now)
            .map_err(|_| Error::AccountingUnavailable)?;
        if self.clock.now()?
            >= current
                .authority_until()
                .min(milliseconds(bounds.valid_until)?)
        {
            return Err(Error::AccountingUnavailable);
        }
        Ok(())
    }

    async fn confirm(
        &mut self,
        current: &Authorized,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(), Error> {
        self.check(current, verification)?;
        self.gather
            .presence
            .confirm(&[&current.row], verification, contact)
            .await
            .map_err(Error::Presence)?;
        self.check(current, verification)?;
        if self.clock.now()? >= current.row.deadline() {
            return Err(Error::Presence(cswb::Error::Expired));
        }
        Ok(())
    }

    pub async fn authorize(
        &mut self,
        request: cswb::RequestProof<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Authorized, Error> {
        self.clock.now()?;
        let session = request.session;
        let current = self
            .gather
            .authorize(request, verification, contact)
            .await?;
        let row = self
            .gather
            .presence
            .requester(session, &current, verification, contact)
            .await
            .map_err(Error::Presence)?;
        let now = self.clock.seconds()?;
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        let attachment = current.attachment().ok_or(Error::AccountingUnavailable)?;
        if row.attachment().is_none_or(|stored| {
            stored.bytes() != attachment.bytes()
                || stored.record_until() != attachment.record_until()
        }) {
            return Err(Error::Presence(cswb::Error::Stale));
        }
        let public: PublicRecord =
            serde_json::from_slice(attachment.bytes()).map_err(|_| Error::AccountingUnavailable)?;
        let record = self
            .verifier
            .verify_cached_record(
                balance,
                bounds,
                &owner(current.binding())?,
                &public.record,
                &public.proof,
                || self.clock.seconds().unwrap_or(0),
            )
            .map_err(|_| Error::AccountingUnavailable)?;
        let current = current
            .bounded_until(milliseconds(record.valid_until())?)
            .map_err(Error::Presence)?;
        let authorized = Authorized {
            current,
            session: session.clone(),
            record,
            row,
        };
        self.confirm(&authorized, verification, contact).await?;
        Ok(authorized)
    }
}
