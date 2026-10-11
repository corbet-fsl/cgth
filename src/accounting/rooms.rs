//! One common anonymous permit epoch under actual current accounting authority.
//! The issuer receives the admitted member and blinded bytes, never a room ID.
use super::*;
use crate::cmbl;
use cblc::record_verifier::VerifiedRecordEpoch;

/// Trusted service configuration. These bounds never come from a room request.
#[derive(Clone, PartialEq, Eq)]
pub struct RoomConfiguration {
    pub incarnation: String,
    pub epoch: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

pub(super) struct RoomAuthority {
    configuration: RoomConfiguration,
    record: record::Epoch,
    policy_digest: [u8; 32],
    quota: u16,
    invalidated: bool,
}

impl<S: Store, C: Clock, R: Tokens, Q: cthl::Store> AccountGather<S, C, R, Q> {
    fn room_view(
        &mut self,
        verification: &Verification<'_>,
    ) -> Result<(VerifiedRecordEpoch, u64), Error> {
        let now = self.clock.seconds()?;
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        let settings = crbk::ForumSettings::from_snapshot(
            verification
                .charter
                .settings(now)
                .map_err(|_| Error::AccountingUnavailable)?,
        )
        .map_err(|_| Error::AccountingUnavailable)?;
        let quota = settings.room_passes_per_epoch;
        let epoch = self
            .verifier
            .current_epoch(balance, bounds, now)
            .map_err(|_| Error::AccountingUnavailable)?;
        Ok((epoch, quota))
    }

    fn check_room(
        &mut self,
        verification: &Verification<'_>,
    ) -> Result<VerifiedRecordEpoch, Error> {
        let (current, quota) = self.room_view(verification)?;
        let frozen = self
            .room_authority
            .as_mut()
            .ok_or(Error::AccountingUnavailable)?;
        let now = self.clock.now()?;
        if frozen.invalidated
            || frozen.record != *current.epoch()
            || frozen.policy_digest != *current.policy_digest()
            || u64::from(frozen.quota) != quota
        {
            frozen.invalidated = true;
            return Err(Error::AccountingUnavailable);
        }
        if frozen.configuration.valid_from_ms < milliseconds(current.valid_from())?
            || frozen.configuration.valid_until_ms > milliseconds(current.valid_until())?
            || now < frozen.configuration.valid_from_ms
            || now >= frozen.configuration.valid_until_ms
        {
            return Err(Error::AccountingUnavailable);
        }
        Ok(current)
    }

    fn confirm_room(
        &mut self,
        original: &VerifiedRecordEpoch,
        verification: &Verification<'_>,
    ) -> Result<(), Error> {
        let now = self.clock.seconds()?;
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        self.verifier
            .check_epoch_current(original, balance, bounds, now)
            .map_err(|_| Error::AccountingUnavailable)?;
        self.check_room(verification)?;
        Ok(())
    }

    /// Activate once in the caller's original volatile service scope. The
    /// native record and G1 cover the whole configured permit end, even if the
    /// presence heartbeat expires sooner. Failed/uncertain creation never
    /// resets the original issuer anchor or generates a replacement authority.
    pub async fn activate_rooms(
        &mut self,
        store: S,
        configuration: RoomConfiguration,
        current: &Authorized,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(), Error> {
        self.confirm(current, verification, contact).await?;
        if let Some(frozen) = &self.room_authority {
            if frozen.configuration != configuration {
                return Err(Error::AccountingUnavailable);
            }
            self.check_room(verification)?;
            return Ok(());
        }
        let (record, quota) = self.room_view(verification)?;
        let quota = u16::try_from(quota)
            .ok()
            .filter(|value| *value > 0 && *value <= 1024)
            .ok_or(Error::AccountingUnavailable)?;
        cmmr::Scope::new(&self.configuration.community, &configuration.incarnation)
            .map_err(|_| Error::AccountingUnavailable)?;
        let now = self.clock.now()?;
        if configuration.incarnation.is_empty()
            || configuration.epoch == 0
            || configuration.valid_from_ms >= configuration.valid_until_ms
            || configuration.valid_from_ms < milliseconds(record.valid_from())?
            || configuration.valid_until_ms > milliseconds(record.valid_until())?
            || configuration.valid_until_ms > current.authority_until()
            || now < configuration.valid_from_ms
            || now >= configuration.valid_until_ms
        {
            return Err(Error::AccountingUnavailable);
        }
        let issuer = cmbl::passes::issuer::BudgetedIssuer::create(
            store,
            self.configuration.community.clone(),
            configuration.epoch,
            configuration.valid_from_ms,
            configuration.valid_until_ms,
            quota,
        )
        .await
        .map_err(Error::Rooms)?;
        self.gather.install_room_issuer(issuer)?;
        self.room_authority = Some(RoomAuthority {
            configuration,
            record: record.epoch().clone(),
            policy_digest: *record.policy_digest(),
            quota,
            invalidated: false,
        });
        self.confirm(current, verification, contact).await?;
        self.confirm_room(&record, verification)
    }

    /// Return the one common descriptor only after its original anchor CAS and
    /// the member's actual final row/currentness cut.
    pub async fn room_epoch(
        &mut self,
        current: &Authorized,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<cmbl::passes::Epoch, Error> {
        self.confirm(current, verification, contact).await?;
        let record = self.check_room(verification)?;
        let epoch = self.gather.room_epoch(self.clock.now()?).await?.clone();
        self.confirm(current, verification, contact).await?;
        self.confirm_room(&record, verification)?;
        Ok(epoch)
    }

    pub async fn issue_room_pass(
        &mut self,
        current: &Authorized,
        operation: cmbl::Id,
        request: &cmbl::passes::BlindRequest,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<u8>, Error> {
        self.confirm(current, verification, contact).await?;
        let record = self.check_room(verification)?;
        if current.authority_until()
            < self
                .room_authority
                .as_ref()
                .ok_or(Error::AccountingUnavailable)?
                .configuration
                .valid_until_ms
        {
            return Err(Error::AccountingUnavailable);
        }
        let signature = self
            .gather
            .issue_room_pass(&current.current, operation, request, self.clock.now()?)
            .await?;
        // A committed allowance never implies the signature can escape after
        // lost authority. The original exact retry receipt remains in the owner.
        self.confirm(current, verification, contact).await?;
        self.confirm_room(&record, verification)?;
        Ok(signature)
    }

    /// Anonymous use checks common epoch authority and the genuine original
    /// room proof only. No member lookup or identity is introduced here.
    pub async fn room(
        &mut self,
        request: &cmbl::Request,
        proof: &[u8],
        verification: &Verification<'_>,
    ) -> Result<cmbl::Outcome, Error> {
        let record = self.check_room(verification)?;
        let epoch = self.gather.room_epoch(self.clock.now()?).await?.clone();
        self.confirm_room(&record, verification)?;
        let incarnation = self
            .room_authority
            .as_ref()
            .ok_or(Error::AccountingUnavailable)?
            .configuration
            .incarnation
            .clone();
        let verifier = cmbl::passes::Verifier::new(epoch, incarnation).map_err(Error::Rooms)?;
        let outcome = self
            .gather
            .room(request, proof, &verifier, self.clock.now()?)
            .await?;
        self.confirm_room(&record, verification)?;
        Ok(outcome)
    }
}
