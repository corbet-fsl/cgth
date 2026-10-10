//! Thin composition of current volatile presence, candidate planning and quotas.
#![forbid(unsafe_code)]

use cmmr::{Clock, Revision, Store};
use cswb::{Admission, Current, Live, Session, Switchboard, Tokens};

pub use clkp::{IndexKey, Plan, Projection};
pub use {clkp, cmbl, cmmr, cswb, cthl};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    QuotaUnavailable,
    QuotaExceeded,
    Presence(cswb::Error),
    Lookup(clkp::LookupError),
    Rooms(cmbl::Error),
}

/// Composition holds child handles only, never its own roster or matching state.
pub struct Gather<S, C, R, Q> {
    presence: Switchboard<S, C, R>,
    throttle: cthl::Throttle<Q>,
    rooms: cmbl::Assembly<S>,
    lookup: clkp::Lookup<S, R>,
    #[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
    issuer: Option<cmbl::passes::issuer::BudgetedIssuer<S>>,
}

impl<S: Store, C: Clock, R: Tokens, Q: cthl::Store> Gather<S, C, R, Q> {
    pub fn new(
        presence: Switchboard<S, C, R>,
        throttle: cthl::Throttle<Q>,
        rooms: cmbl::Assembly<S>,
        lookup: clkp::Lookup<S, R>,
    ) -> Self {
        Self {
            presence,
            throttle,
            rooms,
            lookup,
            #[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
            issuer: None,
        }
    }

    /// Cheap configured quotas precede the caller's expensive verification.
    /// This does not authenticate or admit a member.
    pub async fn preflight(&self, key: &[u8], action: &str) -> Result<(), Error> {
        match self.throttle.check(key, action).await {
            Ok(cthl::Decision::Allowed) => Ok(()),
            Ok(cthl::Decision::Denied { .. }) => Err(Error::QuotaExceeded),
            Err(_) => Err(Error::QuotaUnavailable),
        }
    }

    pub async fn challenge(
        &self,
        origin: &str,
        publication: &cswb::Publication,
        verification: &cswb::Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<cswb::Challenge, Error> {
        self.presence
            .challenge(origin, publication, verification, contact)
            .await
            .map_err(Error::Presence)
    }

    pub async fn admit(
        &self,
        proof: cswb::EntryProof<'_>,
        verification: &cswb::Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(Session, Live), Error> {
        self.presence
            .admit_enter(proof, verification, contact)
            .await
            .map_err(Error::Presence)
    }

    pub async fn authorize(
        &self,
        request: cswb::RequestProof<'_>,
        verification: &cswb::Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Current, Error> {
        self.presence
            .authorize(request, verification, contact)
            .await
            .map_err(Error::Presence)
    }

    pub async fn replacement(
        &self,
        session: &Session,
        current: &Current,
        publication: &cswb::Publication,
        verification: &cswb::Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Admission, Error> {
        self.presence
            .replacement(session, current, publication, verification, contact)
            .await
            .map_err(Error::Presence)
    }

    pub async fn page(
        &self,
        request: clkp::PageRequest<'_>,
        verification: &cswb::Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<clkp::Matches, Error> {
        self.lookup
            .page(&self.presence, request, verification, contact)
            .await
            .map_err(Error::Lookup)
    }

    pub async fn watch(
        &self,
        request: clkp::WatchRequest<'_>,
        verification: &cswb::Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<clkp::Delta, Error> {
        self.lookup
            .watch(&self.presence, request, verification, contact)
            .await
            .map_err(Error::Lookup)
    }

    pub async fn ciphertext(
        &self,
        request: clkp::PageRequest<'_>,
        owner: (&str, u64),
        verification: &cswb::Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<u8>, Error> {
        self.lookup
            .ciphertext(&self.presence, request, owner, verification, contact)
            .await
            .map_err(Error::Lookup)
    }

    pub async fn enter(&self, admission: Admission) -> Result<(Session, Live), Error> {
        self.presence
            .enter(admission)
            .await
            .map_err(Error::Presence)
    }

    pub async fn read(&self, session: &Session, current: &Current) -> Result<Live, Error> {
        self.presence
            .read(session, current)
            .await
            .map_err(Error::Presence)
    }

    pub async fn replace(
        &self,
        session: &Session,
        current: &Current,
        expected: Revision,
        admission: Admission,
    ) -> Result<Live, Error> {
        self.presence
            .replace(session, current, expected, admission)
            .await
            .map_err(Error::Presence)
    }

    pub async fn heartbeat(
        &self,
        session: &Session,
        current: &Current,
        expected: Revision,
    ) -> Result<Live, Error> {
        self.presence
            .heartbeat(session, current, expected)
            .await
            .map_err(Error::Presence)
    }

    pub async fn depart(&self, session: &Session) -> Result<usize, Error> {
        self.presence.depart(session).await.map_err(Error::Presence)
    }

    pub async fn expire(&self) -> Result<usize, Error> {
        self.presence.expire().await.map_err(Error::Presence)
    }

    /// Install the one common owner capability. Replacing a live issuer needs
    /// a new service incarnation; this facade has no key export or reset port.
    #[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
    pub fn install_room_issuer(
        &mut self,
        issuer: cmbl::passes::issuer::BudgetedIssuer<S>,
    ) -> Result<(), Error> {
        if self.issuer.is_some() {
            return Err(Error::Rooms(cmbl::Error::Conflict));
        }
        self.issuer = Some(issuer);
        Ok(())
    }

    /// Preserve the issuer owner's live-anchor check before common descriptor
    /// publication or anonymous use. Never manufacture a replacement on loss.
    #[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
    pub async fn room_epoch(&self, now: u64) -> Result<&cmbl::passes::Epoch, Error> {
        let issuer = self
            .issuer
            .as_ref()
            .ok_or(Error::Rooms(cmbl::Error::ProofUnavailable))?;
        issuer.share(now).await.map_err(Error::Rooms)?;
        Ok(issuer.epoch())
    }

    /// Only the sealed current admission supplies the canonical member. The
    /// original issuer performs its atomic allowance and exact-retry check.
    #[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
    pub async fn issue_room_pass(
        &self,
        current: &Current,
        operation: cmbl::Id,
        request: &cmbl::passes::BlindRequest,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        if now >= current.authority_until() {
            return Err(Error::Presence(cswb::Error::Expired));
        }
        let issuer = self
            .issuer
            .as_ref()
            .ok_or(Error::Rooms(cmbl::Error::ProofUnavailable))?;
        if current.binding().community != issuer.epoch().community {
            return Err(Error::Rooms(cmbl::Error::Refused));
        }
        issuer
            .issue(&current.binding().member, operation, request, now)
            .await
            .map_err(Error::Rooms)
    }

    /// Assembly alone checks the anonymous permit, bounds and ordering.
    /// This does not link a room operation to a presence member or device.
    pub async fn room(
        &self,
        request: &cmbl::Request,
        proof: &[u8],
        verifier: &dyn cmbl::ProofVerifier,
        now: u64,
    ) -> Result<cmbl::Outcome, Error> {
        self.rooms
            .execute(request, proof, verifier, now)
            .await
            .map_err(Error::Rooms)
    }

    pub fn room_handover(&self, proof: &[u8]) -> Result<(), Error> {
        self.rooms.handover(proof).map_err(Error::Rooms)
    }
}

#[cfg(test)]
mod tests;
