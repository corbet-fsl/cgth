//! Thin composition of current volatile presence, candidate planning and quotas.
#![forbid(unsafe_code)]

use cmmr::{Clock, Revision, Store};
use cswb::{Admission, Current, Live, Session, Switchboard, Tokens};

pub use clkp::{IndexKey, Plan, Projection};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    QuotaUnavailable,
    QuotaExceeded,
    Presence(cswb::Error),
    Rooms(cmbl::Error),
}

/// Composition holds child handles only, never its own roster or matching state.
pub struct Gather<S, C, R, Q> {
    presence: Switchboard<S, C, R>,
    throttle: cthl::Throttle<Q>,
    rooms: cmbl::Assembly<S>,
}

impl<S: Store, C: Clock, R: Tokens, Q: cthl::Store> Gather<S, C, R, Q> {
    pub fn new(
        presence: Switchboard<S, C, R>,
        throttle: cthl::Throttle<Q>,
        rooms: cmbl::Assembly<S>,
    ) -> Self {
        Self {
            presence,
            throttle,
            rooms,
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
