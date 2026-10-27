use super::*;

pub struct PageRequest<'a> {
    pub read: Read<'a>,
    pub cursor: Option<&'a clkp::Cursor>,
    pub limit: usize,
}
pub struct WatchRequest<'a> {
    pub read: Read<'a>,
    pub cursor: &'a clkp::Cursor,
}
pub struct CiphertextRequest<'a> {
    pub read: Read<'a>,
    pub member: &'a str,
    pub revision: u64,
}

struct Associated<'a, C> {
    verifier: &'a mut RecordVerifier,
    configuration: &'a Configuration,
    charter: &'a cchr::VerifiedCharter,
    clock: &'a ObservedClock<C>,
}
struct PresenceRecord {
    native: VerifiedCachedRecord,
    deadline: u64,
}
impl<C: Clock> clkp::AssociatedEvidence for Associated<'_, C> {
    type Evidence = PresenceRecord;
    fn verify(
        &mut self,
        row: &cswb::VerifiedPresence,
    ) -> Result<Option<Self::Evidence>, clkp::LookupError> {
        let now = self
            .clock
            .seconds()
            .map_err(|_| clkp::LookupError::Associated)?;
        let (balance, bounds) = material(self.configuration, self.charter, now)
            .map_err(|_| clkp::LookupError::Associated)?;
        let Some(attachment) = row.attachment() else {
            return Ok(None);
        };
        let Ok(public) = serde_json::from_slice::<PublicRecord>(attachment.bytes()) else {
            return Ok(None);
        };
        let Ok(owner) = owner(row.binding()) else {
            return Ok(None);
        };
        match self.verifier.verify_cached_record(
            balance,
            bounds,
            &owner,
            &public.record,
            &public.proof,
            || self.clock.seconds().unwrap_or(0),
        ) {
            Ok(verified) => Ok(Some(PresenceRecord {
                native: verified,
                deadline: row.deadline(),
            })),
            Err(
                cblc::Error::InvalidInput
                | cblc::Error::Admission
                | cblc::Error::Signature
                | cblc::Error::Expired
                | cblc::Error::PolicyMismatch,
            ) => Ok(None),
            Err(_) => Err(clkp::LookupError::Associated),
        }
    }
    fn current(&mut self, evidence: &Self::Evidence) -> Result<(), clkp::LookupError> {
        let now = self
            .clock
            .seconds()
            .map_err(|_| clkp::LookupError::Associated)?;
        let (balance, bounds) = material(self.configuration, self.charter, now)
            .map_err(|_| clkp::LookupError::Associated)?;
        self.verifier
            .check_cached_current(&evidence.native, balance, bounds, now)
            .map_err(|_| clkp::LookupError::Associated)?;
        if self
            .clock
            .now()
            .map_err(|_| clkp::LookupError::Associated)?
            >= self.valid_until(evidence)
        {
            return Err(clkp::LookupError::Associated);
        }
        Ok(())
    }
    fn valid_until(&self, evidence: &Self::Evidence) -> u64 {
        milliseconds(evidence.native.valid_until())
            .unwrap_or(0)
            .min(evidence.deadline)
    }
}

impl<S: Store, C: Clock, R: Tokens, Q: cthl::Store> AccountGather<S, C, R, Q> {
    pub async fn read(
        &mut self,
        read: Read<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<cswb::Live, Error> {
        read.validate()?;
        self.confirm(read.current, verification, contact).await?;
        // The output belongs to the exact sealed row at that cut. Do not reread
        // another revision using this operation's earlier record evidence.
        Ok(cswb::Live {
            revision: read.current.row.revision(),
            deadline: read.current.row.deadline(),
            publication: read.current.row.publication().clone(),
        })
    }
    pub async fn heartbeat(
        &mut self,
        read: Read<'_>,
        expected: cmmr::Revision,
        verification: &Verification<'_>,
    ) -> Result<cswb::Live, Error> {
        self.heartbeat_with(read, expected, verification, None)
            .await
    }
    /// Heartbeat with the device's signed Wave-budget hint (`None` = unknown).
    pub async fn heartbeat_with(
        &mut self,
        read: Read<'_>,
        expected: cmmr::Revision,
        verification: &Verification<'_>,
        accepting_waves: Option<bool>,
    ) -> Result<cswb::Live, Error> {
        read.validate()?;
        if expected != read.current.row.revision() {
            return Err(Error::Presence(cswb::Error::Stale));
        }
        self.check(read.current, verification)?;
        if self.clock.now()? >= read.current.row.deadline() {
            return Err(Error::Presence(cswb::Error::Expired));
        }
        let live = self
            .gather
            .heartbeat_with(
                read.session,
                &read.current.current,
                expected,
                accepting_waves,
            )
            .await?;
        self.check(read.current, verification)?;
        if self.clock.now()? >= live.deadline {
            return Err(Error::Presence(cswb::Error::Expired));
        }
        Ok(live)
    }
    pub async fn depart(
        &mut self,
        read: Read<'_>,
        verification: &Verification<'_>,
    ) -> Result<usize, Error> {
        read.validate()?;
        self.check(read.current, verification)?;
        let removed = self.gather.depart(read.session).await?;
        self.check(read.current, verification)?;
        Ok(removed)
    }
    pub async fn expire(&self) -> Result<usize, Error> {
        self.gather.expire().await
    }

    pub async fn page(
        &mut self,
        request: PageRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<clkp::Matches, Error> {
        request.read.validate()?;
        self.confirm(request.read.current, verification, contact)
            .await?;
        let mut associated = Associated {
            verifier: &mut self.verifier,
            configuration: &self.configuration,
            charter: verification.charter,
            clock: &self.clock,
        };
        let result = self
            .gather
            .lookup
            .page_with(
                &self.gather.presence,
                clkp::PageRequest {
                    session: request.read.session,
                    current: &request.read.current.current,
                    cursor: request.cursor,
                    limit: request.limit,
                },
                verification,
                contact,
                &mut associated,
            )
            .await
            .map_err(Error::Lookup)?;
        self.confirm(request.read.current, verification, contact)
            .await?;
        Ok(result)
    }
    pub async fn watch(
        &mut self,
        request: WatchRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<clkp::Delta, Error> {
        request.read.validate()?;
        self.confirm(request.read.current, verification, contact)
            .await?;
        let mut associated = Associated {
            verifier: &mut self.verifier,
            configuration: &self.configuration,
            charter: verification.charter,
            clock: &self.clock,
        };
        let result = self
            .gather
            .lookup
            .watch_with(
                &self.gather.presence,
                clkp::WatchRequest {
                    session: request.read.session,
                    current: &request.read.current.current,
                    cursor: request.cursor,
                },
                verification,
                contact,
                &mut associated,
            )
            .await
            .map_err(Error::Lookup)?;
        self.confirm(request.read.current, verification, contact)
            .await?;
        Ok(result)
    }
    pub async fn ciphertext(
        &mut self,
        request: CiphertextRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<u8>, Error> {
        request.read.validate()?;
        self.confirm(request.read.current, verification, contact)
            .await?;
        let mut associated = Associated {
            verifier: &mut self.verifier,
            configuration: &self.configuration,
            charter: verification.charter,
            clock: &self.clock,
        };
        let result = self
            .gather
            .lookup
            .ciphertext_with(
                &self.gather.presence,
                clkp::CiphertextRequest {
                    request: clkp::PageRequest {
                        session: request.read.session,
                        current: &request.read.current.current,
                        cursor: None,
                        limit: 1,
                    },
                    member: request.member,
                    revision: request.revision,
                },
                verification,
                contact,
                &mut associated,
            )
            .await
            .map_err(Error::Lookup)?;
        self.confirm(request.read.current, verification, contact)
            .await?;
        Ok(result)
    }
}
