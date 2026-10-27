use super::*;

pub struct Replacement<'a> {
    pub read: Read<'a>,
    pub expected: cmmr::Revision,
    pub publication: &'a cswb::Publication,
    pub record: &'a PublicRecord,
    /// The device's signed Wave-budget hint (`None` = unknown = visible).
    pub accepting_waves: Option<bool>,
}

impl<S: Store, C: Clock, R: Tokens, Q: cthl::Store> AccountGather<S, C, R, Q> {
    pub async fn challenge(
        &mut self,
        origin: &str,
        publication: &cswb::Publication,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<cswb::Challenge, Error> {
        let now = self.clock.seconds()?;
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        let verifier = &mut self.verifier;
        let clock = &self.clock;
        let challenge = self
            .gather
            .presence
            .challenge_bound(
                origin,
                publication,
                verification,
                contact,
                |_, deadline, challenge| {
                    let now = clock.seconds().map_err(|_| cswb::Error::TrustUnavailable)?;
                    let context = verifier
                        .bounded_context(
                            balance,
                            bounds,
                            Context {
                                purpose: Use::ForumListing,
                                challenge,
                                expires_at: deadline / 1000,
                            },
                            now,
                        )
                        .map_err(|_| cswb::Error::TrustUnavailable)?;
                    serde_json::to_vec(&context).map_err(|_| cswb::Error::Invalid)
                },
            )
            .await
            .map_err(Error::Presence)?;
        let now = self.clock.now()?;
        material(&self.configuration, verification.charter, now / 1000)?;
        let context: Context =
            serde_json::from_slice(&challenge.payload).map_err(|_| Error::AccountingUnavailable)?;
        if now
            >= challenge
                .expires_at_ms
                .min(milliseconds(context.expires_at)?)
        {
            return Err(Error::AccountingUnavailable);
        }
        Ok(challenge)
    }

    /// A real R2 presentation is checked against the original service-selected
    /// pending context. Only the consuming two-row Switchboard CAS admits it.
    pub async fn admit(
        &mut self,
        proof: cswb::EntryProof<'_>,
        presentation: &Presentation,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(Session, cswb::Live), Error> {
        self.clock.now()?;
        let prepared = self
            .gather
            .presence
            .prepare_entry(proof, verification, contact)
            .await
            .map_err(Error::Presence)?;
        let now = self.clock.seconds()?;
        let expected: Context =
            serde_json::from_slice(prepared.payload()).map_err(|_| Error::AccountingUnavailable)?;
        if expected.purpose != Use::ForumListing
            || milliseconds(expected.expires_at)? > prepared.deadline()
        {
            return Err(Error::AccountingUnavailable);
        }
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        let verified = self
            .verifier
            .verify(
                balance,
                bounds,
                &owner(prepared.binding())?,
                &expected,
                presentation,
                || self.clock.seconds().unwrap_or(0),
            )
            .map_err(|_| Error::AccountingUnavailable)?;
        // Retain the native owner's exact public statement with the same proof
        // bytes it checked. No per-request context or signature becomes state.
        let public = PublicRecord {
            record: verified.record().clone(),
            proof: presentation.proof.clone(),
        };
        let attachment = attachment(&public, verified.record_until())?;
        self.verifier
            .check_current(&verified, balance, bounds, self.clock.seconds()?)
            .map_err(|_| Error::AccountingUnavailable)?;
        let result = self
            .gather
            .presence
            .commit_entry(
                prepared,
                Some(attachment),
                milliseconds(verified.commit_until())?,
            )
            .await
            .map_err(Error::Presence)?;
        let now = self.clock.seconds()?;
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        self.verifier
            .check_current(&verified, balance, bounds, now)
            .map_err(|_| Error::AccountingUnavailable)?;
        if self.clock.now()?
            >= result
                .1
                .deadline
                .min(milliseconds(verified.commit_until())?)
        {
            return Err(Error::Presence(cswb::Error::Expired));
        }
        Ok(result)
    }

    /// Existing device/session authority signs the whole replacement request.
    /// The cached record check can replace that row, never create a new entry.
    pub async fn replace(
        &mut self,
        replacement: Replacement<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<cswb::Live, Error> {
        let Replacement {
            read,
            expected,
            publication,
            record,
            accepting_waves,
        } = replacement;
        read.validate()?;
        if expected != read.current.row.revision() {
            return Err(Error::Presence(cswb::Error::Stale));
        }
        self.confirm(read.current, verification, contact).await?;
        let candidate = self
            .gather
            .replacement(
                read.session,
                &read.current.current,
                publication,
                verification,
                contact,
            )
            .await?;
        self.check(read.current, verification)?;
        let now = self.clock.seconds()?;
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        let verified = self
            .verifier
            .verify_cached_record(
                balance,
                bounds,
                &owner(read.current.binding())?,
                &record.record,
                &record.proof,
                || self.clock.seconds().unwrap_or(0),
            )
            .map_err(|_| Error::AccountingUnavailable)?;
        let attached = PublicRecord {
            record: verified.record().clone(),
            proof: record.proof.clone(),
        };
        let candidate = candidate
            .with_attachment(attachment(&attached, verified.valid_until())?)
            .map_err(Error::Presence)?;
        self.verifier
            .check_cached_current(&verified, balance, bounds, self.clock.seconds()?)
            .map_err(|_| Error::AccountingUnavailable)?;
        let live = self
            .gather
            .replace_with(
                read.session,
                &read.current.current,
                expected,
                candidate,
                accepting_waves,
            )
            .await?;
        self.check(read.current, verification)?;
        let now = self.clock.seconds()?;
        let (balance, bounds) = material(&self.configuration, verification.charter, now)?;
        self.verifier
            .check_cached_current(&verified, balance, bounds, now)
            .map_err(|_| Error::AccountingUnavailable)?;
        if self.clock.now()? >= live.deadline.min(milliseconds(verified.valid_until())?) {
            return Err(Error::Presence(cswb::Error::Expired));
        }
        Ok(live)
    }
}

fn attachment(public: &PublicRecord, until: u64) -> Result<cswb::Attachment, Error> {
    cswb::Attachment::new(
        serde_json::to_vec(public).map_err(|_| Error::AccountingUnavailable)?,
        milliseconds(until)?,
    )
    .map_err(Error::Presence)
}
