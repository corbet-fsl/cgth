# Contract

Thin routing only: Switchboard owns presence, Lookup owns matching indexes, Assembly owns room ordering/relay. No duplicated policy, quota, room protocol or member registry.

Preflight calls the existing cthl::Throttle over its owner store. Presence methods forward sealed cswb Admission/Current/Session capabilities unchanged; Lookup projections are re-exported without an independent listing. Room and handover calls forward the exact cmbl Request/ProofVerifier/Outcome protocol, preserving owner refusals and storing no attendance link.

Implementation and acceptance remain incomplete. No public constructor can yet supply current production admission capabilities, so the presence forwarding success paths remain untested and strict coverage fails. Tests exercise actual cthl quotas, cmmr cleanup and cmbl unavailable/invalid proof refusals; they never synthesize an accepting verifier. Current Assurance/public record/device attestation/publication integration and live matching remain external seams. No coverage exclusion or lower threshold is used for missing integration.

G1 credential/Guard checks belong to `cgrd::check_published`, referenced through
Charter and Assurance. Envoy (`cnvy`) fetches/follows feeds; it does not verify
authority. Concrete G2 public-record and G3 device capabilities must be composed
with those current owner checks before any admission succeeds. No second verifier
or optional check is introduced here.
