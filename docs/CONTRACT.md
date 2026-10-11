# Contract

Thin routing only: Switchboard owns presence, Lookup owns matching indexes, Assembly owns room ordering/relay. No duplicated policy, quota, room protocol or member registry.

Preflight calls the existing cthl::Throttle over its owner store. Presence methods forward sealed cswb Admission/Current/Session capabilities unchanged; Lookup projections are re-exported without an independent listing. Room and handover calls forward the exact cmbl Request/ProofVerifier/Outcome protocol, preserving owner refusals and storing no attendance link.

The candidate facade delegates real challenges, one-use device admission,
current request authorization, complete replacement, Lookup pages and ciphertext
to their original owners. No verifier or match state is copied here. Admission
forwards to Switchboard's single `admit_enter` operation: pending
challenge consumption and complete attendance/index publication share one
existing multi-record CAS. Gather never separates challenge consumption from
attendance insertion. Original lower-owner sealed-capability methods remain.
Existing quota/room refusal tests are retained. The concrete accounting owner
joins native record authority to the original common room issuer. The entire
configured permit window fits the authenticated record and policy lifetime;
member issuance authority covers that window's end. Descriptor, economic policy
or signed quota changes invalidate the issuer, including withdrawal followed by
restoration. Metadata refresh cannot extend its frozen window. Anonymous use
checks the current common authority and original permit, without a member
lookup, and continues after presence departure until exclusive permit expiry.
All member issuance paths retain final presence and native currentness checks.
Actual native and transport qualification remains required; source review is not
an execution result. Original MLS handover remains unavailable.

G1 credential/Guard checks belong to `cgrd::check_published`, referenced through
Charter and Assurance. Envoy (`cnvy`) fetches/follows feeds; it does not verify
authority. Current Profile device authority and per-request possession must be composed
with those owner checks. The05:45 binding MVP correction requires G2 frontier/ZK
currentness and public punishment; original owner capability integration remains
mandatory before this composition can claim complete admission. No second
verifier, accepting substitute or optional check is introduced here.

The native `issuer` feature holds one original `BudgetedIssuer` capability and
forwards its checked epoch and issuance ports. It cannot replace an installed
issuer, export its key, reset its allowance, or accept a caller member string.
`issue_room_pass` forwards the canonical member from sealed `cswb::Current`;
Forum must obtain that capability by verifying the exact fresh device request.
The original issuer still owns every budget/anchor CAS and blinded response.
