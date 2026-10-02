# cgth — Gather

Implementation in progress. Admission is unavailable until current trust, public-record and device-authority capabilities are integrated.

## Scope

### Purpose

cgth is the live layer of the forum: it wires presence (cswb Switchboard), finding people (clkp Lookup), and public rooms (cmbl Assembly) under quotas.

### Owns

- Routes attendance, search, ciphertext reads, and opaque room operations to their owners with scoped volatile storage handles.
- Applies policy quotas through cthl Throttle and verified community material from cchr Charter, including cutting off a community with excessive load while other communities stay usable.

### Never

- No second presence registry, matching evaluator, quota algorithm, or room protocol.
- Holds no group or room domain state; domain state stays in the child libraries.
- Holds no meaningful logic itself beyond wiring the three libraries.

### States

Derived only:

| State | Meaning |
|---|---|
| Ready | Live operations are served. |
| TrustUnavailable | Verified community material is unavailable, so live operations are refused. |
| QuotaCutoff | A community is cut off by quota. |
| Stopped | The facade is stopped. |

### Test obligations

- Failed admission never yields a search index event; departure invalidates all derived reads.
- Per-community quota exhaustion leaves another community usable.
- Trust refresh and cancellation cannot publish an unchecked entry.

## Dependencies and validation

Reuse the existing volatile storage port and Guard rather than duplicate their mechanisms. CI resolves one lock snapshot and gates stable checks plus exact line and branch coverage. Passing a storage transition test does not establish admission integration.
