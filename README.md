# cgth — Gather

Implementation in progress. Admission is unavailable until current trust, public-record and device-authority capabilities are integrated.

## Scope

Wire Switchboard, Lookup and Assembly with current Assurance and the existing Throttle capability. Domain state stays in the children.

## Dependencies and validation

Reuse the existing volatile storage port and Guard rather than duplicate their mechanisms. CI resolves one lock snapshot and gates stable checks plus exact line and branch coverage. Passing a storage transition test does not establish admission integration.
