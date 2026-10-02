# TODO

- [x] CTX-0001 / Issue #4: metadata gates, independent review, first commit/publication, redacted snapshot, branch protection.
- [ ] CTX-0002 / Issue #3: W-132 accepted execution contract; W-130 governance first.
- [ ] CTX-0003 / Issue #2: standalone supervisor mechanism and tests; no code in bootstrap.
- [ ] CTX-0004 / Issue #1: independent security/platform verification and Core W-140 parity.

Local dependencies: 0001 -> 0002 -> 0003 -> 0004. Cross-repo acceptance is checked by the owner before start. Narrow repository-wide scopes and assign team/implementer/reviewer. Preserve Core PTY authority and cancellation/recovery semantics. Enable full Rust and platform CI with source; metadata checks do not prove product behavior.
