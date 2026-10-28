# Changelog

## Unreleased

- Recorded the issue #21 protocol decision: `execution` keeps its own v2
  codec and `protocol = [2, 2]`. Core 0.0.30 has a v2 client, but the shared
  install/inventory ABI gate still selects `bitty-network-wire` v1, so the
  component is not installable through `bitty extension install/add` until
  Core chooses the protocol per component family. Added `just protocol` plus
  a real v1-refusal/v2-handshake test so the descriptor cannot drift from
  the linked codec or silently claim Core's shared ABI.
- Fixed the load-sensitive claim-lock test: the dropped-lock assertion now
  waits (bounded at 5 s) for the documented OS release instead of assuming
  the release is immediately visible when the handle is dropped.
- Bumped the executable component wire protocol and descriptor range to v2.
  The v2 `Error.request` high-bit job namespace is intentionally incompatible
  with v1, so v1-only handshakes are refused before work is accepted.
- Documented bounded monitor/drain joins and the remaining resource-lifetime
  risk when descendants retain inherited output pipes after the leader exits.
- Disabled persisted checkout credentials in the CodeQL and snapshot-source
  workflows named by the independent review.
