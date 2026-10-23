# Changelog

## Unreleased

- Bumped the executable component wire protocol and descriptor range to v2.
  The v2 `Error.request` high-bit job namespace is intentionally incompatible
  with v1, so v1-only handshakes are refused before work is accepted.
- Documented bounded monitor/drain joins and the remaining resource-lifetime
  risk when descendants retain inherited output pipes after the leader exits.
- Disabled persisted checkout credentials in the CodeQL and snapshot-source
  workflows named by the independent review.
