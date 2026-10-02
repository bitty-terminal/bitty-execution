# CarryCtx

<!-- carryctx:v1 -->

This directory contains versioned CarryCtx project configuration.
Runtime state is stored in the repository's Git common directory, not here.

## Snapshot publication and recovery

- Publish (commander merge closeout): `just workflow-publish` runs
  `carryctx export --publication` (redacted) and pushes
  `refs/heads/carryctx-snapshots`. CarryCtx never pushes by itself.
- The `snapshot-source` CI gate verifies the published `CarryCtx-Source`
  trailer matches or leads `main`.
- Recover a fresh clone: `just workflow-import` fetches
  `refs/heads/carryctx-snapshots` and imports it with
  `carryctx import --from-git`; run with `--dry-run` first to preview.
- Never push `refs/carryctx/local` or the local database, and never merge
  snapshots back.
