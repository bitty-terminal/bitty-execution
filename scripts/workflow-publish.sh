#!/usr/bin/env bash
# workflow-publish.sh — publish a redacted CarryCtx snapshot inside this repo.
#
# In-repo publication (no mirror repository): `carryctx export --publication`
# redacts every table row and project.json, stamps manifest.redacted, and
# commits exactly one snapshot to the fixed public ref
# `refs/heads/carryctx-snapshots`. CarryCtx never touches the network, so this
# target pushes that local ref itself — but only when the ref actually
# advanced. Native carryctx commits one snapshot per export, so a re-run
# publishes again rather than no-opping; the guard skips only a ref that did
# not advance.
#
# Trigger: the commander's merge closeout runs `just workflow-publish` from the
# primary checkout (NOT a git hook: GitHub squash-merges never fire local
# hooks, and `carryctx hooks install` behavior is intentionally untouched).
# The companion CI gate (`snapshot-source`) verifies the pushed snapshot's
# `CarryCtx-Source` trailer matches main HEAD.
#
# What it does:
#   1. Refreshes `$REMOTE/main` (bounded by --git-timeout) for every checkout,
#      including branch `main`, then requires HEAD to be that commit or an
#      ancestor of it. A divergent or unpushed local `main` fails here, before
#      the export writes anything; a detached/behind checkout stays valid with
#      a warning. `--allow-non-main` is the explicit bypass.
#   2. `carryctx export --pack-format dir -o <tmp> --publication`, which
#      redacts the bundle and commits it to `refs/heads/carryctx-snapshots`.
#   3. Refuses to push unless the committed `manifest.json` parses as a JSON
#      object whose TOP-LEVEL `redacted` field is the boolean `true`. A nested
#      `redacted: true` does not satisfy the guard, and the check never
#      degrades to a text match. Failures report the field's JSON type, never
#      its contents.
#   4. Pins the validated commit (`$PUB_REF^{commit}`) and pushes that exact
#      object, so a concurrent ref move between validation and push cannot
#      publish an unvalidated commit. Pushes only when the local ref changed;
#      otherwise prints a no-op message.
#
# Dependencies: git, carryctx, timeout, python3. python3 is required for the
# manifest JSON check and is verified up front; the script fails when it is
# missing instead of skipping redaction verification.
#
# The local CarryCtx DB is never modified. `--dry-run` validates the source
# revision and the export and writes neither the ref nor the remote.
#
# Usage:
#   scripts/workflow-publish.sh [--dry-run] [--project DIR] [--remote NAME]
#                               [--git-timeout SECS] [--allow-non-main]
#                               [--allow-name-mismatch] [--help]
#   --dry-run          validate the source revision and the export; no ref
#                      write, no push.
#   --project DIR      repository to publish (default: this checkout root).
#   --remote NAME      git remote to fetch main from and push to
#                      (default: origin).
#   --git-timeout SECS timeout for every carryctx/git op (default: 120).
#   --allow-non-main   publish even when HEAD is neither $REMOTE/main nor an
#                      ancestor of it, or when $REMOTE/main cannot be
#                      refreshed; the trailer records a source the CI gate
#                      rejects.
#   --allow-name-mismatch
#                      publish even when the checkout directory basename does
#                      not match the repository name; the trailer records the
#                      wrong project token.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUB_REF="refs/heads/carryctx-snapshots"
PROJECT="$REPO_ROOT"
REMOTE="${WORKFLOW_REMOTE:-origin}"
GIT_TIMEOUT="${GIT_TIMEOUT:-120}"
DRY_RUN=0
ALLOW_NON_MAIN=0
ALLOW_NAME_MISMATCH=0

usage() {
	sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d'
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--dry-run)
		DRY_RUN=1
		shift
		;;
	--allow-non-main)
		ALLOW_NON_MAIN=1
		shift
		;;
	--allow-name-mismatch)
		ALLOW_NAME_MISMATCH=1
		shift
		;;
	--project)
		PROJECT="${2:?--project requires a directory}"
		shift 2
		;;
	--project=*)
		PROJECT="${1#--project=}"
		shift
		;;
	--remote)
		REMOTE="${2:?--remote requires a name}"
		shift 2
		;;
	--remote=*)
		REMOTE="${1#--remote=}"
		shift
		;;
	--git-timeout)
		GIT_TIMEOUT="${2:?--git-timeout requires seconds}"
		shift 2
		;;
	--git-timeout=*)
		GIT_TIMEOUT="${1#--git-timeout=}"
		shift
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		echo "workflow-publish: FAIL: unknown flag $1 (see --help)" >&2
		exit 2
		;;
	esac
done

fail() {
	echo "workflow-publish: FAIL: $1" >&2
	exit 1
}

log() {
	echo "workflow-publish: $1"
}

have() { command -v "$1" >/dev/null 2>&1; }

have git || fail "git not on PATH"
have carryctx || fail "carryctx not on PATH"
have timeout || fail "timeout not on PATH"
# The redaction guard below parses JSON. python3 is present on every closeout
# host and CI image; jq and bun are not guaranteed. Fail statically instead of
# falling back to a text match that a nested field could satisfy.
have python3 || fail "python3 not on PATH; it is required to parse $PUB_REF:manifest.json (jq/bun are not assumed)"

PROJECT="$(cd "$PROJECT" && pwd)" || fail "project directory $PROJECT not found"

# CarryCtx records the checkout directory basename as the project token in the
# `CarryCtx-Source` trailer, so a worktree or recovery clone with a different
# name publishes misleading provenance. Require the basename to match the
# repository name derived from the remote.
PROJECT_NAME="$(basename "$PROJECT")"
REPO_NAME="$(basename "$(timeout "$GIT_TIMEOUT" git -C "$PROJECT" remote get-url "$REMOTE" 2>/dev/null || true)" .git)"
if [[ -n "$REPO_NAME" && "$PROJECT_NAME" != "$REPO_NAME" ]]; then
	if [[ "$ALLOW_NAME_MISMATCH" == 1 ]]; then
		log "WARN: checkout basename '$PROJECT_NAME' != repository name '$REPO_NAME'; --allow-name-mismatch set"
	else
		fail "checkout basename '$PROJECT_NAME' != repository name '$REPO_NAME'; CarryCtx records the basename in the CarryCtx-Source trailer. Publish from a checkout named '$REPO_NAME' or pass --allow-name-mismatch."
	fi
fi

# The publication source must be main (or a commit reachable from it), otherwise
# the snapshot-source gate can never match it. Refresh the remote-tracking ref
# first for EVERY checkout, branch `main` included: a stale origin/main would
# let a divergent local main publish a revision that exists nowhere on the
# remote. The accepted rule is the gate's: HEAD must be origin/main or an
# ancestor of it. An ahead/divergent history is rejected before the export
# writes the ref. A detached checkout at or behind origin/main stays valid
# (behind is stale but matchable; the gate flags it until main is republished).
MAIN_REF="refs/remotes/$REMOTE/main"
MAIN_SHA=""
if timeout "$GIT_TIMEOUT" git -C "$PROJECT" fetch --no-tags --quiet "$REMOTE" \
	"+refs/heads/main:$MAIN_REF"; then
	MAIN_SHA="$(timeout "$GIT_TIMEOUT" git -C "$PROJECT" rev-parse -q --verify "$MAIN_REF" 2>/dev/null || true)"
fi
if [[ -z "$MAIN_SHA" && "$ALLOW_NON_MAIN" != 1 ]]; then
	fail "cannot determine $MAIN_REF from $REMOTE (network/auth, or $REMOTE has no main); refusing to publish without verifying the source revision (pass --allow-non-main to bypass with a warning)"
fi
if [[ -z "$MAIN_SHA" ]]; then
	log "WARN: cannot determine $REMOTE/main; --allow-non-main set, skipping source verification"
else
	HEAD_SHA="$(timeout "$GIT_TIMEOUT" git -C "$PROJECT" rev-parse -q --verify HEAD 2>/dev/null)" ||
		fail "cannot resolve HEAD in $PROJECT"
	BRANCH="$(timeout "$GIT_TIMEOUT" git -C "$PROJECT" branch --show-current 2>/dev/null || true)"
	if [[ "$HEAD_SHA" == "$MAIN_SHA" ]]; then
		log "checkout is at $REMOTE/main ($HEAD_SHA)"
	elif timeout "$GIT_TIMEOUT" git -C "$PROJECT" merge-base --is-ancestor "$HEAD_SHA" "$MAIN_SHA" 2>/dev/null; then
		log "WARN: checkout is at $HEAD_SHA (${BRANCH:-detached}), behind $REMOTE/main ($MAIN_SHA); the publication gate flags it until main is republished"
	elif [[ "$ALLOW_NON_MAIN" == 1 ]]; then
		log "WARN: checkout is at $HEAD_SHA on branch '${BRANCH:-detached}', not reachable from $REMOTE/main ($MAIN_SHA); --allow-non-main set, snapshot provenance will record that revision"
	elif [[ "${BRANCH:-}" == "main" ]]; then
		fail "local main at $HEAD_SHA is ahead of or diverged from $REMOTE/main ($MAIN_SHA); fetch and fast-forward/rebase before the closeout (or pass --allow-non-main). Such a publication records a revision the snapshot-source gate rejects."
	else
		fail "checkout is on branch '${BRANCH:-detached}' at $HEAD_SHA, which is neither $REMOTE/main ($MAIN_SHA) nor an ancestor of it; run the closeout from the primary checkout on main (or pass --allow-non-main). A feature-branch publication records a revision the snapshot-source gate rejects."
	fi
fi

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/workflow-publish.XXXXXX")"
cleanup() {
	rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

# Align the local publication ref with the remote tip before exporting, so the
# new snapshot fast-forwards the published branch even when this clone has never
# published or lags behind another clone. A divergent unpushed local ref is
# superseded by this export from the live database.
if [[ "$DRY_RUN" == 0 ]] &&
	timeout "$GIT_TIMEOUT" git -C "$PROJECT" fetch --no-tags "$REMOTE" \
		"+refs/heads/carryctx-snapshots:refs/remotes/$REMOTE/carryctx-snapshots" >/dev/null 2>&1; then
	REMOTE_TIP="$(timeout "$GIT_TIMEOUT" git -C "$PROJECT" rev-parse -q --verify "refs/remotes/$REMOTE/carryctx-snapshots" 2>/dev/null || true)"
	if [[ -n "$REMOTE_TIP" ]]; then
		timeout "$GIT_TIMEOUT" git -C "$PROJECT" update-ref "$PUB_REF" "$REMOTE_TIP" ||
			fail "cannot align $PUB_REF to $REMOTE/$PUB_REF"
	fi
fi

BEFORE="$(timeout "$GIT_TIMEOUT" git -C "$PROJECT" rev-parse -q --verify "$PUB_REF^{commit}" 2>/dev/null || true)"

EXPORT_ARGS=(export --pack-format dir -o "$TMP_ROOT/pack" --publication --project "$PROJECT")
if [[ "$DRY_RUN" == 1 ]]; then
	EXPORT_ARGS+=(--dry-run)
fi

log "exporting redacted publication (ref $PUB_REF)"
if ! timeout "$GIT_TIMEOUT" carryctx "${EXPORT_ARGS[@]}" >"$TMP_ROOT/export.json" 2>"$TMP_ROOT/export.err"; then
	cat "$TMP_ROOT/export.err" >&2 2>/dev/null || true
	fail "carryctx export --publication failed"
fi

if [[ "$DRY_RUN" == 1 ]]; then
	log "dry-run PASS: export validated; no ref written, nothing pushed"
	exit 0
fi

# Pin the commit under validation. Every later read and the push itself use
# this exact object, never the mutable ref name: a concurrent update of
# `$PUB_REF` between the manifest check and the push can no longer substitute an
# unvalidated commit.
AFTER="$(timeout "$GIT_TIMEOUT" git -C "$PROJECT" rev-parse "$PUB_REF^{commit}" 2>/dev/null)" ||
	fail "publication ref $PUB_REF was not created by carryctx export --publication"

MANIFEST_FILE="$TMP_ROOT/manifest.json"
if ! timeout "$GIT_TIMEOUT" git -C "$PROJECT" show "$AFTER:manifest.json" >"$MANIFEST_FILE" 2>/dev/null; then
	fail "cannot read manifest.json from publication commit $AFTER"
fi
# Parse, do not grep: the top-level `redacted` field must be the JSON boolean
# true. A nested `redacted: true`, a string "true", or a number must not
# authorize a push, and a malformed manifest fails closed.
MANIFEST_ERROR="$(
	python3 - "$MANIFEST_FILE" 2>&1 <<'PY'
import json
import sys


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        manifest = json.load(handle)
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
    sys.exit(f"manifest.json is not readable JSON: {exc}")

if not isinstance(manifest, dict):
    sys.exit("manifest.json top level is not a JSON object")

# Report only the JSON type of the rejected field: its contents may hold
# values the publication is supposed to redact, and diagnostics must not leak
# them.
if "redacted" not in manifest:
    sys.exit("manifest.json has no top-level 'redacted' field")
redacted = manifest["redacted"]
if redacted is not True:
    sys.exit(
        "manifest.json top-level 'redacted' must be the JSON boolean true "
        f"(found {json_type(redacted)})"
    )
PY
)" || fail "publication $PUB_REF is not stamped redacted: true at the top level; refusing to push ($MANIFEST_ERROR)"

if [[ -n "$BEFORE" && "$BEFORE" == "$AFTER" ]]; then
	log "publication already current at ${AFTER:0:12}; nothing to push"
	exit 0
fi

log "pushing $PUB_REF (${BEFORE:0:12} -> ${AFTER:0:12}) to $REMOTE"
if ! timeout "$GIT_TIMEOUT" git -C "$PROJECT" push "$REMOTE" "$AFTER:refs/heads/carryctx-snapshots"; then
	fail "git push failed (network/auth/permissions?); the local publication commit is preserved"
fi
log "published $PUB_REF at ${AFTER:0:12}"
