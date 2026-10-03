# Metadata-only gates. These are not Rust/Lua product evidence.
prettier_version := "3.9.6"
markdownlint_version := "0.23.1"
actionlint_version := "1.7.12"

fmt-check:
    bunx --bun prettier@{{prettier_version}} --check . --ignore-unknown

markdownlint:
    bunx --bun markdownlint-cli2@{{markdownlint_version}}

metadata:
    test -s README.md && test -s AGENTS.md && test -s TODO.md && test -s repo.toml
    test -s .carryctx/config.toml
    python3 -c 'import tomllib; from pathlib import Path; [tomllib.loads(p.read_text()) for p in [Path("repo.toml"), Path(".carryctx/config.toml")]]'

hygiene:
    #!/usr/bin/env bash
    set -euo pipefail
    bad=0
    while IFS= read -r -d '' f; do
        case "$f" in
            *.sqlite|*.db|*.zst|*.tar|*.tar.gz|*.tgz|node_modules/*|target/*|dist/*|.worktrees/*)
                echo "unexpected artifact tracked: $f" >&2; bad=1 ;;
        esac
    done < <(git ls-files -z --cached --others --exclude-standard)
    test "$bad" -eq 0

paths:
    #!/usr/bin/env bash
    set -euo pipefail
    # Mirrors Core check-scratch-paths.sh scoping: tests, fixtures, and docs
    # examples are out of scope; unit-test regions (at/after the first
    # #[cfg(test)] line) are out of scope; production code is gated.
    pattern='(/hom''e/|/Use''rs/|/mn''t/[A-Za-z]|[A-Za-z]:[\\/]Use''rs[\\/])'
    found=0
    while IFS= read -r -d '' f; do
        case "$f" in
            tests/*|*/fixtures/*|docs/*|*.md) continue ;;
        esac
        if [[ "$f" == *.rs ]] && grep -q '#\[cfg(test)\]' "$f"; then
            # awk exits nonzero on a production-region hit (like grep); the
            # printed matches are the evidence, `||` records the failure.
            awk -v pat="$pattern" '
                /#\[cfg\(test\)\]/ { exit (found ? 1 : 0) }
                $0 ~ pat { print FILENAME ":" FNR ":" $0; found=1 }
                END { exit (found ? 1 : 0) }
            ' "$f" || found=1
        elif grep -nEI "$pattern" "$f"; then found=1; fi
    done < <(git ls-files -z --cached --others --exclude-standard)
    if [ "$found" -ne 0 ]; then
        echo 'hardcoded host path detected (portable-path gate)' >&2
        exit 1
    fi
    echo 'portable-path gate passed'

actionlint:
    @installed="$(actionlint --version | head -n 1)"; test "$installed" = "{{actionlint_version}}" || { echo "actionlint {{actionlint_version}} required; found $installed" >&2; exit 1; }
    actionlint -color -shellcheck=

check:
    just fmt-check
    just markdownlint
    just metadata
    just hygiene
    just paths

workflows:
    actionlint
    act -n

# Publish a redacted CarryCtx snapshot to refs/heads/carryctx-snapshots.
workflow-publish:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    carryctx export --pack-format dir -o "$tmp" --publication
    git push origin refs/heads/carryctx-snapshots

# Fetch and import the published CarryCtx snapshot (fresh-clone recovery).
workflow-import:
    git fetch origin refs/heads/carryctx-snapshots:refs/remotes/origin/carryctx-snapshots
    carryctx import --from-git refs/remotes/origin/carryctx-snapshots

# No source exists: fail rather than claim product verification.
product:
    @echo 'Blocked: approved source and product gates have not landed.' >&2
    @exit 1
