#!/usr/bin/env bash
# package-component.sh — build (optionally) and pack one `execution` component
# target in the DIR-030 layout.
#
# The archive contains exactly two root members: `bitty-component.toml` with
# the target executable's real SHA-256, and the executable `bitty-execution`
# (`bitty-execution.exe` on Windows). Beside it the script writes
# `<target>.tar.gz.sha256` and the aggregate `SHA256SUMS`; nothing is
# uploaded, tagged, or published.
#
# This script is the Linux x86_64 build/test path and also accepts any other
# Rust target triple for the #2491 per-platform matrix. A target whose binary
# was not built on the matching platform stays unverified and must not be
# added to a catalog.
#
# Usage:
#   scripts/package-component.sh --target TRIPLE --output PATH [--version X.Y.Z]
#   scripts/package-component.sh --target TRIPLE --output PATH --binary PATH
#
# Needs: cargo unless --binary is given, plus tar, gzip, and sha256sum or
# shasum.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly REPO_ROOT
readonly DESCRIPTOR_FILE="bitty-component.toml"
readonly COMPONENT_NAME="execution"
readonly EXECUTABLE="bitty-execution"
readonly ZERO_DIGEST="0000000000000000000000000000000000000000000000000000000000000000"
readonly MAX_DESCRIPTOR_BYTES=4096
readonly MAX_BINARY_BYTES=268435456
readonly CDN_LAYOUT="extensions/execution"

VERSION=""
TARGET=""
BINARY=""
OUTPUT=""

die() {
	printf 'package-component: ERROR: %s\n' "$1" >&2
	exit 1
}

usage() {
	cat <<'EOF'
Usage: scripts/package-component.sh --target TRIPLE --output PATH [--version X.Y.Z] [--binary PATH]

  --target TRIPLE  Rust target triple; output basename must be TRIPLE.tar.gz
  --output PATH    output archive path
  --version X.Y.Z  version (defaults to bitty-component.toml; must match)
  --binary PATH    already-built executable (skips cargo build)

Environment:
  CARGO_TARGET_DIR  respected when building (default: <repo>/target)
  GITHUB_REF_TYPE/GITHUB_REF_NAME  on a tag, the tag must be v<version>

The archive layout is stable: bitty-component.toml first, then the
executable. Upload key layout (when a release task authorizes publication):
<cdn>/extensions/execution/<version>/<target>.tar.gz and SHA256SUMS.
EOF
}

valid_version() {
	local raw="$1"
	[[ "${#raw}" -le 64 ]] || return 1
	[[ "$raw" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
	local part
	for part in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"; do
		[[ "${#part}" -gt 10 ]] && return 1
		[[ "${#part}" -eq 10 && "$part" -gt 4294967295 ]] && return 1
	done
	return 0
}

valid_target() {
	[[ "$1" =~ ^[a-z0-9_]+(-[a-z0-9_]+)+$ ]]
}

descriptor_value() {
	awk -F'"' -v key="$1" '
		$1 ~ "^[[:space:]]*" key "[[:space:]]*=" { print $2; exit }
	' "$REPO_ROOT/$DESCRIPTOR_FILE"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--target)
		TARGET="${2:-}"
		shift 2
		;;
	--output)
		OUTPUT="${2:-}"
		shift 2
		;;
	--version)
		VERSION="${2:-}"
		shift 2
		;;
	--binary)
		BINARY="${2:-}"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		die "unknown argument: $1"
		;;
	esac
done

[[ -f "$REPO_ROOT/$DESCRIPTOR_FILE" && ! -L "$REPO_ROOT/$DESCRIPTOR_FILE" ]] || die "root descriptor is missing"
descriptor_size="$(wc -c <"$REPO_ROOT/$DESCRIPTOR_FILE" | tr -d ' ')"
[[ "$descriptor_size" -le "$MAX_DESCRIPTOR_BYTES" ]] || die "root descriptor exceeds $MAX_DESCRIPTOR_BYTES bytes"

cargo_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO_ROOT/Cargo.toml" | head -n 1)"
valid_version "$cargo_version" || die "Cargo.toml version must be strict X.Y.Z: $cargo_version"
descriptor_version="$(descriptor_value version)"
valid_version "$descriptor_version" || die "descriptor version must be strict X.Y.Z: $descriptor_version"
[[ -z "$VERSION" ]] || valid_version "$VERSION" || die "version must be strict X.Y.Z: $VERSION"
[[ -z "$VERSION" ]] || [[ "$VERSION" == "$cargo_version" ]] || die "version $VERSION differs from Cargo.toml $cargo_version"
[[ -z "$VERSION" ]] || [[ "$VERSION" == "$descriptor_version" ]] || die "version $VERSION differs from descriptor $descriptor_version"
if [[ "${GITHUB_REF_TYPE:-}" == "tag" && -n "${GITHUB_REF_NAME:-}" ]]; then
	[[ "$GITHUB_REF_NAME" == "v$cargo_version" ]] || die "tag $GITHUB_REF_NAME does not match version $cargo_version"
fi

grep -Fx '[component]' "$REPO_ROOT/$DESCRIPTOR_FILE" >/dev/null || die "root descriptor must contain [component]"
grep -Fx "name = \"$COMPONENT_NAME\"" "$REPO_ROOT/$DESCRIPTOR_FILE" >/dev/null || die "root descriptor name must be $COMPONENT_NAME"
grep -Fx 'protocol = [2, 2]' "$REPO_ROOT/$DESCRIPTOR_FILE" >/dev/null || die "root descriptor protocol must be [2, 2]"
grep -Fx "executable = \"$EXECUTABLE\"" "$REPO_ROOT/$DESCRIPTOR_FILE" >/dev/null || die "root descriptor executable must be $EXECUTABLE"
grep -Fx "version = \"$cargo_version\"" "$REPO_ROOT/$DESCRIPTOR_FILE" >/dev/null || die "root descriptor version must be $cargo_version"
grep -Fx "sha256 = \"$ZERO_DIGEST\"" "$REPO_ROOT/$DESCRIPTOR_FILE" >/dev/null || die "root descriptor must use the zero digest sentinel"

valid_target "$TARGET" || die "target must look like a Rust target triple: $TARGET"
[[ -n "$OUTPUT" ]] || die "--output is required"
[[ "$(basename -- "$OUTPUT")" == "$TARGET.tar.gz" ]] || die "output basename must be $TARGET.tar.gz"
if [[ "$OUTPUT" != /* ]]; then
	OUTPUT="$PWD/${OUTPUT#./}"
fi
output_dir="$(dirname -- "$OUTPUT")"
mkdir -p -- "$output_dir"

archive_executable="$EXECUTABLE"
if [[ "$TARGET" == *-windows-* ]]; then
	archive_executable="$EXECUTABLE.exe"
fi

if [[ -z "$BINARY" ]]; then
	command -v cargo >/dev/null 2>&1 || die "cargo is required to build the component"
	target_root="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
	BINARY="$target_root/$TARGET/release/$archive_executable"
	printf 'package-component: building %s %s for %s\n' "$EXECUTABLE" "$cargo_version" "$TARGET" >&2
	(cd -- "$REPO_ROOT" && cargo build --release --locked --target "$TARGET" --bin "$EXECUTABLE")
fi
[[ -f "$BINARY" && ! -L "$BINARY" ]] || die "binary is missing or is a symlink: $BINARY"
binary_size="$(wc -c <"$BINARY" | tr -d ' ')"
[[ "$binary_size" -gt 0 ]] || die "binary is empty"
[[ "$binary_size" -le "$MAX_BINARY_BYTES" ]] || die "binary exceeds $MAX_BINARY_BYTES bytes"

if command -v sha256sum >/dev/null 2>&1; then
	SHA256SUM=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
	SHA256SUM=(shasum -a 256)
else
	die "sha256sum or shasum is required"
fi
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v gzip >/dev/null 2>&1 || die "gzip is required"

binary_digest="$("${SHA256SUM[@]}" "$BINARY" | awk '{print $1}')"
[[ "$binary_digest" =~ ^[0-9a-f]{64}$ ]] || die "digest tool returned an invalid SHA-256"

# Validate existing target archives so a mixed-version directory can never
# publish two incompatible descriptors under one SHA256SUMS.
shopt -s nullglob
existing_archives=("$output_dir"/*.tar.gz)
shopt -u nullglob
for candidate in "${existing_archives[@]}"; do
	[[ -f "$candidate" && ! -L "$candidate" ]] || die "archive is not a regular file: $candidate"
	candidate_name="$(basename -- "$candidate")"
	valid_target "${candidate_name%.tar.gz}" || die "archive basename is not a target triple: $candidate_name"
	[[ "$candidate" == "$OUTPUT" ]] && continue
	candidate_descriptor="$(tar -xOzf "$candidate" "$DESCRIPTOR_FILE" 2>/dev/null)" || die "archive has no readable $DESCRIPTOR_FILE: $candidate"
	candidate_version="$(awk -F'"' '$1 ~ /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }' <<<"$candidate_descriptor")"
	[[ "$candidate_version" == "$cargo_version" ]] || die "archive $candidate_name has version $candidate_version, expected $cargo_version"
done

scratch_root="${TMPDIR:-/tmp/bitty}"
mkdir -p -- "$scratch_root"
stage_dir="$(mktemp -d "$scratch_root/execution-component.XXXXXX")"
cleanup() { rm -rf -- "$stage_dir"; }
trap cleanup EXIT

# Render the per-target descriptor: only the sha256 line may differ from the
# canonical record, so descriptor drift fails here instead of shipping.
awk -v digest="$binary_digest" '
  /^[[:space:]]*sha256[[:space:]]*=/ { print "sha256 = \"" digest "\""; next }
  { print }
' "$REPO_ROOT/$DESCRIPTOR_FILE" >"$stage_dir/$DESCRIPTOR_FILE"
if ! diff <(grep -v '^sha256 = ' "$REPO_ROOT/$DESCRIPTOR_FILE") <(grep -v '^sha256 = ' "$stage_dir/$DESCRIPTOR_FILE") >/dev/null; then
	die "rendered descriptor drifted from $DESCRIPTOR_FILE (non-sha256 lines)"
fi
grep -Fx "sha256 = \"$binary_digest\"" "$stage_dir/$DESCRIPTOR_FILE" >/dev/null || die "rendered digest is missing"

cp -- "$BINARY" "$stage_dir/$archive_executable"
chmod 755 "$stage_dir/$archive_executable"

rm -f -- "$OUTPUT"
tar -czf "$OUTPUT" -C "$stage_dir" "$DESCRIPTOR_FILE" "$archive_executable"
expected_members="$(printf '%s\n%s\n' "$DESCRIPTOR_FILE" "$archive_executable" | LC_ALL=C sort)"
actual_members="$(tar -tzf "$OUTPUT" | LC_ALL=C sort)"
[[ "$actual_members" == "$expected_members" ]] || die "archive members are not exactly descriptor plus executable"

# Read the packed descriptor back; the digest must describe the packed bytes.
packed_descriptor="$(tar -xOzf "$OUTPUT" "$DESCRIPTOR_FILE")"
packed_digest="$(awk -F'"' '$1 ~ /^[[:space:]]*sha256[[:space:]]*=/ { print $2; exit }' <<<"$packed_descriptor")"
[[ "$packed_digest" == "$binary_digest" ]] || die "packed descriptor digest does not match the executable"

# Recompute every archive's sidecar and the aggregate manifest.
shopt -s nullglob
tarballs=()
for candidate in "$output_dir"/*.tar.gz; do
	candidate_name="$(basename -- "$candidate")"
	candidate_target="${candidate_name%.tar.gz}"
	if valid_target "$candidate_target"; then
		tarballs+=("$candidate_name")
	fi
done
shopt -u nullglob
[[ "${#tarballs[@]}" -gt 0 ]] || die "no target archives found in $output_dir"
printf '%s\n' "${tarballs[@]}" | LC_ALL=C sort >"$output_dir/.component-targets"
sorted_archives=()
while IFS= read -r archive_name; do
	sorted_archives+=("$archive_name")
done <"$output_dir/.component-targets"
for archive_name in "${sorted_archives[@]}"; do
	(cd -- "$output_dir" && "${SHA256SUM[@]}" "$archive_name" >"$archive_name.sha256")
done
(cd -- "$output_dir" && "${SHA256SUM[@]}" "${sorted_archives[@]}" | LC_ALL=C sort -k2 >SHA256SUMS)
rm -f -- "$output_dir/.component-targets"
(cd -- "$output_dir" && "${SHA256SUM[@]}" -c SHA256SUMS >/dev/null) || die "SHA256SUMS verification failed"
for archive_name in "${sorted_archives[@]}"; do
	cmp -s <(cd -- "$output_dir" && "${SHA256SUM[@]}" "$archive_name") "$output_dir/$archive_name.sha256" ||
		die "sidecar digest does not match archive: $archive_name.sha256"
done

printf 'package-component: PASS (name=%s, target=%s, version=%s, output=%s, key=%s/%s/%s.tar.gz)\n' \
	"$COMPONENT_NAME" "$TARGET" "$cargo_version" "$OUTPUT" "$CDN_LAYOUT" "$cargo_version" "$TARGET"
