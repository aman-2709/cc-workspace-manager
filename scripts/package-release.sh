#!/bin/sh
# Assemble the release archive and SHA256SUMS (REQUIREMENTS.md §17). Used locally and by release.yml.
#
#   scripts/package-release.sh <stripped ccwm binary> <version> <THIRD_PARTY_LICENSES file> <output dir>
#
# Produces <output dir>/ccwm-<version>-x86_64-unknown-linux-musl.tar.gz and <output dir>/SHA256SUMS.
# The other packaged files are taken from the checkout that contains this script.
#
# Deterministic: sorted file list, owner/group 0, fixed modes, every mtime set to SOURCE_DATE_EPOCH
# (default: the last commit's time), gzip without name or timestamp. Needs GNU tar (--sort=name).
set -eu

TARGET=x86_64-unknown-linux-musl
# Files copied from the checkout, relative to its root. Keep in sync with the release notes.
DOCS="LICENSE README.md SECURITY.md CHANGELOG.md"
SCRIPTS="scripts/install.sh scripts/uninstall.sh"

die() {
    printf 'package-release: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 4 ] || die "usage: $0 <binary> <version> <THIRD_PARTY_LICENSES> <output dir>"
bin=$1
version=$2
licenses=$3
out=$4

root=$(cd "$(dirname "$0")/.." && pwd)

case $version in
    '' | *[!0-9A-Za-z.+-]* | [!0-9]*) die "invalid version '$version' (expected e.g. 0.1.0)" ;;
esac

# Check every input first and report all missing files at once.
missing=""
if [ ! -f "$bin" ] || [ ! -x "$bin" ]; then
    missing="$missing $bin(executable)"
fi
if [ ! -s "$licenses" ]; then
    missing="$missing $licenses(non-empty)"
fi
for f in $DOCS $SCRIPTS; do
    [ -f "$root/$f" ] || missing="$missing $f"
done
[ -z "$missing" ] || die "missing input file(s):$missing"

# The binary must be the version being packaged.
reported=$("$bin" --version)
[ "$reported" = "ccwm $version" ] || die "binary reports '$reported', expected 'ccwm $version'"

epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || true)}
case $epoch in
    '' | *[!0-9]*) die "set SOURCE_DATE_EPOCH (no Git commit time available: '$epoch')" ;;
esac

name="ccwm-$version-$TARGET"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
dir="$stage/$name"
mkdir -p "$dir/scripts"

install -m 0755 "$bin" "$dir/ccwm"
install -m 0644 "$licenses" "$dir/THIRD_PARTY_LICENSES"
for f in $DOCS; do
    install -m 0644 "$root/$f" "$dir/$f"
done
for f in $SCRIPTS; do
    install -m 0755 "$root/$f" "$dir/$f"
done
chmod 0755 "$dir" "$dir/scripts"

mkdir -p "$out"
archive="$out/$name.tar.gz"
LC_ALL=C tar -C "$stage" --sort=name --format=ustar \
    --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    -cf - "$name" | gzip -9 -n > "$archive"

(cd "$out" && sha256sum "$name.tar.gz" > SHA256SUMS)

printf 'package-release: wrote %s\n' "$archive"
cat "$out/SHA256SUMS"
