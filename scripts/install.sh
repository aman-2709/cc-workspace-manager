#!/bin/sh
# Install ccwm (CC Workspace Manager, unofficial) for the current user:
#   1. copy the binary to ~/.local/bin/ccwm (atomically, so a running daemon is not disturbed);
#   2. `ccwm service install`: write ~/.config/systemd/user/ccwm.service, daemon-reload,
#      enable --now (the service then starts at every login);
#   3. restart the service if it was already running (an upgrade).
# Idempotent. Needs no root and runs no privileged command. Never touches your data, your
# projects or your Claude Code sessions.
#
# Usage: scripts/install.sh [PATH/TO/ccwm]
#   Without an argument it uses the ccwm next to this script's directory (the release archive
#   layout: ccwm and scripts/install.sh), then ./ccwm.
set -eu

die() {
    echo "install.sh: $*" >&2
    exit 1
}

[ "$(id -u)" -ne 0 ] || die "run this as your normal user, not as root"
[ -n "${HOME:-}" ] || die "HOME is not set"

here=$(cd "$(dirname "$0")" && pwd)
src=${1:-}
if [ -z "$src" ]; then
    for candidate in "$here/../ccwm" "./ccwm"; do
        if [ -f "$candidate" ]; then
            src=$candidate
            break
        fi
    done
fi
if [ -z "$src" ] || [ ! -f "$src" ]; then
    die "no ccwm binary found; pass its path: scripts/install.sh path/to/ccwm"
fi
"$src" --version >/dev/null 2>&1 || die "$src does not run (is it the x86_64 Linux build?)"

bindir="$HOME/.local/bin"
dest="$bindir/ccwm"
mkdir -p "$bindir"

was_active=no
if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet ccwm.service 2>/dev/null; then
    was_active=yes
fi

tmp="$dest.new.$$"
trap 'rm -f "$tmp"' EXIT
cp "$src" "$tmp"
chmod 0755 "$tmp"
mv -f "$tmp" "$dest"
echo "Installed $dest ($("$dest" --version))"

if ! "$dest" service install; then
    echo "install.sh: the binary is installed, but the systemd user unit is not; without systemd, run \`$dest serve\` in the foreground" >&2
    exit 1
fi
if [ "$was_active" = yes ]; then
    "$dest" restart
fi

case ":${PATH:-}:" in
*":$bindir:"*) echo "Next: ccwm open" ;;
*) echo "Next: $dest open    ($bindir is not on your PATH)" ;;
esac
