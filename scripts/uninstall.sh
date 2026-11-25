#!/bin/sh
# Remove ccwm (CC Workspace Manager, unofficial) for the current user: stop and remove the
# systemd user unit (`ccwm service uninstall`) and ~/.local/bin/ccwm.
# Your ccwm data (configuration, database, state) is KEPT unless you pass --purge, which asks
# for confirmation first. Your projects and Claude Code sessions are never touched.
# Idempotent. Needs no root and runs no privileged command.
#
# Usage: scripts/uninstall.sh [--purge]
set -eu

die() {
    echo "uninstall.sh: $*" >&2
    exit 1
}

purge=
case "${1:-}" in
"") ;;
--purge) purge=--purge ;;
*) die "usage: scripts/uninstall.sh [--purge]" ;;
esac
[ "$(id -u)" -ne 0 ] || die "run this as your normal user, not as root"
[ -n "${HOME:-}" ] || die "HOME is not set"

dest="$HOME/.local/bin/ccwm"
if [ -x "$dest" ]; then
    # shellcheck disable=SC2086 # $purge is empty or one word
    "$dest" service uninstall $purge
    rm -f "$dest"
    echo "Removed $dest"
else
    echo "$dest is not installed; nothing to remove"
    if [ -n "$purge" ]; then
        die "--purge needs the ccwm binary to locate its data; delete ~/.config/ccwm, ~/.local/share/ccwm and ~/.local/state/ccwm yourself (or the \$XDG_* equivalents)"
    fi
fi
