#!/bin/sh
# Remove the mavirank collector of the calling user (see install.sh).
#
#   ./uninstall.sh                  remove the crontab entry; remove the shared command and
#                                        package unless other instances (--name) still use them
#   ./uninstall.sh --name <name>    remove only the crontab entry of this instance
#   --home <dir>                         the base directory given to install.sh --home
#   --purge                              also delete the configuration and state (offsets, day
#                                        keys) of the instance
set -eu
umask 077

PURGE=0
NAME=
BASE=
ANY_MARKER="# mavirank-collector[: ].*(install\.sh)"

die() { echo "uninstall.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --purge) PURGE=1; shift ;;
        --name) [ $# -ge 2 ] || die "--name needs a value"; NAME=$2; shift 2 ;;
        --home) [ $# -ge 2 ] || die "--home needs a directory"; BASE=$2; shift 2 ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$NAME" in
    *[!a-z0-9-]*) die "--name: only lowercase letters, digits and - are allowed" ;;
    collector|keys) die "--name: \"$NAME\" is reserved" ;;
esac

# Everything lives below one base directory: the home directory, or --home <dir> where the home
# directory is not writable (hosting panels often protect it and offer a private subdirectory).
if [ -z "$BASE" ]; then
    [ -n "${HOME:-}" ] && [ -d "$HOME" ] || die "HOME is not set or does not exist (or use --home <dir>)"
    BASE=$HOME
fi
[ -d "$BASE" ] || die "--home: $BASE is not a directory"
BASE=$(cd "$BASE" && pwd) || die "--home: cannot enter $BASE"

SHARE_DIR=$BASE/.local/share/mavirank-collector
BIN=$BASE/.local/bin/mavirank-collector
CONF_DIR=$BASE/.config/mavirank-collector
STATE_BASE=$BASE/.local/state/mavirank-collector
if [ -n "$NAME" ]; then
    CONF_FILE=$CONF_DIR/$NAME.conf
    STATE_DIR=$STATE_BASE/$NAME
    MARKER="# mavirank-collector:$NAME (install.sh)"
    LABEL="instance $NAME"
else
    CONF_FILE=$CONF_DIR/collector.conf
    STATE_DIR=$STATE_BASE
    MARKER="# mavirank-collector (install.sh)"
    LABEL="mavirank collector"
fi

OTHERS=0
if command -v crontab >/dev/null 2>&1; then
    OLD=$(mktemp "${TMPDIR:-/tmp}/mavirank-cron.XXXXXX")
    NEW=$(mktemp "${TMPDIR:-/tmp}/mavirank-cron.XXXXXX")
    trap 'rm -f "$OLD" "$NEW"' EXIT
    if crontab -l > "$OLD" 2>/dev/null; then
        if grep -qF "$MARKER" "$OLD"; then
            grep -vF "$MARKER" "$OLD" > "$NEW" || true
            if [ -s "$NEW" ]; then
                crontab "$NEW" || die "cannot write your crontab; remove the line ending in '$MARKER' yourself"
            else
                crontab -r 2>/dev/null || crontab "$NEW" || die "cannot remove your crontab entry"
            fi
            echo "removed the crontab entry ($MARKER)"
        else
            cp "$OLD" "$NEW"
        fi
        if grep -qE "$ANY_MARKER" "$NEW"; then OTHERS=1; fi
    fi
fi

# Command and package are shared: only the default call removes them, and only if no other
# instance still has a crontab entry.
if [ -z "$NAME" ]; then
    if [ "$OTHERS" -eq 1 ]; then
        echo "kept $BIN and $SHARE_DIR: other instances still run from your crontab (remove them with --name first)"
    else
        if [ -f "$BIN" ]; then
            if grep -q "install.sh" "$BIN" 2>/dev/null; then
                rm -f "$BIN"
                echo "removed $BIN"
            else
                echo "kept $BIN (not created by install.sh)" >&2
            fi
        fi
        if [ -d "$SHARE_DIR" ]; then
            rm -rf "$SHARE_DIR"
            echo "removed $SHARE_DIR"
        fi
    fi
fi

if [ "$PURGE" -eq 1 ]; then
    rm -f "$CONF_FILE"
    if [ -n "$NAME" ]; then
        rm -rf "$STATE_DIR"
    elif [ -d "$STATE_DIR" ]; then
        # The default state directory also holds the state of named instances: keep those
        # whose configuration still exists.
        for entry in "$STATE_DIR"/* "$STATE_DIR"/.[!.]*; do
            [ -e "$entry" ] || continue
            base=$(basename "$entry")
            if [ -d "$entry" ] && [ -f "$CONF_DIR/$base.conf" ]; then
                continue
            fi
            rm -rf "$entry"
        done
    fi
    rmdir "$STATE_DIR" "$STATE_BASE" "$CONF_DIR" 2>/dev/null || true
    echo "$LABEL removed (including configuration and state)."
else
    echo "$LABEL removed. Kept: $CONF_FILE, $STATE_DIR."
    echo "Use --purge to delete them as well."
fi
