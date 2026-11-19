#!/bin/sh
# Install the mavirank collector for one website in the account of the calling user (SSH,
# Python 3.9+ and cron). No root needed; nothing is downloaded; no pip, no venv, no sudo.
# Run it as a user who can read the website's log files, not as root.
#
#   ./install.sh [--name <name>] [--python /usr/bin/python3] [--cron]
#
# Creates:  ~/.local/share/mavirank-collector/            the package (shared by all instances)
#           ~/.local/bin/mavirank-collector               command (shared)
#           ~/.config/mavirank-collector/collector.conf   configuration (0600, kept on reinstall)
#           ~/.local/state/mavirank-collector             state (0700)
#   --name  another website in the same account (lowercase letters, digits, "-"): uses
#           ~/.config/mavirank-collector/<name>.conf and ~/.local/state/mavirank-collector/<name>
#   --cron  adds a crontab entry that runs this instance every 5 minutes (idempotent);
#           without it the entry is only printed.
#
# Remove with ./uninstall.sh [--name <name>] (--purge also deletes configuration and state).
set -eu
umask 077

PYTHON=
CRON=0
NAME=

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --python) [ $# -ge 2 ] || die "--python needs a path"; PYTHON=$2; shift 2 ;;
        --cron) CRON=1; shift ;;
        --name) [ $# -ge 2 ] || die "--name needs a value"; NAME=$2; shift 2 ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$NAME" in
    *[!a-z0-9-]*) die "--name: only lowercase letters, digits and - are allowed" ;;
    collector|keys) die "--name: \"$NAME\" is reserved, choose another name" ;;
esac

UID_NOW=$(id -u) || die "the id command is not available"
ROOT_NOTE="Note: you are installing as root, so the collector runs as root from root's crontab.
It only needs to read the log files: better install it as a user who can read them (the
website's user, or a user in the group that owns the logs, e.g. adm) instead of root."
if [ "$UID_NOW" -eq 0 ]; then
    echo "$ROOT_NOTE" >&2
    echo >&2
fi
[ -n "${HOME:-}" ] && [ -d "$HOME" ] || die "HOME is not set or does not exist"

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$SRC_DIR/mavirank_collector/cli.py" ] || die "package not found next to this script ($SRC_DIR)"

SHARE_DIR=$HOME/.local/share/mavirank-collector
BIN_DIR=$HOME/.local/bin
BIN=$BIN_DIR/mavirank-collector
CONF_DIR=$HOME/.config/mavirank-collector
STATE_BASE=$HOME/.local/state/mavirank-collector
if [ -n "$NAME" ]; then
    CONF_FILE=$CONF_DIR/$NAME.conf
    STATE_DIR=$STATE_BASE/$NAME
    MARKER="# mavirank-collector:$NAME (install.sh)"
    RUN="'$BIN' --config '$CONF_FILE'"
else
    CONF_FILE=$CONF_DIR/collector.conf
    STATE_DIR=$STATE_BASE
    MARKER="# mavirank-collector (install.sh)"
    RUN="'$BIN'"
fi

# Python >= 3.9: the given one, else python3, else the newest python3.X found in PATH.
py_ok() {
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1
}
if [ -n "$PYTHON" ]; then
    FOUND=$(command -v "$PYTHON" 2>/dev/null) || die "Python not found: $PYTHON"
    py_ok "$FOUND" || die "Python >= 3.9 is required, $FOUND is $("$FOUND" -V 2>&1 || echo 'not usable')"
else
    FOUND=
    for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10 python3.9; do
        path=$(command -v "$candidate" 2>/dev/null) || continue
        if py_ok "$path"; then FOUND=$path; break; fi
    done
    if [ -z "$FOUND" ]; then
        have=$(command -v python3 2>/dev/null) && have="$have is $("$have" -V 2>&1)" || have="no python3 in PATH"
        die "Python >= 3.9 is required ($have); pass another interpreter with --python /path/to/python3.X"
    fi
fi
case "$FOUND" in /*) ;; *) FOUND=$(cd "$(dirname "$FOUND")" && pwd)/$(basename "$FOUND") ;; esac
PYTHON=$FOUND
case "$HOME$PYTHON" in
    *"'"*|*"%"*) die "paths containing ' or % are not supported: $HOME, $PYTHON" ;;
esac
echo "==> Python $PYTHON ($("$PYTHON" -V 2>&1))"

echo "==> package in $SHARE_DIR"
mkdir -p "$SHARE_DIR"
rm -rf "$SHARE_DIR/mavirank_collector"
cp -R "$SRC_DIR/mavirank_collector" "$SHARE_DIR/mavirank_collector"
find "$SHARE_DIR/mavirank_collector" -name '__pycache__' -type d -prune -exec rm -rf {} +
[ -f "$SRC_DIR/README.md" ] && cp "$SRC_DIR/README.md" "$SHARE_DIR/README.md"
"$PYTHON" -m compileall -q "$SHARE_DIR/mavirank_collector" >/dev/null 2>&1 || true

echo "==> command $BIN"
mkdir -p "$BIN_DIR"
TMP_BIN=$BIN.tmp.$$
cat > "$TMP_BIN" <<STARTER
#!/bin/sh
# mavirank collector, user installation (created by install.sh).
# The configuration defaults to the file below; --config or MAVIRANK_COLLECTOR_CONFIG override it.
if [ -z "\${MAVIRANK_COLLECTOR_CONFIG+x}" ]; then
    MAVIRANK_COLLECTOR_CONFIG='$CONF_FILE'
    export MAVIRANK_COLLECTOR_CONFIG
fi
PYTHONPATH='$SHARE_DIR'
export PYTHONPATH
# Same as "python3 -m mavirank_collector", but without the current directory on sys.path.
exec '$PYTHON' -s -c 'import sys
if sys.path and sys.path[0] == "":
    del sys.path[0]
from mavirank_collector.cli import main
sys.exit(main())' "\$@"
STARTER
chmod 0700 "$TMP_BIN"
mv -f "$TMP_BIN" "$BIN"

echo "==> configuration $CONF_FILE"
mkdir -p "$CONF_DIR"
chmod 0700 "$CONF_DIR"
if [ -e "$CONF_FILE" ]; then
    chmod 0600 "$CONF_FILE"
    NEW_CONF=0
    echo "    kept the existing file"
else
    TMP_CONF=$CONF_FILE.tmp.$$
    # "dir" in [state] becomes the state directory in the home directory; everything else as in the example.
    STATE_DIR=$STATE_DIR awk '
        function put() { print "dir = " ENVIRON["STATE_DIR"]; done = 1 }
        /^[[:space:]]*\[/ {
            if (section == "[state]" && !done) put()
            section = $0; gsub(/[[:space:]]/, "", section)
        }
        section == "[state]" && /^[[:space:]]*[#;]?[[:space:]]*dir[[:space:]]*=/ { if (!done) put(); next }
        { print }
        END {
            if (section == "[state]" && !done) put()
            if (!done) { print ""; print "[state]"; put() }
        }
    ' "$SRC_DIR/examples/collector.conf" > "$TMP_CONF"
    chmod 0600 "$TMP_CONF"
    mv "$TMP_CONF" "$CONF_FILE"
    NEW_CONF=1
fi

echo "==> state $STATE_DIR"
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_BASE" "$STATE_DIR"

CRON_LINE="*/5 * * * * $RUN run >/dev/null 2>&1 $MARKER"
if [ "$CRON" -eq 1 ]; then
    echo "==> crontab"
    command -v crontab >/dev/null 2>&1 || die "crontab not found; add this line with the cron tool of your hosting panel: $CRON_LINE"
    OLD=$(mktemp "${TMPDIR:-/tmp}/mavirank-cron.XXXXXX")
    ERR=$(mktemp "${TMPDIR:-/tmp}/mavirank-cron.XXXXXX")
    NEW=$(mktemp "${TMPDIR:-/tmp}/mavirank-cron.XXXXXX")
    trap 'rm -f "$OLD" "$ERR" "$NEW"' EXIT
    if ! crontab -l > "$OLD" 2> "$ERR"; then
        # "no crontab for <user>" (cron, cronie) or "can't open" (busybox): start empty.
        if grep -qiE "no crontab|can't open|cannot open" "$ERR"; then
            : > "$OLD"
        else
            die "cannot read your crontab ($(cat "$ERR")); add this line yourself: $CRON_LINE"
        fi
    fi
    grep -vF "$MARKER" "$OLD" > "$NEW" || true
    printf '%s\n' "$CRON_LINE" >> "$NEW"
    crontab "$NEW" || die "cannot write your crontab; add this line yourself: $CRON_LINE"
    if grep -qF "$MARKER" "$OLD"; then echo "    entry updated"; else echo "    entry added"; fi
fi

echo
echo "Installed${NAME:+ instance $NAME} for user $(id -un). Next steps:"
step=1
if [ "$NEW_CONF" -eq 1 ]; then
    echo "  $step. edit $CONF_FILE (ingest_url, token, log paths, domain)"; step=$((step + 1))
fi
echo "  $step. $RUN check"; step=$((step + 1))
echo "  $step. $RUN run --dry-run"; step=$((step + 1))
if [ "$CRON" -eq 1 ]; then
    echo "  The collector runs every 5 minutes from your crontab (crontab -l)."
else
    echo "  $step. run it every 5 minutes: ./install.sh${NAME:+ --name $NAME} --cron, or add this line with crontab -e"
    echo "     or the cron tool of your hosting panel:"
    echo
    echo "$CRON_LINE"
fi
if [ "$UID_NOW" -eq 0 ]; then
    echo
    echo "$ROOT_NOTE"
fi
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo; echo "Note: $BIN_DIR is not in your PATH; use the full path shown above." ;;
esac
