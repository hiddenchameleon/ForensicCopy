#!/usr/bin/env sh
# install_man.sh — installs the Forensic_Copy(1) man page.
# Run after `cargo build --release`, or via `make install-man`.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MAN_SRC="$REPO_ROOT/docs/Forensic_Copy.1"

if [ ! -f "$MAN_SRC" ]; then
    echo "Error: man page not found at $MAN_SRC" >&2
    exit 1
fi

# Determine the best available man1 directory.
if [ -d "/usr/local/share/man/man1" ]; then
    MAN_DIR="/usr/local/share/man/man1"
elif [ -d "/usr/share/man/man1" ]; then
    MAN_DIR="/usr/share/man/man1"
else
    # Fall back: create under /usr/local/share/man/man1
    MAN_DIR="/usr/local/share/man/man1"
    mkdir -p "$MAN_DIR"
fi

echo "Installing Forensic_Copy.1 -> $MAN_DIR/Forensic_Copy.1"
cp "$MAN_SRC" "$MAN_DIR/Forensic_Copy.1"

# Update the man database.
if command -v mandb >/dev/null 2>&1; then
    mandb -q 2>/dev/null || true
elif command -v makewhatis >/dev/null 2>&1; then
    makewhatis "$MAN_DIR" 2>/dev/null || true
fi

echo "man Forensic_Copy is now available"
