#!/bin/bash
# Revert Windows App to the original, unpatched, Microsoft-signed binary.
# Restores from /Applications/Windows App.app.bak (whole-bundle ditto).
#
# Requires: Terminal has App Management permission
# (System Settings > Privacy & Security > App Management)

set -euo pipefail

APP="/Applications/Windows App.app"
BAK="/Applications/Windows App.app.bak"
BIN="$APP/Contents/MacOS/Windows App"

if [ ! -d "$BAK" ]; then
    echo "ERROR: $BAK not found. Cannot revert." >&2
    echo "(You would need to reinstall Windows App from Microsoft.)" >&2
    exit 1
fi

echo "==> Removing patched bundle..."
sudo rm -rf "$APP"

echo "==> Restoring original from $BAK..."
sudo ditto "$BAK" "$APP"

echo "==> Verifying original at VA 0x100b484e4 via otool..."
INSTR=$(otool -arch arm64 -tV "$BIN" 2>/dev/null | awk '/^0000000100b484e4/ {print $2}')
if [ "$INSTR" = "cbz" ]; then
    echo "OK: original cbz restored at 0x100b484e4"
else
    echo "WARN: expected cbz, got '$INSTR'. .bak may not be pristine." >&2
fi

echo "Done. Launch Windows App — it is now unpatched, Microsoft-signed."
