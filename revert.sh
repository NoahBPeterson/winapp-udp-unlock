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

# Version/arch-independent verification: the original binary still *branches* at the
# second IsWvdConnection gate (cbz on arm64, je on x86_64). auto-patch.sh replaces that
# branch with a NOP, so a restored, pristine binary must show a real branch again.
echo "==> Verifying the UDP gate is a real branch again on every slice..."
FAIL=0
for ARCH in $(lipo -archs "$BIN" 2>/dev/null || echo arm64); do
    # `|| true`: the awk `exit` closes otool's pipe early; under `set -o pipefail`
    # otool's SIGPIPE would otherwise abort the script here.
    MN=$(otool -arch "$ARCH" -tV "$BIN" 2>/dev/null | awk '
        /asConnectionSettingsEx\]:/ {infn=1}
        infn && /IsWvdConnectionEv/ && ($2=="bl"||$2=="callq") {n++; win=(n==2?4:0); next}
        infn && n==2 && win>0 { if ($2=="cbz"||$2=="je"||$2=="nop"){print $2; exit} else win-- }
    ') || true
    if [ "$MN" = "cbz" ] || [ "$MN" = "je" ]; then
        echo "OK [$ARCH]: original branch ($MN) restored at the UDP gate."
    else
        echo "WARN [$ARCH]: expected cbz/je at the UDP gate, got '${MN:-none}'. .bak may not be pristine." >&2
        FAIL=1
    fi
done

if [ "$FAIL" = 0 ]; then
    echo "Done. Launch Windows App — it is now unpatched, Microsoft-signed."
else
    echo "Done, but verification was inconclusive — check the backup." >&2
fi
