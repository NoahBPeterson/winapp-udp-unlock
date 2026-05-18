#!/bin/bash
# Auto-patch Windows App to enable MS-RDPEUDP for direct (non-AVD) RDP connections.
#
# What it does:
#   Finds the ObjC method -[RDCConnectionSettings(RdpConnectionSettings) asConnectionSettingsEx]
#   in the arm64 slice, locates the 2nd call to RdCore::RdpConnectionSettings::IsWvdConnection
#   (the gate that suppresses EnableUdpSideTransport for non-AVD connections), and NOPs the
#   cbz w0 that immediately follows it. Then re-signs ad-hoc.
#
# Requires:
#   - App Management permission for this terminal (Privacy & Security)
#   - sudo
#   - ClientSettings.EnableAvdUdpSideTransport = 1 in com.microsoft.rdc.macos defaults
#   - Server-side SelectTransport = 0 (and no GPO override)

set -euo pipefail

APP="${1:-/Applications/Windows App.app}"
BIN="$APP/Contents/MacOS/Windows App"
BAK="$APP.bak"

[ -d "$APP" ] || { echo "Not found: $APP" >&2; exit 1; }

# Backup once, idempotently
if [ ! -d "$BAK" ]; then
    echo "==> Backing up bundle to $BAK..."
    sudo ditto "$APP" "$BAK"
fi

echo "==> Disassembling arm64 slice..."
DISASM=$(mktemp)
trap "rm -f $DISASM" EXIT
otool -arch arm64 -tV "$BIN" > "$DISASM" 2>/dev/null

# Find function entry
FN_LINE=$(grep -n 'RDCConnectionSettings.*asConnectionSettingsEx\]:' "$DISASM" | head -1 | cut -d: -f1)
[ -n "$FN_LINE" ] || { echo "asConnectionSettingsEx not found — symbol structure changed" >&2; exit 2; }

# Walk forward through function body, collect every cbz w0 that follows a bl to IsWvdConnection.
# Cap search at 500 lines (function is ~300 lines of asm).
BL_IDX=0
NR=0
declare -a CBZ_VAS
while IFS= read -r line; do
    NR=$((NR + 1))
    [ "$NR" -gt 500 ] && break
    if [[ "$line" =~ bl.*IsWvdConnectionEv ]]; then
        PREV_WAS_BL=1
        continue
    fi
    if [ "${PREV_WAS_BL:-0}" = "1" ] && [[ "$line" =~ cbz[[:space:]]+w0,[[:space:]]+(0x[0-9a-f]+) ]]; then
        VA=$(echo "$line" | awk '{print $1}')
        CBZ_VAS+=("$VA")
    fi
    PREV_WAS_BL=0
done < <(tail -n +"$FN_LINE" "$DISASM")

COUNT=${#CBZ_VAS[@]}
echo "Found $COUNT 'cbz w0' instructions following IsWvdConnection calls"

if [ "$COUNT" -lt 2 ]; then
    echo "ERROR: expected ≥2, function structure may have changed" >&2
    echo "Manual investigation required — load in Ghidra and find the cbz" >&2
    echo "that gates the block setting property \"EnableUdpSideTransport\"." >&2
    exit 3
fi

# Second one is the UDP gate (first is AAD tenant ID gate).
TARGET_VA="${CBZ_VAS[1]}"
echo "Target VA (UDP gate): $TARGET_VA"

# Compute fat file offset
ARM64_OFF=$(lipo -detailed_info "$BIN" | awk '$1=="architecture" && $2=="arm64" {f=1} f && $1=="offset" {print $2; exit}')
VA_HEX="${TARGET_VA#0x}"
VA_DEC=$((16#$VA_HEX))
SLICE_BASE=$((16#100000000))
FAT_OFF=$((ARM64_OFF + VA_DEC - SLICE_BASE))
echo "Fat file offset: $FAT_OFF ($(printf '0x%X' $FAT_OFF))"

# Verify current bytes encode cbz w0 (opcode byte = 0x34 in little-endian, so last hex byte)
CURRENT=$(sudo dd if="$BIN" bs=1 skip=$FAT_OFF count=4 2>/dev/null | xxd -p)
if [[ ! "$CURRENT" =~ 34$ ]]; then
    echo "WARN: bytes $CURRENT don't look like cbz w0 (expect trailing 34). Aborting." >&2
    exit 4
fi
echo "Current: $CURRENT  →  patching to: 1f2003d5 (nop)"

# Apply patch
printf '\x1f\x20\x03\xd5' | sudo dd of="$BIN" bs=1 seek=$FAT_OFF count=4 conv=notrunc 2>&1 | tail -1

# Re-sign + clear quarantine
echo "==> Re-signing ad-hoc..."
sudo codesign --force --deep --sign - "$APP"
sudo codesign -v "$APP"
sudo xattr -r -d com.apple.quarantine "$APP" 2>/dev/null || true

# Final verification via otool (VA-stable, works regardless of signature shifts)
INSTR=$(otool -arch arm64 -tV "$BIN" 2>/dev/null | awk -v va="${TARGET_VA#0x}" 'tolower($1) ~ va {print $2}')
if [ "$INSTR" = "nop" ]; then
    echo "SUCCESS: nop at $TARGET_VA"
else
    echo "FAIL: expected nop, got '$INSTR'" >&2
    exit 5
fi
