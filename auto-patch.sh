#!/bin/bash
# Auto-patch Windows App to enable MS-RDPEUDP for direct (non-AVD) RDP connections.
#
# What it does:
#   Finds the ObjC method -[RDCConnectionSettings(RdpConnectionSettings) asConnectionSettingsEx]
#   in EACH architecture slice (arm64 and/or x86_64), locates the 2nd call to
#   RdCore::RdpConnectionSettings::IsWvdConnection (the gate that suppresses
#   EnableUdpSideTransport for non-AVD connections), and NOPs the conditional branch that
#   immediately follows it. Then re-signs ad-hoc.
#
#   Windows App ships as a universal binary. Apple Silicon Macs run the arm64 slice;
#   Intel Macs run the x86_64 slice. Both are patched so the fix works on either machine.
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

app_version() {
    /usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$1/Contents/Info.plist" 2>/dev/null || echo "?"
}

# Best-effort "is the live binary still un-patched?" check. Returns success (0) when
# the second IsWvdConnection gate on the native slice is still a real conditional
# branch (cbz/je) rather than a NOP we already wrote.
native_is_pristine() {
    local a res
    a=$(lipo -archs "$BIN" 2>/dev/null | tr ' ' '\n' | grep -xE "$(uname -m)" | head -1) || true
    [ -n "$a" ] || a=$(lipo -archs "$BIN" 2>/dev/null | awk '{print $1}')
    # Capture into a var (not `| grep -q`): the awk `exit` closes otool's pipe early,
    # and under `set -o pipefail` otool's resulting SIGPIPE would poison the pipeline.
    res=$(otool -arch "$a" -tV "$BIN" 2>/dev/null | awk '
        /asConnectionSettingsEx\]:/ {infn=1}
        infn && /IsWvdConnectionEv/ && ($2=="bl"||$2=="callq") {n++; win=(n==2?4:0); next}
        infn && n==2 && win>0 { if ($2=="cbz"||$2=="je"){print "BRANCH"; exit} else win-- }
    ') || true
    [ "$res" = "BRANCH" ]
}

# ---------------------------------------------------------------------------
# Backup (version-aware). We keep a pristine, Microsoft-signed copy in $BAK so
# revert.sh can restore it. If a backup from a PREVIOUS Windows App version is
# lying around (e.g. you updated the app since last patching), leaving it would
# make revert.sh silently downgrade you. Refresh it — but only when the live app
# is still pristine, so we never snapshot an already-patched binary as "original".
# ---------------------------------------------------------------------------
APP_VER=$(app_version "$APP")

if [ -d "$BAK" ]; then
    BAK_VER=$(app_version "$BAK")
    if [ "$BAK_VER" != "$APP_VER" ]; then
        echo "==> Existing backup is version $BAK_VER but installed app is $APP_VER (stale)."
        if native_is_pristine; then
            echo "    App looks un-patched. Refreshing backup so revert.sh restores $APP_VER."
            sudo rm -rf "$BAK"
            sudo ditto "$APP" "$BAK"
        else
            echo "ERROR: the installed app appears ALREADY PATCHED, and the only backup is a" >&2
            echo "       different version ($BAK_VER). Refreshing now would save a patched binary" >&2
            echo "       as the 'original'. Reinstall a clean Windows App $APP_VER, delete $BAK," >&2
            echo "       then re-run this script." >&2
            exit 1
        fi
    fi
else
    echo "==> Backing up bundle to $BAK..."
    sudo ditto "$APP" "$BAK"
fi

# ---------------------------------------------------------------------------
# Per-arch patch
# ---------------------------------------------------------------------------
# Discover which slices are present.
ARCHES=$(lipo -archs "$BIN" 2>/dev/null || echo arm64)
echo "==> Slices present: $ARCHES"

PATCHED_ANY=0

patch_arch() {
    local ARCH="$1"
    echo
    echo "==================== $ARCH ===================="

    local DISASM
    DISASM=$(mktemp)
    otool -arch "$ARCH" -tV "$BIN" > "$DISASM" 2>/dev/null

    local FN_LINE
    FN_LINE=$(grep -n 'RDCConnectionSettings.*asConnectionSettingsEx\]:' "$DISASM" | head -1 | cut -d: -f1)
    if [ -z "$FN_LINE" ]; then
        echo "[$ARCH] asConnectionSettingsEx not found — skipping this slice." >&2
        rm -f "$DISASM"; return 0
    fi

    # Walk the function body. After each call to IsWvdConnection, capture the first
    # conditional branch within a short window (arm64: cbz w0; x86_64: je after testb).
    # Cap at 500 lines so we stay inside asConnectionSettingsEx.
    local -a GATES=()
    local NR=0 WIN=0
    while IFS= read -r line; do
        NR=$((NR + 1)); [ "$NR" -gt 500 ] && break

        if [[ "$line" =~ IsWvdConnectionEv ]] && { [[ "$line" =~ [[:space:]]bl[[:space:]] ]] || [[ "$line" =~ callq ]]; }; then
            WIN=4
            continue
        fi
        if [ "$WIN" -gt 0 ]; then
            if [[ "$ARCH" == arm64* ]] && [[ "$line" =~ cbz[[:space:]]+w0, ]]; then
                GATES+=("$(echo "$line" | awk '{print $1}')")
                WIN=0
            elif [[ "$ARCH" == x86_64 ]] && [[ "$line" =~ [[:space:]]je[[:space:]]+0x ]]; then
                GATES+=("$(echo "$line" | awk '{print $1}')")
                WIN=0
            else
                WIN=$((WIN - 1))
            fi
        fi
    done < <(tail -n +"$FN_LINE" "$DISASM")
    rm -f "$DISASM"

    local COUNT=${#GATES[@]}
    echo "[$ARCH] Found $COUNT branch(es) following IsWvdConnection calls"
    if [ "$COUNT" -lt 2 ]; then
        echo "[$ARCH] ERROR: expected >=2, function structure may have changed." >&2
        echo "[$ARCH] Fall through to Ghidra with find-udp-gate.py (see INVESTIGATION.md)." >&2
        return 3
    fi

    # Second branch is the UDP gate (first gates the AAD tenant-ID block).
    local TARGET_VA="${GATES[1]}"
    echo "[$ARCH] UDP-gate branch VA: $TARGET_VA"

    # Fat-file offset = lipo slice offset + (VA - __TEXT vmaddr for this slice).
    local ARCH_OFF TEXT_VM VA_DEC FAT_OFF
    ARCH_OFF=$(lipo -detailed_info "$BIN" | awk -v a="$ARCH" '$1=="architecture" && $2==a {f=1} f && $1=="offset" {print $2; exit}')
    TEXT_VM=$(otool -arch "$ARCH" -l "$BIN" | awk '/segname __TEXT/{f=1} f && $1=="vmaddr"{print $2; exit}')
    VA_DEC=$((16#${TARGET_VA#0x}))
    FAT_OFF=$((ARCH_OFF + VA_DEC - TEXT_VM))
    printf '[%s] fat file offset: %d (0x%X)\n' "$ARCH" "$FAT_OFF" "$FAT_OFF"

    # Determine instruction length + NOP encoding, and sanity-check the current bytes.
    local PATCH LEN CURRENT
    if [[ "$ARCH" == arm64* ]]; then
        # cbz w0 = 4 bytes, little-endian opcode byte 0x34 => trailing hex byte "34".
        LEN=4
        CURRENT=$(sudo dd if="$BIN" bs=1 skip="$FAT_OFF" count=4 2>/dev/null | xxd -p)
        if [[ ! "$CURRENT" =~ 34$ ]]; then
            echo "[$ARCH] WARN: bytes $CURRENT not a cbz w0 (expect trailing 34). Aborting slice." >&2
            return 4
        fi
        PATCH='\x1f\x20\x03\xd5'   # nop
    else
        # x86_64 je: short 0x74 (2 bytes) or near 0x0F 0x84 (6 bytes). NOP-fill with 0x90.
        local B2
        B2=$(sudo dd if="$BIN" bs=1 skip="$FAT_OFF" count=2 2>/dev/null | xxd -p)
        if [[ "$B2" == 0f84 ]]; then
            LEN=6
        elif [[ "${B2:0:2}" == 74 ]]; then
            LEN=2
        else
            echo "[$ARCH] WARN: bytes $B2 not a je (expect 74 or 0f84). Aborting slice." >&2
            return 4
        fi
        CURRENT=$(sudo dd if="$BIN" bs=1 skip="$FAT_OFF" count="$LEN" 2>/dev/null | xxd -p)
        PATCH=$(printf '\\x90%.0s' $(seq 1 "$LEN"))   # LEN * NOP
    fi
    echo "[$ARCH] Current: $CURRENT  ->  NOP ($LEN bytes)"

    # Apply patch.
    printf "$PATCH" | sudo dd of="$BIN" bs=1 seek="$FAT_OFF" count="$LEN" conv=notrunc 2>&1 | tail -1

    PATCHED_ANY=1
    # Remember for post-signing verification.
    VERIFY_ARCH+=("$ARCH")
    VERIFY_VA+=("$TARGET_VA")
    return 0
}

VERIFY_ARCH=()
VERIFY_VA=()

for ARCH in $ARCHES; do
    patch_arch "$ARCH" || { echo "Slice $ARCH failed." >&2; exit 3; }
done

if [ "$PATCHED_ANY" != 1 ]; then
    echo "Nothing patched." >&2; exit 3
fi

# ---------------------------------------------------------------------------
# Re-sign + clear quarantine (once, after all slices patched).
# ---------------------------------------------------------------------------
echo
echo "==> Re-signing ad-hoc..."
sudo codesign --force --deep --sign - "$APP"
sudo codesign -v "$APP"
sudo xattr -r -d com.apple.quarantine "$APP" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Final verification per slice (VA-stable, works regardless of signature shifts).
# ---------------------------------------------------------------------------
echo
FAILED=0
for i in "${!VERIFY_ARCH[@]}"; do
    ARCH="${VERIFY_ARCH[$i]}"
    VA="${VERIFY_VA[$i]}"
    INSTR=$(otool -arch "$ARCH" -tV "$BIN" 2>/dev/null | awk -v va="${VA#0x}" 'tolower($1) ~ va {print $2}')
    if [[ "$INSTR" == nop* ]]; then
        echo "SUCCESS [$ARCH]: nop at $VA"
    else
        echo "FAIL [$ARCH]: expected nop at $VA, got '$INSTR'" >&2
        FAILED=1
    fi
done
exit $FAILED
