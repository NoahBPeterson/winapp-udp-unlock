#!/bin/bash
# deep-patch.sh v3 — 11.4.2 (build 3104) UDP side-transport injection, arm64 + x86_64.
#
# 11.4.2 rewrote the UDP engine to RdpNano, which refuses to start unless a
# SideTransportCreationParams object is present on the connection property set. Only the
# Azure gateway path ever creates one, so direct RDP fell back to TCP (TsUdpTransport::Connect
# aborted with 0x8000ffff). This injects a code-cave stub that fabricates that object (empty
# fields; RdpNano reads the server address from the property set) and publishes it via the
# property set's own virtual SetIUnknownProperty, right after Connect resolves that property
# set. Result: direct RDP negotiates UDP (Private).
#
# Requires auto-patch.sh (the gate NOP) applied first, sudo, App Management permission.
# Reversible via revert.sh or ~/Backups/winapp-udp-unlock/11.4.2/restore.sh pristine.
# Verified: arm64 live (UDP Private); x86_64 under Rosetta 2.

set -euo pipefail
APP="${1:-/Applications/Windows App.app}"
BIN="$APP/Contents/MacOS/Windows App"
[ -f "$BIN" ] || { echo "Not found: $BIN" >&2; exit 1; }
VER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$APP/Contents/Info.plist" 2>/dev/null || echo "?")
[ "$VER" = "3104" ] || echo "WARN: build $VER (stub built for 3104)." >&2
TEXT_VM=0x100000000

# --- arm64 payload ---
A64_STUB="ff0301d1f35300a9f57b01a9f30300aaff1700f9680240f9083d40f9e00313aa01edff9021c42891e2a3009100013fd6e81740f9c80400b5001780d281ddfff02128239145c8d197200400b4f40300aa08dcfff0094d43f9890e00f9a80900d0086110919f1600f909610191890600f989220091891200f909410091890200f909410291890a00f989c200913f7d00a93f7d01a93f7d02a93f7d03a93f7d04a93f7d05a93f7d06a93f7d07a93f4100f9680240f9081940f9e00313aa01edff9021c42891e20314aa00013fd6e00313aaf35340a9f57b41a9ff030191080040f95369e517"
A64_HOOK="76961a14"; A64_CAVE=0x101f140a8; A64_HOOKVA=0x10186e6d0; A64_ORIG="080040f9"
A64_OLD_HOOKVA=0x10186e6c0; A64_OLD_BR="7a961a14"; A64_OLD_ORIG="e00f41f9"

# --- x86_64 payload ---
X64_STUB="ff5028554889e5534883ec104889c348c7042400000000488b034889df488d353e2cdbff4889e2ff5078488b04244885c00f85a5000000bfb8000000488d35af7abcffe838ae3bff4885c00f848b0000004889c148bacdabcadb0100000048895118c7412800000000488d510848895120488d15a0d01200488d7210488931488d7258488971084881c290000000488951100f57c00f1141300f1141400f1141500f1141600f1141700f1181800000000f1181900000000f1181a000000048c781b0000000000000004889ca4889df488b03488d35892bdbffff50304889d84883c4105b5d488b08e9291399ff"
X64_HOOK="e9ebeb660090"; X64_CAVE=0x102175070; X64_HOOKVA=0x101b06480; X64_ORIG="ff5028488b08"

archoff(){ lipo -detailed_info "$BIN" | awk -v a="$1" '$1=="architecture" && $2==a{f=1} f && $1=="offset"{print $2; exit}'; }
rd(){ sudo dd if="$BIN" bs=1 skip="$1" count="$2" 2>/dev/null | xxd -p | tr -d '\n'; }
wr(){ echo "$2" | xxd -r -p | sudo dd of="$BIN" bs=1 seek="$1" conv=notrunc 2>/dev/null; }

patch_arch(){ # arch cave_va hook_va orig stub hook  [oldhook oldbr oldorig]
    local arch=$1 cave_va=$2 hook_va=$3 orig=$4 stub=$5 hook=$6
    local ao; ao=$(archoff "$arch"); [ -n "$ao" ] || { echo "[$arch] no slice, skip"; return 0; }
    local cave=$(( ao + ($cave_va - TEXT_VM) )) hf=$(( ao + ($hook_va - TEXT_VM) ))
    if [ $# -ge 9 ]; then         # arm64 v1 hook cleanup
        local of=$(( ao + ($7 - TEXT_VM) ))
        [ "$(rd $of 4)" = "$8" ] && { echo "[$arch] undoing v1 hook"; wr $of "$9"; }
    fi
    local slen=$(( ${#stub} / 2 ))
    local hlen=$(( ${#hook} / 2 ))
    local curhook=$(rd $hf $hlen)
    local curcave=$(rd $cave $slen)
    if [ "$curhook" = "$hook" ] && [ "$curcave" = "$stub" ]; then
        echo "[$arch] already injected (current)"; return 0; fi
    if [ "$curhook" = "$hook" ]; then
        # hook present but cave differs (e.g. older stub) -> rewrite cave only
        echo "[$arch] refreshing cave stub ($slen bytes)"
        head -c $((slen+16)) /dev/zero | sudo dd of="$BIN" bs=1 seek="$cave" conv=notrunc 2>/dev/null
        wr $cave "$stub"; return 0; fi
    local orig_len=$(( ${#orig} / 2 ))
    local cur=$(rd $hf $orig_len)
    [ "$cur" = "$orig" ] || { echo "[$arch] ERROR hook bytes $cur != $orig; skip" >&2; return 1; }
    echo "[$arch] zeroing cave + writing stub ($slen bytes) + hook"
    head -c $((slen+16)) /dev/zero | sudo dd of="$BIN" bs=1 seek="$cave" conv=notrunc 2>/dev/null
    wr $cave "$stub"; wr $hf "$hook"
}

FAIL=0
patch_arch arm64  $A64_CAVE $A64_HOOKVA $A64_ORIG "$A64_STUB" "$A64_HOOK" $A64_OLD_HOOKVA "$A64_OLD_BR" "$A64_OLD_ORIG" || FAIL=1
patch_arch x86_64 $X64_CAVE $X64_HOOKVA $X64_ORIG "$X64_STUB" "$X64_HOOK" || FAIL=1

echo "==> Re-signing ad-hoc..."
sudo codesign --force --sign - "$BIN" 2>/dev/null || sudo codesign --force --deep --sign - "$APP"
sudo xattr -r -d com.apple.quarantine "$APP" 2>/dev/null || true
echo "Done (fail=$FAIL). Quit Windows App fully, relaunch, connect."
echo "Intel test under Rosetta:  arch -x86_64 '$BIN'   (then connect, check Transport Protocol)"
exit $FAIL
