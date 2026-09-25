#!/bin/bash
# deep-patch.sh — 11.4.x UDP side-transport injection (arm64 + x86_64).
#
# Thin wrapper over deep-patch.py. NOTHING is hardcoded to a build: the patcher discovers the
# code cave, the TsUdpTransport::Connect hook site, the fabricated SideTransportCreationParams
# object's vtables/size/init-constant/field layout, and every call target from the pristine
# binary itself (nm symbol table + capstone disassembly of Connect and the producer), then
# generates the stub per build. This is why it survives Microsoft updates the way auto-patch.sh
# does — re-run it after any update and it re-derives everything.
#
# Requires auto-patch.sh (the gate NOP) applied first. Run as your normal user; the Python
# shells out to sudo only for the two privileged steps (writing the binary, re-signing), so it
# prompts for your password once. Reversible via revert.sh.
#
# Dependency: capstone  (pip3 install capstone)
# Verified: arm64 live (UDP Private); x86_64 under Rosetta 2.  Pass --dry to preview without writing.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 -c 'import capstone' 2>/dev/null || {
    echo "deep-patch needs the 'capstone' module:  pip3 install capstone" >&2; exit 1; }
exec python3 "$DIR/deep-patch.py" "$@"
