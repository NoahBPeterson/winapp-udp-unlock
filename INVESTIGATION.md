# Enable MS-RDPEUDP on Windows App for direct (non-AVD) RDP — runbook

This is a version-independent recipe. It assumes no prior knowledge of the
specific byte offsets or symbol names — those change with every Microsoft
release. The only thing it relies on is that the C++ RDP core still reads a
property-bag key named literally `"EnableUdpSideTransport"`.

## Prerequisites (one-time, unrelated to updates)

- Windows host: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SelectTransport = 0`, no conflicting GPO, UDP 3389 inbound allowed in firewall, `Restart-Service TermService`.
- Mac: `defaults write com.microsoft.rdc.macos ClientSettings.EnableAvdUdpSideTransport -bool true`
- Mac: Terminal (or Ghostty/iTerm/etc.) granted App Management in System Settings → Privacy & Security, so root can modify signed bundles in /Applications.
- Mac: Ghidra with PyGhidra installed, or any other decompiler (IDA, Hopper, Binary Ninja).

## Investigation (per Microsoft release)

The goal is to find the conditional branch that, for non-AVD connections, skips the code that sets the `"EnableUdpSideTransport"` key in the property bag, and NOP it.

### Step 1 — Confirm the invariant string exists

```bash
lipo -thin arm64 "/Applications/Windows App.app/Contents/MacOS/Windows App" -output /tmp/ws.arm64
strings /tmp/ws.arm64 | grep -x EnableUdpSideTransport
```
If absent, Microsoft removed the feature entirely; different problem.

### Step 2 — Import into Ghidra, auto-analyze

Headless:
```bash
~/Downloads/ghidra_12.0.3_PUBLIC/support/pyghidraRun -H \
  /tmp/ghidra-proj WindowsApp -import /tmp/ws.arm64
```
~30–60 min.

### Step 3 — Find the WRITE of `"EnableUdpSideTransport"` to the property bag

Run the locator script (saved alongside this runbook, `find-udp-gate.py`) as a headless Ghidra post-script, OR do it manually:

1. In Ghidra, search for defined string `"EnableUdpSideTransport"`.
2. List xrefs. Typically 2–3 hits.
3. Decompile each containing function. You're looking for the one that **writes** the string as a map key (pattern: something like `__tree::__emplace_unique_key_args(..., "EnableUdpSideTransport", ...)` followed by assigning `*(lVar + 0x38) = 1`). The other xrefs will be **reads** (pattern: `GetProperty<bool>(..., "EnableUdpSideTransport")`).

The writer is the target function. In the current version it's `-[RDCConnectionSettings(RdpConnectionSettings) asConnectionSettingsEx]`; the name will change if Microsoft renames or refactors, but the pattern (inserting the string into an std::map of property variants) is stable.

### Step 4 — Identify the outermost conditional that can skip the write

In the decompiler, the write will be inside one or more `if` blocks. Walk outward until you find the outermost `if` whose false-branch skips past the entire block of property-bag writes that includes `"EnableUdpSideTransport"` (as well as `"EnableIce"`, `"IceInitializationOptions"`, etc. — they're grouped together).

In the current version, that outermost conditional is a **compound**: `enableAvdUdpSideTransport_ivar == 1 && IsWvdConnection() != 0`. You want to eliminate **only the WVD part** (the user-pref part is fine — it gates the feature correctly).

In the disassembly, this compound appears as two consecutive short-circuit branches, e.g.:

```
  ldrb   wN, [x?, #<ivar-offset>]   ; load enableAvdUdpSideTransport ivar
  cmp    wN, #0x1
  b.ne   <skip_udp_block>             ; BRANCH A — leave this alone
  ldr    x0, [x?, #<sibling-ivar>]
  bl     <IsWvdConnection>            ; return bool
  cbz    w0, <skip_udp_block>          ; BRANCH B — NOP this
  <first write to "EnableUdpSideTransport" begins here>
```

Identify Branch B by these combined signals:
- It's a `cbz w0` (or `cbnz`) immediately after a `bl` to a function that takes one pointer arg and returns a bool.
- Its branch destination address is the same as Branch A's destination (both short-circuit to the same "skip" label).
- The fall-through instructions below it contain a reference to the literal string `"EnableUdpSideTransport"` within ~30 instructions.

The third criterion is the strongest identifier — use it to verify.

### Step 5 — Compute the fat-file offset and patch

```bash
TARGET_VA=0x????????  # the VA of Branch B from Ghidra
FAT_BIN="/Applications/Windows App.app/Contents/MacOS/Windows App"
ARM64_OFF=$(lipo -detailed_info "$FAT_BIN" | awk '$1=="architecture" && $2=="arm64" {f=1} f && $1=="offset" {print $2; exit}')
SLICE_BASE=0x100000000   # standard for arm64 Mach-O __TEXT
FAT_OFF=$((ARM64_OFF + TARGET_VA - SLICE_BASE))

# Verify current bytes look like cbz/cbnz w0 (trailing byte 0x34 or 0x35)
sudo dd if="$FAT_BIN" bs=1 skip=$FAT_OFF count=4 2>/dev/null | xxd -p

# Apply NOP
printf '\x1f\x20\x03\xd5' | sudo dd of="$FAT_BIN" bs=1 seek=$FAT_OFF count=4 conv=notrunc
```

### Step 6 — Re-sign and verify

```bash
APP="/Applications/Windows App.app"
sudo codesign --force --deep --sign - "$APP"
sudo codesign -v "$APP"
sudo xattr -r -d com.apple.quarantine "$APP" 2>/dev/null || true
otool -arch arm64 -tV "$APP/Contents/MacOS/Windows App" | grep -A1 "$TARGET_VA"
# expect: nop
```

### Step 7 — Runtime verify

1. Reconnect to the Windows host.
2. `sudo tcpdump -ni any "udp and host <server-ip> and port 3389" -c 30` should show bidirectional UDP.
3. Connection Information panel: Transport Protocol should eventually read `UDP (Private)`.

## Failure modes and adaptations

- **String not found** → Microsoft removed UDP side-transport entirely. The feature isn't there to enable.
- **String only referenced as READ, never WRITE** → writer path got inlined, moved into another binary (e.g., a dylib in `Contents/Frameworks`), or guarded differently. Widen the search to those.
- **Write exists but no conditional gates it** → the feature already works; you don't need a patch. Verify server config and user pref first.
- **Multiple conditionals gate it** → NOP the outermost one only. Test. If still gated, extend the patch inward.
- **Compound is rewritten as a function call** (e.g., `if (ShouldEnableUdp())`) → find the implementation of that predicate and patch it to return true.
