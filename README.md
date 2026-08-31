# winapp-udp-unlock

Force Microsoft's "Windows App" on macOS to use MS-RDPEUDP for direct RDP, not just for Azure Virtual Desktop and Cloud PC.

Windows App already contains a full UDP multi-transport implementation. It's gated at runtime to activate only for Azure Virtual Desktop and Cloud PC sessions. For direct RDP to your own Windows hosts, the client silently falls back to TCP, which on long-RTT paths gets crushed by the TCP BDP window ceiling.

This repo removes the gate by NOPing one conditional branch per architecture slice (a 4-byte `cbz` on arm64, a 6-byte `je` on x86_64).

> **Confirmed working on Windows App 11.3.5, 11.3.6, 11.3.7, 11.3.9, and 11.4.0.** The pattern-based locator in `auto-patch.sh` re-patched each Microsoft update with no script changes.
>
> **Apple Silicon and Intel.** Windows App is a universal binary; `auto-patch.sh` patches every slice present (arm64 and x86_64), so the fix works on both. The x86_64 patch was verified by running the patched slice under Rosetta 2 on Apple Silicon.

## Before / after on a 151 ms RTT path

| | Before | After |
|---|---|---|
| Transport | TCP | UDP (Private) |
| Available Bandwidth | **807 Kbps** | **93.12 Mbps** |
| Measured RTT | 195 ms | 151 ms |

~115× effective throughput, same network, same host.

## The gate

Inside `-[RDCConnectionSettings(RdpConnectionSettings) asConnectionSettingsEx]`:

```c
if (self->_enableAvdUdpSideTransport == 1 && IsWvdConnection()) {
    // set "EnableUdpSideTransport" = true in the core property bag
    // set "EnableIce", "EnableMouseCursorDVC", etc.
}
```

The patch NOPs the conditional branch after the `IsWvdConnection()` call — `cbz w0, <skip>` on arm64, `je <skip>` (a 6-byte `0F 84` near jump) on x86_64. The user-preference arm (the `_enableAvdUdpSideTransport == 1` check, which is its own branch just before) is left intact — the feature still only activates when the user opts in.

## Quick start

**1. Windows host** (PowerShell as admin, once):
```powershell
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
  -Name SelectTransport -Value 0 -Type DWord
Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -Name SelectTransport, fDisableUDP -ErrorAction SilentlyContinue
Restart-Service TermService -Force
```
Also verify UDP 3389 inbound is allowed in the firewall.

**2. Mac, one-time:**
```bash
defaults write com.microsoft.rdc.macos ClientSettings.EnableAvdUdpSideTransport -bool true
```
Grant your terminal **App Management** permission: System Settings → Privacy & Security → App Management → enable Terminal / iTerm2 / Ghostty / ...

**3. Apply:**
```bash
./auto-patch.sh
```

**4. Relaunch Windows App and reconnect.** Connection Information → Transport Protocol should read `UDP (Private)`.

Verify with `sudo tcpdump -ni any "udp and host <server-ip> and port 3389"` — you should see bidirectional UDP during and throughout the session.

## Contents

| File | Purpose |
|---|---|
| `auto-patch.sh` | Patches the installed Windows App — every arch slice present (arm64 + x86_64). Backs up to `/Applications/Windows App.app.bak` first, and refreshes that backup if it's from an older app version (so revert can't downgrade you). Locates the gate by instruction pattern, not hardcoded offset — survives minor recompiles. |
| `revert.sh` | Restores the `.bak` whole-bundle backup and verifies the original branch is back on every slice (version/arch-independent). |
| `find-udp-gate.py` | Ghidra post-script. Locates the gate using only the invariant string `"EnableUdpSideTransport"` — does not depend on mangled C++ symbols or branch positions. For when `auto-patch.sh` can't. |
| `INVESTIGATION.md` | Full methodology to rediscover the patch site from scratch against any future version. |

## When Microsoft ships an update

Your patch gets overwritten. Re-run `./auto-patch.sh`. If it fails (pattern matcher no longer recognizes the gate), fall through to Ghidra with `find-udp-gate.py` — instructions in `INVESTIGATION.md`.

## Caveats

- **EULA.** Patching Microsoft's signed binary isn't blessed by Microsoft. Use on machines you own.
- **Signature.** `auto-patch.sh` ad-hoc re-signs the bundle. Gatekeeper still launches it, but the signature is no longer notarized. Library-validation-enforcing entitlements may reject it (none observed so far).

## License

Unlicense / public domain. No warranty. If it bricks your /Applications, restore from `revert.sh` or reinstall from the App Store.
