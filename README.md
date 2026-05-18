# winapp-udp-unlock

Force Microsoft's "Windows App" on macOS to use MS-RDPEUDP for direct RDP, not just for Azure Virtual Desktop and Cloud PC.

Windows App already contains a full UDP multi-transport implementation. It's gated at runtime to activate only for Azure Virtual Desktop and Cloud PC sessions. For direct RDP to your own Windows hosts, the client silently falls back to TCP, which on long-RTT paths gets crushed by the TCP BDP window ceiling.

This repo removes the gate with a single 4-byte NOP.

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

The patch NOPs the `cbz w0, <skip>` after the `IsWvdConnection()` call. The user-preference arm is left intact — the feature still only activates when the user opts in.

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
| `auto-patch.sh` | Patches the installed Windows App. Backs up to `/Applications/Windows App.app.bak` first. Locates the gate by instruction pattern, not hardcoded offset — survives minor recompiles. |
| `revert.sh` | Restores the `.bak` whole-bundle backup. |
| `find-udp-gate.py` | Ghidra post-script. Locates the gate using only the invariant string `"EnableUdpSideTransport"` — does not depend on mangled C++ symbols or branch positions. For when `auto-patch.sh` can't. |
| `INVESTIGATION.md` | Full methodology to rediscover the patch site from scratch against any future version. |

## When Microsoft ships an update

Your patch gets overwritten. Re-run `./auto-patch.sh`. If it fails (pattern matcher no longer recognizes the gate), fall through to Ghidra with `find-udp-gate.py` — instructions in `INVESTIGATION.md`.

## Caveats

- **EULA.** Patching Microsoft's signed binary isn't blessed by Microsoft. Use on machines you own.
- **Signature.** `auto-patch.sh` ad-hoc re-signs the bundle. Gatekeeper still launches it, but the signature is no longer notarized. Library-validation-enforcing entitlements may reject it (none observed so far).

## License

Unlicense / public domain. No warranty. If it bricks your /Applications, restore from `revert.sh` or reinstall from the App Store.
