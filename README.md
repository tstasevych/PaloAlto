# Palo Alto Firewall Manager

A WPF GUI wrapper around the [`pan-power`](https://www.powershellgallery.com/packages/pan-power) PowerShell module for managing Palo Alto firewalls through Panorama. Single file, no install — open in PowerShell with `-STA` and go.

Based on scripts from Steve Borba's [PaloAltoNetworks](https://github.com/sjborbajr/PaloAltoNetworks/) repo and the [`pan-power`](https://www.powershellgallery.com/packages/pan-power) module. Credit and thanks to Steve for the API patterns this GUI unifies: Install-Software, User-ID check, ARP, IPsec, Routes, commit-lock removal, EDL refresh, and the general `Invoke-PANOperation` workflow.

---

## What it does

- Connects to Panorama, lists every connected firewall in a dark-themed `DataGrid`.
- Shows per-device **HA State / Type / Sync / Priority / Preemptive** and **SW Version**.
- **Filter** by region (US/EU/AU/NZ/UK/CH/MFG/SHP), HA state, target SW version, or hostname regex.
- **Quick-select** All / Active HA / Passive HA / Single / Needs Update.
- **Bulk-execute** against the selection:
  - Refresh HA, Sync HA Config
  - Set HA Priority (70 / 90 / 110 / 130) with preemptive always `yes`
  - Check & Download software, Install, Job Status, Reboot
- **Ping loop** — parallel `Ping.SendPingAsync` over the displayed rows, refreshed every 5 s.
- **Reboot auto-poller** — after Reboot, pings rebooting devices every 15 s and flips them to `● UP` when they return.
- **Licenses tab** — per-firewall matrix showing expiry for WildFire / DNS Security / URL Filtering / IoT / Threat Prev / Support.
- **CSV export** for devices and the license matrix.

---

## Requirements

- **Windows PowerShell 5.1** (STA apartment — `-STA` is required for WPF).
- The [`pan-power`](https://www.powershellgallery.com/packages/pan-power) module from PSGallery.
- Network access to Panorama on HTTPS, plus a Panorama account with API permissions.

Install the module once:

```powershell
Install-Module -Name pan-power -Scope CurrentUser
```

---

## Run

```powershell
PowerShell.exe -STA -File .\InstallUpdatesGUI.ps1
```

Then in the GUI:

1. Enter the Panorama IP, username, password, and target SW version (e.g. `11.1.13-h5`).
2. Click **Connect** — the status dot turns green on success.
3. Click **Load Devices**. Phase 1 populates the grid with basic info + HA state in ~2 s; Phase 2 fills in HA detail per device sequentially in the background (can take several minutes for 150+ devices — this is a `pan-power` overhead, not a script bug).
4. Filter, select, then click an action button.

---

## Architecture (short version)

The script runs on a single-runspace-per-button-click model — Steve Borba's pattern. This is the only architecture that consistently worked with `pan-power`; parallel-runspace and parallel-REST detours all hit module-state issues. The architecture is deliberate, not lazy. See [HANDOFF.md](./HANDOFF.md) for the rationale and a tour of every dead end we hit so far.

- **One runspace per button click** — `[runspacefactory]::CreateRunspace()`, `ApartmentState='STA'`, `Open()`, then a sequential `foreach` over the selection.
- **Cross-thread UI updates** go through `$Window.Dispatcher.Invoke([action]{ ... }, 'Normal')`. No direct `$control.Text = …` from runspaces.
- **Read queries** embed `&target=$serial` in the `Command` string (`<show>...</show>&target=<serial>`).
- **Writes / commits / reboot** use `-Target $serial` as a parameter to `Set-PANConfig` / `Invoke-PANCommit` / `Invoke-PANOperation`.
- **`FirewallDevice`** is a C# class (`Add-Type`) implementing `INotifyPropertyChanged`, so DataGrid bindings update live as the script mutates per-device fields.
- **`PingCtrl` / `RebootPollCtrl`** are `Hashtable.Synchronized` flags — the only cross-runspace control state.

The "two different ways to target a device" detail (`&target=` vs `-Target`) **is real** and the script depends on it; do not refactor to one or the other. The OLD script established this contract and it works.

---

## File layout

```
PANManager.ps1 (a.k.a. InstallUpdatesGUI.ps1 on GitHub)
├── #Requires / Imports / pan-power check
├── Add-Type FirewallDevice (C# with INotifyPropertyChanged)
├── [xml]$XAML  — WPF window definition (one big here-string)
├── Parse XAML  — XamlReader.Load, bind named controls
├── Global state  — AllDevices, DisplayColl, PingCtrl, RebootPollCtrl
├── Helpers  — Write-Log, UI, Update-Stats, Apply-Filter, Set-ActionButtons
├── Button handlers  — Connect, LoadDevices, RefreshHA, SyncHA,
│                       Pri70/90/110/130, CheckDl, Install, CheckJobs,
│                       Reboot, FetchLicenses, ExportCSVs, Ping*, Sel*
├── Start-PingLoop function
├── Start-RebootPoller function
└── $Window.ShowDialog()
```

---

## Known gotchas

- **Always restart PowerShell between testing iterations.** Accumulated runspace state from failed runs corrupts the runtime — you'll see things like `Where-Object: command not found` at runtime, which is the shell, not your code.
- **HA detail Phase 2 is slow** (~1.5 s per device × 150 devices ≈ 4 min). Phase 1 still shows HA state immediately because that comes back in the bulk `<show><devices><connected/>` response for free. If you need to fix this, the path is direct PAN-OS REST + a `RunspacePool(1, 12)` — see HANDOFF section 5.2. Do **not** try to parallelize `pan-power` calls; that breaks the module's internal state.
- **`Job Status` after FIN** shows the finish timestamp in the progress field — cosmetic only, the job did finish. Treat any `FIN …%` reading as success.

---

## Recent changes

### Operations tabs (10 in total)

Goal: never log into an individual firewall. Each tab targets the device selection from the main **Devices** tab; results land in a tab-specific grid and can be exported to CSV.

| Tab | What it pulls | Source command |
|---|---|---|
| 🔑 **Licenses** | License feature × expiry matrix | `show license info` |
| 👤 **User-ID** | Per-device IP-mapping count, agent total + connected, group count, issue flags | `show user ip-user-mapping all` / `user-id-agent statistics` / `group-mapping state all` |
| 📡 **ARP** | Every ARP entry across selected devices, filterable by IP/MAC regex | `show arp entry name=all` |
| 🔒 **IPsec** | IPsec SAs (tunnel name, peer, state, algorithm) | `show vpn ipsec-sa` |
| 🛣 **Routes** | Full routing table, filterable by destination prefix regex | `show routing route` |
| 🔓 **Locks** | Commit-locks per device + **Remove ALL on Selected** action | `show commit-locks vsys all`, `revert config`, `request commit-lock remove admin <x>` |
| 📋 **EDLs** | Shared EDLs in a checkable list; **Refresh Checked on Selected Devices** | `Get-PANConfig /config/shared/external-list`, `request system external-list refresh ...` |
| 📦 **Content** | App+Threat / AV / WildFire / URL DB / GP datafile versions + uptime | `show system info` |
| 📊 **System** | CPU% / Mem% / Disk% / session count per device | `show system resources` (CDATA), `show system disk-space`, `show session info` |
| 📝 **Commits** | Last 25 commit jobs per device (admin, time, status, result) | `show jobs all` filtered to commit-type |
| 🌐 **GP Users** | Active GlobalProtect sessions, filterable | `show global-protect-gateway current-user` |

All use the single-runspace-per-button architecture established for the existing operations — sequential `foreach` over devices, `Invoke-PANOperation -Target $serial`, dispatcher-marshaled UI updates. No new concurrency model.

### HA action buttons

The HA action bar now includes emergency-failover controls alongside the priority buttons:

- **⏸ Suspend** — `request high-availability state suspend` on selected devices (triggers failover off an active peer).
- **▶ Resume** — `request high-availability state functional` (returns a suspended peer to election).
- **⇈ 70 Force Primary** — emergency override when the secondary needs to become primary. Red (destructive intent), preemptive=yes.
- **↑ 90 Primary** — normal primary priority.
- **↓ 110 Secondary** — normal secondary priority.
- **⇊ 130 Force Secondary** — emergency override when the primary needs to step aside. Red, preemptive=yes.

Normal operating state is **90 primary / 110 secondary** with preempt=yes; 70 and 130 are for emergency role swaps only.

### Cfg action

- **✓ Commit Selected** — runs `Invoke-PANCommit` on each selected device. Confirmation dialog, OK/fail counts in the log.

### Earlier changes

- **License fetch — diagnostics + fallbacks.** Tries `&target=` embedded, then `-Target` parameter, then `<info></info>` non-self-closing; walks four candidate response shapes; on first failure dumps the raw XML prefix / property names so we can pin down what Panorama actually returned.
- **Priority 70 button** added. Order in the action bar: 70 → 90 (1°) → 110 (2°) → 130 (3°).
- **Preemptive is now always `yes`** when setting any priority. Previously, only Priority 90 stayed preemptive and 110 / 130 flipped to `no`, which defeats priority-based failover recovery.
- **Ping loop rewrite.** Old version dispatched per-device updates with `BeginInvoke` and captured `$dev`/`$ss`/`$ll` by reference — by the time the dispatcher ran the scriptblock, the `foreach` had advanced and updates landed on the wrong device. New version snapshots `$DisplayColl` with `@(...)` on the UI thread, collects all results into a list, and pushes every update in **one synchronous** `Dispatcher.Invoke` at `Normal` priority.

## Roadmap

Still planned (next batch): cert-expiry tracker, BGP/OSPF peers tab, interface counters, session search, connectivity test (ping/traceroute from firewall), clear-sessions dialog.

---

## Authorship

- **Author:** Tadey Stasevych — <Tadey.Stasevych@jameshardie.com>
- **Based on:** Steve Borba's `Install-Software.ps1` — https://github.com/sjborbajr/PaloAltoNetworks/blob/main/Install-Software.ps1

---

## License

No license declared in this repo. Treat as "internal tool, ask before reusing." Steve Borba's upstream script is also unlicensed — same caveat applies if you fork from there.
