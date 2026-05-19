# Palo Alto Firewall Manager

A WPF GUI wrapper around the [`pan-power`](https://www.powershellgallery.com/packages/pan-power) PowerShell module for managing a fleet of Palo Alto firewalls through Panorama — without ever logging into an individual firewall. Single file, no install — open in Windows PowerShell with `-STA` and go.

Based on scripts from Steve Borba's [PaloAltoNetworks](https://github.com/sjborbajr/PaloAltoNetworks/) repo and the [`pan-power`](https://www.powershellgallery.com/packages/pan-power) module. Credit to Steve for the API patterns this GUI unifies: Install-Software, User-ID check, ARP, IPsec, Routes, commit-lock removal, EDL refresh, and the general `Invoke-PANOperation` workflow.

---

## Requirements

- **Windows PowerShell 5.1** running with the STA apartment (`-STA` is required for WPF).
- The [`pan-power`](https://www.powershellgallery.com/packages/pan-power) module from the PowerShell Gallery.
- Network reach to Panorama on TCP/443.
- A Panorama admin account with API permissions (read for query operations, superuser/operator role if you'll commit, reboot, install software, or change HA priority).
- For the **Licenses** tab specifically: TCP/443 reachability to **each managed firewall's management IP**, not just Panorama. Licenses go direct firewall → workstation (Panorama refuses to proxy the license-info call).

Install the module once:

```powershell
Install-Module -Name pan-power -Scope CurrentUser
```

---

## Run

```powershell
PowerShell.exe -STA -File .\InstallUpdatesGUI.ps1
```

A debug log is written to `PANManager-debug.log` next to the script, truncated each session. Send it to whoever's helping you debug if something misbehaves — every fetch traces structured detail (exception type, raw response samples, regex match/miss).

### First-time flow

1. Enter the **Panorama IP**, your **Username**, your **Password**, and the **target software version** you want devices compared against (e.g. `11.1.13-h5`).
2. Click **Connect**. The status dot turns green on success and `Load Devices` becomes enabled. The same credentials get stashed in memory for the Licenses tab (which uses them to direct-keygen against each firewall).
3. Click **Load Devices**. Two phases happen:
   - **Phase 1** (~2 s): basic device info + HA state for all connected firewalls. Grid fills immediately.
   - **Phase 2** (background, sequential): full HA detail per device — priority, preemptive, sync, type. Roughly 1.5 s per device, so ~4 min for 150 devices. The status bar shows progress. This is a `pan-power` overhead, not a script bug — see "Known gotchas" below.
4. Filter the grid down to what you care about, **check the boxes** of the devices you want to act on, then click an action button in the bottom bar.

---

## The top bar (header)

| Field | Purpose |
|---|---|
| Panorama IP | Address of your Panorama controller. |
| User / Pass | Panorama admin credentials. Also reused for direct REST to firewalls when fetching Licenses. |
| Version | Target SW version used by **Exclude target ver** filter and the "Needs Update" quick-select. Devices not on this version are highlighted in orange. |
| **Connect** | Authenticate to Panorama. Green dot = success, red = failed (check log). |
| **Load Devices** | Pull the device list from Panorama. Enabled after Connect succeeds. |

---

## Filtering (under the header)

These filters affect the **Devices** grid and what counts as "selected" everywhere else.

| Control | Behavior |
|---|---|
| **Region** checkboxes (US / EU / AU / NZ / UK / CH / MFG / SHP) | Hostname-regex match. Multiple boxes are OR'd. Empty = all regions. |
| **HA State**: Active / Passive / Single | Filter by HA role. Single = standalone (no HA peer). Multiple checkboxes OR'd. Empty = all states. |
| **Exclude target ver** | Hides devices that already match the Version field. Useful for "only show devices that still need updating." |
| **Custom** | Free-text regex; rows matching the regex against hostname are shown. |
| **Excl** | Free-text regex; rows matching this regex are hidden. Excl wins over Custom. |
| **Apply** / **Clear** | Apply re-runs the filter; Clear resets all filter widgets. |

Row coloring:
- **Green background** = HA active
- **Orange-tinted background** = HA passive
- **Orange foreground** = on a software version other than the target
- **Bold** = currently checked/selected

---

## Quick-select buttons (right side, above the grid)

| Button | Effect |
|---|---|
| **All** | Check every visible row. |
| **None** | Uncheck every visible row. |
| **Active HA** | Check only visible rows with HA state = active. |
| **Passive HA** | Check only visible rows with HA state = passive. |
| **Single** | Check only visible rows with no HA peer. |
| **Needs Update** | Check only visible rows whose SW version ≠ target version. |
| **▶ Ping** | Start the ping loop. Pings every visible (filtered) row every 5 s. Shows `● UP` / `○ DOWN` and RTT in the Ping/Latency columns. |
| **■ Stop** | Stop the ping loop. |

---

## The bottom action bar

These buttons act on **selected (checked) rows** in the Devices grid. The single-flight gate means only one of these (or any fetch) can run at a time — if you click a second one while one's running, you'll see `[X] another fetch (Y) is in progress` in the log and the click is ignored.

### HA group

| Button | What it does | Confirmation? |
|---|---|---|
| ↻ **Refresh HA** | Re-pulls HA state/priority/sync for selected devices. | No |
| ↻ **Sync Config** | Pushes the active peer's running config to the passive peer. Only acts on selected devices that are currently active. | No |
| ⏸ **Suspend** | `request high-availability state suspend` on selected devices. **Suspending an active peer causes immediate failover to its passive peer.** Use sparingly. | Yes |
| ▶ **Resume** | `request high-availability state functional` — returns a suspended peer to election. | Yes |
| ⇈ **70 Force Primary** | Sets priority to 70 (emergency override). Use when the secondary needs to become primary right now. Always preemptive=yes. Performs a config commit. | No, but red label = destructive |
| ↑ **90 Primary** | Sets priority to 90 — the normal value for the primary peer. Always preemptive=yes, commits. | No |
| ↓ **110 Secondary** | Sets priority to 110 — the normal value for the secondary peer. Always preemptive=yes, commits. | No |
| ⇊ **130 Force Secondary** | Sets priority to 130 (emergency override). Use when the primary needs to step aside. Always preemptive=yes, commits. | No, but red label = destructive |

Operating model: **steady state is 90 / 110 with preempt=yes**. Use 70/130 only for short emergency role swaps; flip back to 90/110 afterward.

### SW (software install) group

| Button | What it does |
|---|---|
| 🔍 **Check & Download** | Asks each selected firewall for the target version's PAN-OS image and starts a download job. Updates the Download column with progress per device. |
| ↓ **Install** | Installs the (already downloaded) target version on each selected firewall. **Does not reboot** — Install button is for the install job only. |
| 🛈 **Job Status** | Polls outstanding download/install jobs per device and updates progress columns. |

### Cfg group

| Button | What it does |
|---|---|
| ✓ **Commit Selected** | `Invoke-PANCommit` on each selected device. Confirmation dialog, OK/fail counts logged. |

### Reboot (right-most)

| Button | What it does |
|---|---|
| ⚡ **Reboot Selected** | Sends `request restart system` to each selected device. Marks each as `Rebooting` in the Ping column and starts the **reboot auto-poller**: pings every 15 s and flips status to `● UP` when the device returns. Confirmation dialog warns if you've selected any non-passive devices (the active peer should be rebooted last). |

---

## Tabs

The main TabControl has the Devices grid plus 10 operations tabs. Every operations tab follows the same pattern:
- **Fetch (Selected)** queries the selected devices.
- **Fetch All** (or just **All**) queries every loaded device.
- **Export CSV** dumps the current grid contents.
- Status text on the right of the toolbar shows progress and completion counts.

### 🛡 Devices (default)

The main grid. Columns: Hostname, Model, Serial, IP, SW Version, HA State / Type / Sync / Priority / Preemptive, Ping / Latency, Download / Install (progress), Notes.

### 🔑 Licenses

Per-firewall license matrix: WildFire / DNS Security / URL Filtering / IoT Security / Threat Prevention / Support. Each cell shows expiry date, `Active` (non-expiring), `EXPIRED (date)` if past expiry, or `-` if the feature isn't present.

**This tab works differently from the others.** Panorama refuses to proxy `<request><license><info/></license></request>` to managed devices, so the script hits each firewall's management IP directly via REST. Parallelized with a runspace pool of 8. Requires:
- Workstation can reach each firewall's management IP on TCP/443 (the tab will report `TCP 443 not reachable` per device if it can't).
- Your Panorama credentials are also valid against the firewall directly (typically RADIUS / central auth setups work; Panorama-only local users won't).

### 👤 User-ID

Per-device User-ID health: IP-mapping count, agents total + connected, group-mapping count, any issues flagged. Useful for spotting firewalls where user-to-IP mapping has stopped working.

### 📡 ARP

ARP table from each selected device, with filter textbox (regex on IP or MAC). Use this to track down a MAC/IP without SSH'ing to every firewall.

### 🔒 IPsec

IPsec SAs (tunnel name, peer IP, gateway name, state, algorithm). Firewalls with zero tunnels are omitted from the grid.

### 🛣 Routes

Full routing table from each device, filter textbox (regex on destination prefix). Useful for "which firewall has a route to X.X.X.X?"

### 🔓 Locks

Commit-locks per device. Empty `name` entries are filtered out — they represent "no lock held". The **Remove ALL on Selected** button reverts any uncommitted config changes on the device side and clears every lock; confirmation dialog required.

### 📋 EDLs

Shared external-dynamic-lists from Panorama in a checkable list. **Refresh Checked on Selected Devices** forces each checked EDL to refresh on each selected firewall. Useful for "I just updated this threat list, push it out to all sites now."

### 📦 Content

Content-version matrix per device: App+Threat / AntiVirus / WildFire / URL DB / GlobalProtect Datafile / Uptime. Lets you spot devices that are behind on signatures.

### 📊 System

Live system resources per device: CPU% / Memory% / Disk% (root) / active session count / uptime. Parsed from the CDATA top-style output of `show system resources` plus `show system disk-space` and `show session info`. If CPU/Mem cells show `?` with `regex miss` notes, check `PANManager-debug.log` for the raw CDATA sample dumped for the first device — the regex may need updating for a newer PAN-OS top format.

### 📝 Commits

Last 25 commit jobs per device (admin who triggered it, queue/end timestamps, result). Useful for "who pushed config to this firewall and when?"

### 🌐 GP Users

Active GlobalProtect sessions, with filter textbox (matches username / computer / client IP / virtual IP / public IP). **Only the data-center firewalls run a GP gateway**, so this tab automatically restricts itself to the hardcoded DC list regardless of what you selected:

```
65028-US-IRV-FW01/02, 65031-US-CHI-FW01/02, 65093-AU-SY5-FW01/02,
65095-AU-BR1-FW01, 65135-EU-DUS-FW01/02, 65159-EU-FTS-FW01/02
```

Gateways with zero active users are hidden from results.

---

## Operation Log (bottom panel)

Live in-window log of every action. Every line is also mirrored to `PANManager-debug.log` (next to the script) so you have a persistent record across sessions. The trace file includes verbose detail that doesn't make it to the in-window log (full exception types, response XML samples, regex match info).

---

## How the GUI behaves

- **Single-flight fetches.** Only one fetch / bulk action can run at a time. The lock is process-global (a synchronized hashtable) and clears when the runspace's last UI action fires, success or failure. If you click while another is running, you'll see `[X] another fetch ('Y') is in progress - wait for it to finish` in the log and your click is ignored.
- **No silent crashes.** Every fetch runspace wraps its work in try/catch; exceptions land in the log AND the trace file with full type + message.
- **Live row updates.** `FirewallDevice` is a C# class implementing `INotifyPropertyChanged`, so per-device fields update in the grid as queries return without rebuilding rows.
- **Reboot auto-poller.** After clicking Reboot, every rebooting device gets pinged every 15 s. The first successful ping flips it from `Rebooting` to `● UP <rtt>`. Poller exits automatically when nothing's in Rebooting state.
- **Shutdown safety.** Closing the window stops the ping loop and reboot poller; Write-Log is defensive against the dispatcher being gone so closing during an active fetch doesn't spew red text.

---

## Architecture (the short version)

The script runs on a **single-runspace-per-button-click** model — Steve Borba's pattern. This is the only architecture that consistently works with `pan-power`; parallel-runspace and parallel-REST detours all hit module-state issues. The architecture is deliberate, not lazy. See [HANDOFF.md](./HANDOFF.md) for the rationale and the list of dead ends already explored.

- **One runspace per button click.** `[runspacefactory]::CreateRunspace()`, `ApartmentState='STA'`, `Open()`, then a sequential `foreach` over the selection.
- **Cross-thread UI updates** go through `$Window.Dispatcher.Invoke([action]{ ... }, 'Normal')`. No direct `$control.Text = …` from background runspaces.
- **Read queries** embed `&target=$serial` in the `Command` string: `<show>...</show>&target=<serial>`.
- **Writes / commits / reboot** use `-Target $serial` as a parameter to `Set-PANConfig` / `Invoke-PANCommit` / `Invoke-PANOperation`.
- **`FirewallDevice`** is a C# class (`Add-Type`) implementing `INotifyPropertyChanged`, so DataGrid bindings update live as the script mutates per-device fields.
- **`PingCtrl` / `RebootPollCtrl` / `FetchLock`** are `Hashtable.Synchronized` flags — the only cross-runspace control state.
- **TLS** is left alone process-wide. The Licenses tab uses a *compiled* `SSLAcceptAll::Validate` callback (Add-Type'd at script load) — NOT a PowerShell scriptblock — and saves/restores the ServicePointManager callback around its work so `pan-power`'s TLS state is never poisoned.

The "two different ways to target a device" detail (`&target=` vs `-Target`) **is real** and the script depends on it; do not refactor to one or the other. The OLD script established this contract and it works.

---

## File layout

```
InstallUpdatesGUI.ps1 (a.k.a. PANManager.ps1 locally)
├── #Requires / Imports / pan-power check / SSLAcceptAll Add-Type
├── Add-Type FirewallDevice + EDLEntry (C# with INotifyPropertyChanged)
├── [xml]$XAML  — WPF window definition (one big here-string)
├── Parse XAML  — XamlReader.Load, bind named controls
├── Global state  — AllDevices, DisplayColl, PingCtrl, RebootPollCtrl,
│                    FetchLock, PanCred (synchronized hashtable),
│                    DataCenterFWs (hardcoded GP gateway list)
├── Helpers  — Write-Log (file + UI), Write-Trace (file only),
│              Begin-Fetch, UI, Update-Stats, Apply-Filter, Set-ActionButtons
├── Button handlers  — Connect, LoadDevices, RefreshHA, SyncHA,
│                       Suspend/Resume, Pri70/90/110/130, CheckDl, Install,
│                       CheckJobs, Reboot, FetchLicenses (direct REST),
│                       FetchUserID/ARP/IPsec/Routes/Locks/EDL/Content/System/
│                       Commits/GP, ExportCSVs, Ping*, Sel*, Commit
├── Start-PingLoop function
├── Start-RebootPoller function
└── $Window.ShowDialog()
```

---

## Known gotchas

- **Always restart PowerShell between testing iterations.** Accumulated runspace state from failed runs corrupts the runtime — you'll see things like `Where-Object: command not found` at runtime, which is the shell, not your code. HANDOFF §5.3.
- **HA detail Phase 2 is slow** (~1.5 s per device × 150 devices ≈ 4 min). Phase 1 still shows HA state immediately because that comes back in the bulk `<show><devices><connected/>` response for free. If you need to fix this, the path is direct PAN-OS REST + a `RunspacePool(1, 12)` — see HANDOFF §5.2. Do **not** try to parallelize `pan-power` calls; that breaks the module's internal state (HANDOFF §6.1).
- **License fetch needs direct firewall reachability.** It will not work if your workstation can only reach Panorama. The tab logs `TCP 443 not reachable` per device when the route's missing.
- **License XML uses `request`, not `show`.** `<show><license/></show>` returns `show -> license is unexpected`; the API only exposes license info under `<request>`. If you copy commands from a PAN-OS CLI session, the API form is different.
- **Job Status after FIN** shows the finish timestamp in the progress field — cosmetic only, the job did finish. Treat any `FIN …%` reading as success.
- **Concurrent fetches are blocked, not queued.** If you click another fetch while one's running, the second click is dropped and a log message says so. Wait, click again.

---

## Recent changes

### Operations tabs (10 in total)

Goal: never log into an individual firewall. Each tab targets the device selection from the main **Devices** tab; results land in a tab-specific grid and can be exported to CSV.

| Tab | What it pulls | Source command |
|---|---|---|
| 🔑 **Licenses** | License feature × expiry matrix | `request license info` (direct to FW) |
| 👤 **User-ID** | Per-device IP-mapping count, agent total + connected, group count, issue flags | `show user ip-user-mapping all` / `user-id-agent statistics` / `group-mapping state all` |
| 📡 **ARP** | Every ARP entry across selected devices, filterable by IP/MAC regex | `show arp entry name=all` |
| 🔒 **IPsec** | IPsec SAs (tunnel name, peer, state, algorithm) | `show vpn ipsec-sa` |
| 🛣 **Routes** | Full routing table, filterable by destination prefix regex | `show routing route` |
| 🔓 **Locks** | Commit-locks per device + **Remove ALL on Selected** action | `show commit-locks vsys all`, `revert config`, `request commit-lock remove admin <x>` |
| 📋 **EDLs** | Shared EDLs in a checkable list; **Refresh Checked on Selected Devices** | `Get-PANConfig /config/shared/external-list`, `request system external-list refresh ...` |
| 📦 **Content** | App+Threat / AV / WildFire / URL DB / GP datafile versions + uptime | `show system info` |
| 📊 **System** | CPU% / Mem% / Disk% / session count per device | `show system resources` (CDATA), `show system disk-space`, `show session info` |
| 📝 **Commits** | Last 25 commit jobs per device (admin, time, status, result) | `show jobs all` filtered to commit-type |
| 🌐 **GP Users** | Active GlobalProtect sessions, filterable; auto-restricted to DC firewalls | `show global-protect-gateway current-user` |

All use the single-runspace-per-button architecture established for the existing operations — sequential `foreach` over devices, `Invoke-PANOperation -Target $serial`, dispatcher-marshaled UI updates. Licenses is the lone exception: direct REST + RunspacePool since Panorama won't proxy.

### Fetch serialization

Two `pan-power` runspaces can't run at the same time without corrupting the module's state. A single-flight gate (`$script:FetchLock`) is checked at the head of every fetch handler and cleared as the runspace's final UI action.

### HA action buttons

The HA action bar now includes emergency-failover controls alongside the priority buttons:

- **⏸ Suspend** — `request high-availability state suspend` on selected devices (triggers failover off an active peer).
- **▶ Resume** — `request high-availability state functional` (returns a suspended peer to election).
- **⇈ 70 Force Primary** — emergency override when the secondary needs to become primary. Red (destructive intent), preemptive=yes.
- **↑ 90 Primary** — normal primary priority.
- **↓ 110 Secondary** — normal secondary priority.
- **⇊ 130 Force Secondary** — emergency override when the primary needs to step aside. Red, preemptive=yes.

Normal operating state is **90 primary / 110 secondary** with preempt=yes; 70 and 130 are for emergency role swaps only.

### Bulk Commit

- **✓ Commit Selected** — runs `Invoke-PANCommit` on each selected device. Confirmation dialog, OK/fail counts in the log.

### Ping loop rewrite

Old version dispatched per-device updates with `BeginInvoke` and captured `$dev`/`$ss`/`$ll` by reference — by the time the dispatcher ran the scriptblock, the `foreach` had advanced and updates landed on the wrong device. New version snapshots `$DisplayColl` with `@(...)` on the UI thread, collects all results into a list, and pushes every update in **one synchronous** `Dispatcher.Invoke` at `Normal` priority.

### Reboot poller fix

Earlier version called `Start-RebootPoller` via `Dispatcher.Invoke` from inside the reboot runspace, but the dispatched scriptblock kept the runspace's lexical scope where the function is undefined — so it silently no-op'd. Now the poller starts from main scope after marking devices as `Rebooting`.

---

## Roadmap

Still planned (next batch): **active sessions tab** (query and clear sessions per firewall), cert-expiry tracker, BGP/OSPF peers tab, interface counters, session search, connectivity test (ping/traceroute from firewall).

---

## Authorship

- **Author:** Tadey Stasevych — <Tadey.Stasevych@jameshardie.com>
- **Based on:** Steve Borba's scripts at https://github.com/sjborbajr/PaloAltoNetworks/ (Install-Software, User-ID-check, ARP / IPsec / Routes, commit-lock removal, EDL refresh)

---

## License

No license declared in this repo. Treat as "internal tool, ask before reusing." Steve Borba's upstream scripts are also unlicensed — same caveat applies if you fork from there.
