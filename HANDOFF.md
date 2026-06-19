# Palo Alto Firewall Manager — Project Handoff

> Handoff document for continuing work on `PANManager.ps1`. Read this fully before making changes.

---

## 1. Origin & Attribution

- **Based on:** Steve Borba's `Install-Software.ps1`
  https://github.com/sjborbajr/PaloAltoNetworks/blob/main/Install-Software.ps1
- **Owner:** Tadey Stasevych <Tadey.Stasevych@jameshardie.com>
- **Target environment:** Windows PowerShell **5.1**, STA apartment, WPF, `pan-power` module from PSGallery
- **Run command:** `PowerShell.exe -STA -File PANManager.ps1`
- **Repo target:** user intends to push this to GitHub

The script header in `PANManager.ps1` already credits Steve Borba. Preserve that.

---

## 2. What This Script Is

A WPF GUI wrapper around `pan-power` for managing Palo Alto firewalls via Panorama:

- Connect to Panorama (`Invoke-PANKeyGen`)
- Load all connected devices into a dark-themed `DataGrid`
- See HA State / Type / Sync / Priority / Preemptive
- Filter by region (US/EU/AU/NZ/UK/CH/MFG/SHP), HA state, target SW version, hostname regex
- Bulk-select (All / Active HA / Passive HA / Single / Needs Update)
- Bulk-execute: Refresh HA, Sync HA Config, Set HA Priority (90/110/130), Check & Download software, Install, Job Status, Reboot
- Background Ping loop (parallel `Ping.SendPingAsync`) for selected/displayed rows
- **License matrix** (new): per-firewall row × license-type column showing expiry for WildFire / DNS Security / URL Filtering / IoT Security / Threat Prev / Support
- After Reboot, an auto-poller pings rebooting devices every 15 s and flips them to `● UP` when they come back

---

## 3. Architecture — What Works and Why

After many failed attempts at parallelism, we settled on **the original architecture** from Steve Borba's script:

- **One runspace per button click**, opened with `[runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()`.
- Inside the runspace: `Import-Module pan-power -ErrorAction SilentlyContinue`, then a sequential `foreach` over the selected devices.
- Cross-thread UI updates go through `$Window.Dispatcher.Invoke({...}, 'Normal')` (wrapped in a `UI {}` helper inside each runspace's body).
- Variables passed to runspaces with `SessionStateProxy.SetVariable()`; functions via `${function:Write-Log}`.
- For per-firewall PAN-OS operations, **`&target=$serial` is embedded in the `-Command` string** (e.g. `("<show>...</show>&target=" + $dev.Serial)`). The OLD script uses this and it works. Do **not** switch to `-Target $serial` — see "Dead Ends" below.
- For write/commit ops, `Set-PANConfig -Target $serial`, `Invoke-PANCommit -Target $serial`, `Invoke-PANOperation -Target $serial` for **Reboot** specifically all work via the `-Target` parameter because the OLD script does it that way.
- Custom C# class `FirewallDevice` implements `INotifyPropertyChanged`, so property assignments fire `PropertyChanged` and WPF DataGrid bindings update live.
- `ObservableCollection[object]` for `DisplayColl` (bound to both Devices tab and Licenses tab).
- `Hashtable.Synchronized` for cross-runspace control flags (`PingCtrl`, `RebootPollCtrl`).

### File layout (single file)

```
PANManager.ps1
├── #Requires / Imports / pan-power check
├── Add-Type FirewallDevice class (C# with INotifyPropertyChanged)
├── [xml]$XAML = @'…'@        (WPF window definition)
├── $Window = XamlReader.Load   (parse XAML)
├── Ctrl() helper + bind all named controls to $vars
├── $script:AllDevices / $script:DisplayColl / $script:PingCtrl / $script:RebootPollCtrl
├── Helpers: Write-Log, UI, Update-Stats, Apply-Filter, Set-ActionButtons
├── Button click handlers (Connect, LoadDevices, RefreshHA, SyncHA, Pri90/110/130,
│                          CheckDl, Install, CheckJobs, Reboot, FetchLicenses, ExportCSVs,
│                          PingStart, PingStop, ApplyFilter, ClearFilter, Sel*)
├── Start-PingLoop function
├── Start-RebootPoller function
└── [void]$Window.ShowDialog()
```

---

## 4. Current State Summary

| Feature | Status | Notes |
|---|---|---|
| Connect | ✅ Works | Tries `-Credentials`, `-Credential`, then no-cred; logs which succeeded |
| Load Devices (basic info + HA state in <2 s) | ✅ Works | Pulls `<ha><state>` from the bulk `<show><devices><connected>` response |
| Load Devices (full HA detail) | ⚠ Slow | Phase 2 per-device queries take ~4 min for 151 devices — pan-power overhead |
| Refresh HA on selection | ✅ Works | Sequential per device |
| Sync HA Config | ✅ Works | |
| Set Priority (90/110/130) + Commit | ✅ Works (untested at scale) | Uses `Set-PANConfig -Target` + `Invoke-PANCommit -Target` |
| Check & Download | ✅ Works | Per-device sequential. Logs PAN error msg if rejected. |
| Install | ✅ Works (untested at scale) | Same pattern as Check & Download. |
| Job Status | ✅ Works | Manual button. Cosmetic issue: when job is FIN, PAN returns finish *timestamp* in `progress` field → displays as `FIN 2026/05/18 04:52:27%`. Cosmetic only. |
| Reboot | ✅ Works | Uses `-Target $serial`. Sets device PingStatus='Rebooting'. Auto-starts reboot poller. |
| Reboot auto-poller | ✅ Works (last tested as-coded) | Pings rebooting devices every 15 s; flips to `● UP` when they respond. |
| Ping loop | ⚠ See section 5 | Last known issue: crashed 1 s after Start; latest version has full error logging in place |
| Filters / quick-select | ✅ Works | |
| License matrix | ✅ Works | Fetch Licenses (Selected) / Fetch All. Per-device sequential. Regex matches feature names to columns. |
| Export CSVs (devices & license matrix) | ✅ Works | |

---

## 5. Outstanding Issues

### 5.1 Ping loop crashing after ~1 second — needs diagnostic data

Last user test showed:

```
[06:55:05] ▶ Ping loop started (every 5 s).
[06:55:06] ⏹ Ping loop stopped.
```

The current code now wraps the runspace body in `try/catch/finally` with explicit logging:

- Outer `catch` logs `✘ Ping loop CRASHED: <TypeName>: <message>` + first three stack frames.
- Per-iteration `try/catch` logs `✘ Ping cycle N error: ...` so a single bad ping doesn't kill the loop.
- Cycle counter in stop message: `⏹ Ping loop stopped (after N cycle(s)).`

**Next step:** user needs to run the latest version in a fresh PowerShell process and paste the log around the crash so we can see the actual exception. Likely suspects:

- `UISync { foreach ($d in $DisplayColl) ... }` throwing `Collection was modified` if Apply-Filter or another runspace is modifying `DisplayColl` mid-iteration.
- `[System.Net.NetworkInformation.Ping]` exhausting handles when 151 devices are pinged in parallel.
- Concurrent `RebootPoller` and `PingLoop` racing each other through the dispatcher.

### 5.2 Performance — 4 minutes to load 151 devices is too slow

Root cause: `Invoke-PANOperation` (pan-power) is slow per call, ~1.5 s overhead each. 151 devices × 1.5 s = 4 min just for HA queries.

**Options the user is aware of:**

- **A.** Leave as-is. Phase 1 is fast (2 s) and shows HA State; full HA detail only on demand.
- **B.** Bypass pan-power for read queries — use direct PAN-OS REST (`Invoke-RestMethod` with `&target=$serial&key=$apiKey`) and parallelize with `RunspacePool` (12-way). Would cut full HA load to ~20 s. Requires acquiring a REST API key on Connect alongside the pan-power keygen.
- **C.** Keep slow sequential — user has explicitly rejected this.

The codebase currently implements **A** (Phase 1 = basic HA from bulk response; Phase 2 = sequential per-device for the detail columns).

### 5.3 PowerShell session corruption

During iteration, the user hit `Where-Object: command not found` errors at runtime. This is **PowerShell runtime corruption** from accumulated runspace failures, NOT a code bug. Documented for awareness — **always restart PowerShell** after a series of failed test runs.

---

## 6. Dead Ends — Things That Don't Work (DO NOT REPEAT)

### 6.1 Parallel runspaces via `Start-PANParallel`

Tried: N concurrent runspaces, each importing pan-power, each calling `Invoke-PANOperation`. **Result:** Empty/null responses. Hypothesis: pan-power has per-runspace module state that isn't initialized correctly when many runspaces import simultaneously. Reverted.

### 6.2 `-Target $serial` parameter on `Invoke-PANOperation` for read queries

Tried: passing `-Target $serial` as a parameter instead of embedding `&target=` in the Command string. **Result:** Response shape differs (deeper nesting), and `$ha.result.group` returned `$null` for all devices. The OLD script uses `&target=` embedded for **reads** and `-Target` for **writes/commits/reboot** — that distinction is real and must be preserved.

### 6.3 Direct REST keygen detour

Tried: acquire a separate REST API key on Connect and use `Invoke-RestMethod` for HA/license fetches. Added complexity, didn't actually fix the HA issue (the issue was the `-Target` parameter; once we reverted to `&target=` embedded, HA started working again). Reverted, but **this is the right path for the speed problem** (section 5.2 option B).

### 6.4 Job-poller queue ping-pong

Tried: runspace enqueues `RequestSnapshot`, UI tick dequeues it, processes, enqueues `Snapshot` back, runspace dequeues it. **Bug:** UI tick's `while ($pq.TryDequeue(...))` loop continued past `RequestSnapshot` and re-dequeued the `Snapshot` it just enqueued, hit no matching `switch` case, dropped it silently. Runspace timed out waiting. Replaced with synchronous `Dispatcher.Invoke` from the runspace to fetch snapshots directly — no queue ping-pong.

### 6.5 `Start-Sleep` on UI thread in button handlers

Tried: force-reset of stuck `PingCtrl.Running` flag with `Start-Sleep -Milliseconds 100` in a loop. **Bug:** Button click handlers run on the UI thread; sleeping there freezes the GUI for up to 2 s. Removed.

### 6.6 Filtering ping to selected-only with no fallback

Tried: ping only `$_.Selected -and $_.IPAddress` devices. **Bug:** If user clicks Ping without selecting anything, snapshot is empty every cycle, no visible feedback. Reverted to "ping all displayed devices with an IP" (Steve Borba's original).

### 6.7 Auto-fetching detailed HA inline during Load Devices

Originally Phase 1 and Phase 2 were merged: build a `FirewallDevice` AND query HA detail inside one `foreach` over the bulk response. Grid stayed empty for 4 minutes. Split into Phase 1 (instant grid population from bulk response) + Phase 2 (sequential HA detail in background) so the grid appears immediately.

---

## 7. PAN-OS / pan-power Specifics Worth Knowing

- `<show><devices><connected></connected></devices></show>` returns ALL connected device metadata in one call, including `<ha><state>` per device. Use this on Load — no per-device HA-state queries needed for the basic state.
- Detail HA fields (`local-info/priority`, `local-info/preemptive`, `running-sync`, `group/mode`) require per-device queries: `<show><high-availability><state/></high-availability></show>&target=<serial>` against Panorama, which proxies to the firewall.
- Software check / download / install / job-status commands all use `&target=<serial>` embedded in Command.
- `<request><restart><system/></restart></request>` for reboot, with `-Target $serial` as a separate parameter.
- pan-power's `Invoke-PANKeyGen` parameter name varies by version — script tries `-Credentials` (plural), then `-Credential` (singular), then no-creds, to be version-tolerant.

---

## 8. Code Conventions Used

- **No emoji in code unless the user added them** — but the existing script uses several (`▶`, `⏹`, `●`, `○`, `🔥`, `🔍`, `📥`, `🔑`, `⚡`, etc.) because they're rendered in the WPF GUI. Preserve these. Don't add new ones in code paths the user didn't request.
- **`Write-Log` ALWAYS marshals via `$Window.Dispatcher.Invoke([action]{...}, 'Normal')`** — never write to `$txtLog.Text` from a runspace directly.
- **`UI {…}` and `UIAsync {…}` helpers are redefined inside each runspace's body** — they're not in the parent script scope; each runspace defines its own.
- **`SetVariable` is the only way to pass references into a runspace.** Don't try to use `$script:` from inside a runspace's `AddScript` body — it won't resolve.
- **Always wrap runspace bodies in `try/catch/finally`** with the finally setting `Running=$false` and re-enabling buttons. This is the lesson from the ping-button-jam bug.
- **Background priority** for `Dispatcher.Invoke/BeginInvoke` from ping loop (`[System.Windows.Threading.DispatcherPriority]::Background`) so other UI work isn't starved.

---

## 9. To-Do for the Next Session

Ordered by priority:

1. **Get the ping-loop crash diagnostic.** Have user run the current script in a fresh PowerShell, click Ping, screenshot the log around the crash. The new `Ping loop CRASHED:` line will pinpoint the exception. Fix the root cause.
2. **Speed up Load Devices Phase 2.** Add direct PAN-OS REST keygen on Connect (acquired in parallel with the pan-power keygen — don't replace it; pan-power is still needed for `Set-PANConfig`/`Invoke-PANCommit`). Then in Phase 2, use `RunspacePool(1, 12)` with `Invoke-RestMethod` to query HA details concurrently. Goal: 4 min → 20 s.
3. **Cosmetic fix in Job Status:** when `$status -eq 'FIN'`, don't append `$pct%` — PAN returns a finish *timestamp* in the progress field for completed jobs. Just show `'FIN ' + $pct` or `'Done'`.
4. **Stop button on Ping needs to also stop the Reboot Poller** if the user wants a global "stop background tasks" affordance.
5. **Move ApplyFilter behind the same Dispatcher discipline** — currently runs inline on the UI thread, which can block briefly with 151 devices.

---

## 10. Files in This Workspace

- `PANManager.ps1` — the script. **This is the deliverable.**
- `HANDOFF.md` — this document.

---

## 11. Quick-Start for Claude Code

Once you've cloned the repo:

```powershell
# Run the GUI
PowerShell.exe -STA -File .\PANManager.ps1

# Sanity-check brace/paren balance after edits
$src = Get-Content .\PANManager.ps1 -Raw
"{ count: $((($src -split '{').Count - 1))  } count: $((($src -split '}').Count - 1))"
"( count: $((($src -split '\(').Count - 1))  ) count: $((($src -split '\)').Count - 1))"

# Parse-only syntax check
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path .\PANManager.ps1).Path, [ref]$tokens, [ref]$errors)
if ($errors) { $errors | Format-List }
```

When changing the script:

1. Make one focused change at a time.
2. Verify brace/paren balance (the script is 1100+ lines, easy to lose track).
3. Run `Parser::ParseFile` to confirm syntactic validity.
4. **Tell the user to close all PowerShell windows and reopen before testing.** Accumulated runspace state from failed test cycles corrupts the runtime.
5. Add a `try/catch/finally` to every runspace body. The `catch` MUST log the exception. The `finally` MUST reset shared state flags and re-enable buttons.
6. Never put `Start-Sleep` or any blocking call in a button-click handler scriptblock — those run on the UI thread.

---

## 12. Conversation Summary — How We Got Here

User started with Steve Borba's Install-Software.ps1 and an earlier WPF GUI variant. Asked Sonnet to fix HA-info not populating and ping not working. Sonnet over-engineered with parallel runspaces and a DispatcherTimer-based architecture, broke things. Multiple rounds of debugging:

1. First fix attempt: swapped `&target=` for `-Target $serial`. Made HA worse (response shape changed silently).
2. Discovered pan-power returns differently for `-Target` vs `&target=`. Reverted.
3. Tried parallel runspaces with various approaches — all returned empty or partial data.
4. Tried direct REST keygen + parallel REST. Worked but added complexity.
5. Eventually reset to OLD script's architecture (sequential single-runspace) and added only the license-matrix feature on top.
6. Layered Phase 1 / Phase 2 load to get fast initial display.
7. Ping loop has been a recurring source of bugs — the latest version has full error-logging so the next test run will reveal the actual cause.
8. User wants this in Claude Code for future maintenance.

**Lesson learned:** when in doubt, copy Steve Borba's pattern. He's the source of truth for what works with pan-power.

---

*End of handoff.*
