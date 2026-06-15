# PANManager

A single-window **WPF GUI for managing a fleet of Palo Alto Networks firewalls through Panorama**, written in PowerShell. It unifies the day-to-day read/operate tasks a firewall admin runs across many devices — HA status, licensing, User-ID, ARP, IPsec, routes, commit locks, EDLs, content updates, sessions, certificates, connectivity tests — into one tabbed dashboard, plus a **Rule Miner** that turns real traffic logs into candidate least-privilege rules.

> **Attribution:** Based on scripts by **Steve Borba** — <https://github.com/sjborbajr/PaloAltoNetworks/>.
> This GUI extends and unifies his `pan-power` module and his Install-Software / User-ID-check / ARP / IPsec / Routes / commit-lock / EDL-refresh scripts into one tool. Credit and thanks to Steve Borba for the original work.

## Requirements

- **Windows PowerShell 5.1** (the script targets 5.1; `#Requires -Version 5.1`)
- The **`pan-power`** module:
  ```powershell
  Install-Module 'pan-power' -Scope CurrentUser
  ```
- Network access to your **Panorama** appliance and the managed firewalls
- Panorama credentials (the tool authenticates and uses a generated API key; no credentials are stored on disk)

## Running

```powershell
PowerShell.exe -STA -File PANManager.ps1
```

`-STA` (Single-Threaded Apartment) is **required** — WPF must run on an STA thread, and PowerShell 5.1 defaults to MTA. Without it the GUI fails to instantiate.

Workflow: **🔗 Connect** → **↻ Load Devices** → pick a tab → select devices → run the action. Every tab can fetch for *selected* devices or *all*, and most export results to CSV.

## Tabs / features

| Tab | What it does |
|-----|--------------|
| 🖥 **Devices** | Inventory from Panorama with live HA state (state/type/sync/priority), software version, and a background **Ping** column. Selection helpers: All / None / Active HA / Passive HA / Single / Needs Update. |
| 🔑 **Licenses** | Pivots per-firewall license data into a matrix (WildFire / DNS / URL / IoT / Threat / Support) so expiries are visible at a glance. CSV export. |
| 👤 **User-ID** | Checks User-ID agent/group-mapping health; can resync group-mapping and Cloud Identity Engine on selected firewalls. |
| 📡 **ARP** | Fetches ARP tables; can clear ARP on selected firewalls. |
| 🔒 **IPsec** | Lists IPsec tunnels/SAs; can clear selected tunnels. |
| 🛣 **Routes** | Fetches routing tables with filtering. |
| 🔓 **Locks** | Checks and removes config/commit locks across devices. |
| 📋 **EDLs** | Lists external dynamic lists and refreshes checked EDLs on selected devices. |
| 📦 **Content** | Reports Apps+Threats content versions; can force check/download/install latest content. |
| 📊 **System** | System info (model, serial, uptime, etc.). |
| 📝 **Commits** | Commit history / pending-change status. |
| 🌐 **GP Users** | GlobalProtect connected users. |
| 🌊 **Sessions** | Active session browser; can clear selected sessions. |
| 🔒 **Certs** | Certificate inventory with filtering. |
| 🛰 **Ping/Trace** | On-box ping/traceroute from a chosen firewall interface. |
| ⛏ **Rule Miner** | Mines Panorama traffic logs for a broad/permissive rule and proposes tighter replacements. |

## Rule Miner workflow

1. Enter a **device-group**, click **Load Rules** to pull its pre-rulebase rules.
2. Pick the broad rule, set a **Days** window and a log **cap**, click **⛏ Mine Flows**. The tool pulls matching traffic logs from Panorama and aggregates them into distinct flows (destination + app/port), sorted by session count.
3. Select the candidate flow rows and **Generate CLI** to produce `set` commands for tighter rules.

Safety behaviors built into the generator:

- If a flow has **>20 observed sources**, it falls back to `source any` and suggests creating an address group instead.
- If a common flow has an **unknown App-ID**, the rule is generated port-based and flagged for investigation.
- If a flow has **0 mapped users on real sessions**, it is flagged as likely machine traffic — `known-user` would block it — so you can uncheck `known-user` for that flow.

**Nothing is pushed automatically.** Rule Miner only generates CLI for you to review, paste into Panorama, and commit yourself.

## Architecture notes

- **Single-runspace, sequential** design (one runspace per operation, iterating devices inside) — the proven-stable pattern. Background work marshals UI updates through the WPF dispatcher.
- **TLS validation** for the license REST calls uses a *compiled* `.NET` certificate-validation callback, never a PowerShell scriptblock — a scriptblock callback persists process-wide after its runspace is disposed and silently breaks every subsequent TLS handshake. Do not reintroduce one.
- Reads embed `&target=<serial>`; writes/reboots use `-Target <serial>` — the distinction matters per operation type in `pan-power`.

## Files

- `PANManager.ps1` — the application.
- `HANDOFF.md` — project notes, current state, known issues, and dead ends to avoid.
