# PANManager

A single-window **WPF GUI for operating a fleet of Palo Alto Networks firewalls through Panorama**, written in Windows PowerShell. It unifies the day-to-day read/operate tasks a firewall admin runs across many devices into one tabbed dashboard, and adds a **Rule Miner** that turns real traffic logs into candidate least-privilege rules following James Hardie's naming/tagging standards.

> **Attribution:** Based on scripts by **Steve Borba** — <https://github.com/sjborbajr/PaloAltoNetworks/>. This GUI extends and unifies his `pan-power` module and his Install-Software / User-ID-check / ARP / IPsec / Routes / commit-lock / EDL-refresh scripts into one tool.

> **Repository:** `tstasevych/PaloAlto` (GitHub). This is a **separate project** from the *Panlogs → Azure* log-pipeline work; keep them in different folders to avoid confusion.

---

## 1. Goals & audience

**Goal:** give the firewall/SecOps team one desktop tool to inventory, health-check, and operate the whole PAN fleet via Panorama without hopping between the Panorama UI, SSH, and one-off scripts — and to *accelerate zero-trust rule tightening* by mining what traffic a broad rule actually carries and proposing specific replacements that already conform to JH naming standards.

**Audience:** firewall administrators / SecOps engineers at James Hardie. Read-only and operational actions are exposed; **no configuration is pushed automatically** — operational writes are explicit and confirmed, and Rule Miner only generates CLI for review.

---

## 2. Quick start

Requirements:
- **Windows PowerShell 5.1** (`#Requires -Version 5.1`). The script targets 5.1 specifically.
- **`pan-power`** module: `Install-Module 'pan-power' -Scope CurrentUser`.
- Network access to **Panorama** and the managed firewalls' mgmt interfaces.
- For **LDAP user-group matching** (Rule Miner): the machine should be **domain-joined**, run as a domain user (AD reads use the logged-in context).
- For **Ping/Traceroute**: the **Posh-SSH** module (`Install-Module Posh-SSH -Scope CurrentUser`) and mgmt-IP reachability to the firewalls — see §7.

Run:
```powershell
PowerShell.exe -STA -File .\PANManager.ps1
```
`-STA` is **mandatory** — WPF must run on a Single-Threaded-Apartment thread, and PowerShell 5.1 defaults to MTA. Without it the window won't instantiate.

Workflow: **Connect** (enter Panorama IP + credentials; an API key is generated and held in memory only) → **Load Devices** → pick a tab → select devices → run an action.

---

## 3. Architecture & key design decisions

These decisions are load-bearing; changing them tends to reintroduce old bugs.

- **Single runspace per operation, sequential.** Each action spawns one background runspace that iterates devices in a `foreach`. Two `pan-power` runspaces must **never** run concurrently — they corrupt each other's module state. A single-flight gate (`$script:FetchLock` = `{Busy, Name}`) enforces this.
- **Action queue (not rejection).** If you click another action while one is running, `Begin-Fetch` enqueues it (capturing the clicked button) and a `DispatcherTimer` re-raises that button's click when the lock frees — so actions run one-at-a-time in order instead of being dropped.
- **Dispatcher discipline.** Background runspaces never touch WPF controls directly; they marshal UI updates through `$Window.Dispatcher.Invoke(...)` (the `UI { }` helper). Control **values** (textbox text, checkbox state, selection) are read on the UI thread *before* a runspace launches and passed in via `SessionStateProxy.SetVariable`.
- **Event handlers must never throw.** An unhandled exception escaping a WPF event/dispatcher handler **poisons the whole PowerShell session** — afterwards every handler fails, even built-ins like `Where-Object` ("not recognized"). All event handlers (tab-switch, mouse capture, queue timer) are wrapped in `try/catch` with null guards. If you ever see "X not recognized" cascades, the session is poisoned: **close PowerShell entirely and reopen** — it cannot be recovered in place.
- **TLS validation is a compiled .NET callback**, never a PowerShell scriptblock. A scriptblock `ServerCertificateValidationCallback` persists process-wide after its runspace is disposed and then throws "no Runspace available," silently breaking *every* subsequent TLS handshake (this once broke every tab after the License tab was used). See the `SSLAcceptAll` class.
- **Reads vs writes in pan-power:** reads embed `&target=<serial>`; writes/reboots use `-Target <serial>`. The distinction matters per operation type.
- **No `Start-Sleep` on the UI thread.** It freezes the GUI. Sleeps belong only inside background runspaces.
- **Confirmations on state-changing actions.** Reboot, Install, Commit, HA suspend/resume/priority, content force-update, ARP/IPsec/session clears, lock removal, EDL refresh, and User-ID resync all prompt with a detailed impact description before running.

---

## 4. Tabs

| Tab | Purpose |
|-----|---------|
| 🖥 Devices | Inventory + live HA state, software version, background Ping column; selection helpers (All / None / Active HA / Passive HA / Single / Needs Update). |
| 🔑 Licenses | Per-firewall license matrix (WildFire / DNS / URL / IoT / Threat / Support). |
| 👤 User-ID | User-ID / group-mapping health; resync group-mapping and Cloud Identity Engine. *(Planned: show user→IP and user→group mappings for CIE + LDAP.)* |
| 📡 ARP | ARP tables; clear ARP. |
| 🔒 IPsec | IPsec tunnels/SAs; clear selected tunnels. *(State column / time-since-change is being fixed against live output — see §7.)* |
| 🛣 Routes | Routing tables with filtering. |
| 🔓 Locks | Check/remove config & commit locks. |
| 📋 EDLs | List external dynamic lists; refresh checked EDLs. |
| 📦 Content | Apps+Threats content versions; force check/download/install. |
| 📊 System | System info (model, serial, uptime, versions). |
| 📝 Commits | Commit history / pending-change status. |
| 🌐 GP Users | GlobalProtect connected users (DC gateways only), with filters: hide remote (real virtual IP), hide internal-gateway (vIP 0.0.0.0), and dedupe the same user across HA peers. |
| 🌊 Sessions | Active session browser; clear selected sessions. *(Fetch parsing being fixed against live output — see §7.)* |
| 🔒 Certs | Certificate inventory. *(Fetch parsing being fixed against live output — see §7.)* |
| 🛰 Ping/Trace | Firewall-sourced ping/traceroute **via SSH** (the XML API blocks these — see §7). |
| 🌐 Routing Peers / 📡 HA Drift / 📶 GP Gateways / 🔎 Policy Match | Additional fleet views. |
| ⛏ Rule Miner | Mine traffic logs for a broad rule and generate tighter replacements — **detailed in §5**. |

---

## 5. Rule Miner — full mechanics

Takes one broad/permissive security rule, samples the traffic that actually hit it, and proposes specific least-privilege rules. Uses the raw PAN-OS XML API (keygen + `type=log` / `type=config`), respects the single-flight lock, and **never pushes** — output is copy/paste CLI for review.

**Load Rules** → keygen, then `config get` on the device-group's `pre-rulebase/security/rules`; caches each rule's from/to zones (reused so tightened rules inherit the broad rule's zones).

**Mine Flows** → submits a traffic-log query `(rule eq '<rule>') and (receive_time geq '<since>')`, polls the async log job to `FIN`, pages backward up to the cap, and aggregates entries by `dst | dport | proto | app`, accumulating session count, bytes, and the **sets** of source IPs and users.

**Address object/group matching** (during Mine, **shared scope only**): fetches `/config/shared/address` + `/address-group`, indexes host objects by exact IP (O(1)) and keeps CIDR/range predicates for containment. Destinations match the most-specific object; sources match best by group coverage (≥ **Cover %**). Dynamic address groups and FQDN objects are skipped for matching (logged). **Existing tags, services, and group names are inventoried and reused** so generation doesn't re-create what already exists.

**LDAP user→group matching** (deferred background pass so the grid shows immediately): for flows with `0 < users < Max users`, resolves each user's AD groups (`[ADSISearcher]`, `memberOf` or transitive in-chain with the **Transitive** toggle), and picks the highest-coverage group **whose total transitive membership is ≤ 2× the flow's distinct users** (so broad groups like "All Users"/"GP VPN Users" are rejected → suggest a new group instead).

**Generate** (two buttons): **Individual Rules** (one per flow) or **Merge → 1 Rule** (union of all selected flows). Per JH naming standards (§6) the generator emits dynamic tag-based shared groups, `tcp-<port>`/`udp-<port>` services, the `JH-Outbound-SP` profile, and a rule named:
- `{USER-GROUP}-to-{SERVER-GROUP/NAME}` when a user group is the source identity, else
- `{ServiceGroup}-to-Outside_Port{port}`.

**GP-VPN special case:** any flow whose from-zone is `GP-VPN` uses source `"Global Protect Subnets"`; to-zone `GP-VPN` uses that as the destination — overriding the matched group. Reflected in both the grid and the CLI.

**CLI ordering:** `description` is emitted **before** `profile-setting group` — Panorama rejects the reverse order.

Options reference (toolbar): rule prefix; source-user known-user; restrict source; match objects/groups; resolve LDAP; transitive; Max users; Cover %; offer create-group; Region/Loc/Env/Service (tags + group/rule names) and Profile.

---

## 6. JH naming & tagging standards

Full text in `Palo-Alto-Naming-Standards.md`. Summary: prefer **dynamic tag-based** address groups (not static); all objects **shared**; tag each object with Region / Location / Type / Environment / Service (+ `port<n>`, `Destination`); group names by server prefix or `<SourceGroup>-Destination_Port<port>`; rule names `<Src>-to-<Dst>_Port<n>`; services `tcp-<port>`; profile group `JH-Outbound-SP`; avoid `any` (RFC-1918 / negate-RFC-1918 for private/public). The Rule Miner generator implements these when the **Service** field is set.

---

## 7. Known PAN-OS / environment limits & gotchas

- **Ping/Traceroute over the XML API is impossible** — PAN-OS returns `code="17"` "not available to xmlapi client" (the op command needs a PTY). The Ping/Trace tab therefore **SSHes to the firewall** (Posh-SSH, reusing the Panorama login) and runs the real CLI. Requires Posh-SSH installed and mgmt-IP reachability.
- **Sessions / Certs / IPsec parsing is environment-specific.** Empty/0 results or an empty IPsec State usually mean the response node/field names differ on this PAN-OS build. Each fetch dumps a diagnostic to the trace log (`[IPsec DIAG]`, `[Certs DIAG]`, session "sample OuterXml") — capture the real XML and fix the parser against it rather than guessing. IPsec up/down state may need `show vpn flow` rather than `show vpn ipsec-sa`.
- **Trace log:** `PANManager-debug.log` next to the script captures all log lines plus diagnostics.
- **PowerShell session poisoning:** see §3 — if handlers start failing with "not recognized," restart PowerShell.
- **OneDrive sync:** when this folder is OneDrive-synced, external tools (and the build agent's shell) sometimes read a *partially-synced/truncated* copy. Verify edits against the real file, and run a parser check before launching (below).

---

## 8. Safety model

- Every tab is **read-and-suggest** for configuration. Rule Miner output is text only — you paste and commit it in Panorama yourself.
- AD reads are read-only (`memberOf`/`tokenGroups`). Address-object reads are read-only config GETs.
- State-changing operational actions (reboot/install/commit/HA/clears/etc.) require a confirmation dialog with impact detail.
- Fallbacks fail safe toward `any` / `known-user` with explicit warnings rather than silently emitting something too narrow that would break traffic.

---

## 9. Pre-launch check

```powershell
$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("$PWD\PANManager.ps1",[ref]$null,[ref]$e); $e
```
Should print nothing. Then run with `-STA` in a **fresh** PowerShell window.

---

## 10. Files

- `PANManager.ps1` — the application.
- `README.md` — this document.
- `CLAUDE.md` — conventions & guidance for AI agents / contributors working on the script.
- `HANDOFF.md` — original project notes / dead-ends.
- `RuleMiner-Matching-Design.md` — design notes for the object/group + LDAP matching.
- `Palo-Alto-Naming-Standards.md` — the JH PAN naming/tagging standard.

## 11. Outstanding / roadmap

- Fix Sessions, Certs, and IPsec parsing against captured live XML (state + time-since-change for IPsec).
- Build the User-ID mappings view (user→IP, user→group for CIE + LDAP).
- Validate the SSH ping/traceroute read-loop against real PAN-OS shell behavior (prompt/pager handling).
