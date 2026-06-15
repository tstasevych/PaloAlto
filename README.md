# PANManager

A single-window **WPF GUI for managing a fleet of Palo Alto Networks firewalls through Panorama**, written in PowerShell. It unifies the day-to-day read/operate tasks a firewall admin runs across many devices — HA status, licensing, User-ID, ARP, IPsec, routes, commit locks, EDLs, content updates, sessions, certificates, connectivity tests — into one tabbed dashboard, plus a **Rule Miner** that turns real traffic logs into candidate least-privilege rules, with automatic matching against existing address objects/groups and Active Directory groups.

> **Attribution:** Based on scripts by **Steve Borba** — <https://github.com/sjborbajr/PaloAltoNetworks/>.
> This GUI extends and unifies his `pan-power` module and his Install-Software / User-ID-check / ARP / IPsec / Routes / commit-lock / EDL-refresh scripts into one tool. Credit and thanks to Steve Borba for the original work.

---

## 1. Requirements & running

- **Windows PowerShell 5.1** (`#Requires -Version 5.1`).
- The **`pan-power`** module: `Install-Module 'pan-power' -Scope CurrentUser`.
- Network reachability to **Panorama** and the managed firewalls.
- Panorama credentials. No credentials are written to disk — on Connect the tool calls the PAN-OS `keygen` API and holds the resulting API key in memory for the session only.
- For LDAP user-group matching: the machine should be **domain-joined**, and you run PANManager as a domain user (the AD lookups use your logged-in Windows context — no separate service account or stored password).

Run:

```powershell
PowerShell.exe -STA -File PANManager.ps1
```

`-STA` (Single-Threaded Apartment) is **mandatory**. WPF must run on an STA thread and PowerShell 5.1 defaults to MTA; without `-STA` the window fails to instantiate.

---

## 2. Architecture (why it's built this way)

**Single-runspace, sequential per operation.** Each button spawns one background runspace that does its work iterating devices inside a `foreach`. Two `pan-power` runspaces must never run at once — they corrupt each other's module state — so a single-flight gate (`$script:FetchLock`) blocks overlapping fetches. This is the proven-stable pattern; parallel runspaces were tried and abandoned.

**UI marshalling via the dispatcher.** Background runspaces never touch WPF controls directly. They post updates with `$Window.Dispatcher.Invoke(...)` (the `UI {}` helper inside each runspace). Control *values* are always read on the UI thread **before** a runspace is launched and passed in via `SessionStateProxy.SetVariable` — a runspace cannot read a checkbox or textbox itself.

**TLS certificate handling.** The license and Rule Miner REST/XML-API calls must accept self-signed PAN-OS management certs. The validation callback is a **compiled .NET method** (`SSLAcceptAll`), never a PowerShell scriptblock. A scriptblock callback persists process-wide after its runspace is disposed and then throws "no Runspace available," silently breaking every subsequent TLS handshake in the process. Do not reintroduce a scriptblock callback.

**Reads vs writes in pan-power.** Reads embed `&target=<serial>` in the API call; writes/reboots use `-Target <serial>`. The distinction matters per operation type.

---

## 3. Tabs at a glance

| Tab | Purpose |
|-----|---------|
| 🖥 Devices | Inventory + live HA state, software version, background Ping column, selection helpers (All / None / Active HA / Passive HA / Single / Needs Update). |
| 🔑 Licenses | Per-firewall license matrix (WildFire / DNS / URL / IoT / Threat / Support). CSV export. |
| 👤 User-ID | User-ID / group-mapping health; resync group-mapping and Cloud Identity Engine. |
| 📡 ARP | ARP tables; clear ARP on selected firewalls. |
| 🔒 IPsec | IPsec tunnels/SAs; clear selected tunnels. |
| 🛣 Routes | Routing tables with filtering. |
| 🔓 Locks | Check/remove config & commit locks. |
| 📋 EDLs | List external dynamic lists; refresh checked EDLs on selected devices. |
| 📦 Content | Apps+Threats content versions; force check/download/install. |
| 📊 System | System info (model, serial, uptime…). |
| 📝 Commits | Commit history / pending-change status. |
| 🌐 GP Users | GlobalProtect connected users (data-center firewalls only). |
| 🌊 Sessions | Active session browser; clear selected sessions. |
| 🔒 Certs | Certificate inventory with filtering. |
| 🛰 Ping/Trace | On-box ping/traceroute from a chosen firewall interface. |
| ⛏ Rule Miner | Mine traffic logs for a broad rule and generate tighter replacements. **Detailed below.** |

---

## 4. Rule Miner — full mechanics

The Rule Miner takes one broad/permissive security rule, samples the traffic that actually hit it, and proposes specific least-privilege rules. It uses the **raw PAN-OS XML API** (keygen + `type=log` and `type=config`) rather than `pan-power`, but still respects the single-flight `FetchLock`.

**Nothing is ever pushed.** Every button only reads from Panorama/AD and writes text into the CLI box. You review, copy, paste into Panorama configure mode, and commit yourself.

### 4.1 Load Rules
Enter the **device-group** and click **↻ Load Rules**. A runspace does keygen, then `type=config&action=get` on
`/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='<dg>']/pre-rulebase/security/rules`.
It caches each rule's `from`/`to` zones and `action` (`$script:RMRuleInfo`) — the zones are reused when generating new rules so the tightened rules inherit the broad rule's zone pair. If no rules are found, it lists the available device-group names to help you correct the name.

### 4.2 Mine Flows
Set **Days** (look-back window) and **Max logs** (sample cap; the API is paged 5000 at a time). Click **⛏ Mine Flows**. The runspace:

1. Runs keygen, then submits a log query: `(rule eq '<rule>') and (receive_time geq '<since>')` against `log-type=traffic`.
2. PAN-OS log queries are asynchronous — it returns a **job id**, which the tool polls (every 2 s, up to ~180 s/page) until status `FIN`, then reads the log entries. It pages backward until the cap is hit or logs run out.
3. **Aggregation:** every log entry is bucketed by the key `dst | dport | proto | app`. Per bucket it accumulates session count, total bytes, and the **sets** of distinct source IPs (`src`), users (`srcuser`), and actions. From/to zones are taken from the entries.
4. Buckets are sorted by session count (busiest first) and rendered as rows. The full source and user lists are carried on each row (`AllSources`, `AllUsers`) for later CLI generation; the grid shows truncated "Top" previews.

### 4.3 Address object / group matching (during Mine)
If **Match address objects/groups** is on, the Mine runspace also fetches `/config/shared/address` and `/config/shared/address-group` (**shared scope only**, per configuration) and builds an in-memory index:

- **Address objects** are parsed into predicates: `ip-netmask` becomes a base+prefix CIDR (a bare host becomes `/32`); `ip-range` becomes a start–end pair. IPs are converted to 32-bit integers for fast comparison. **FQDN objects are skipped** (they resolve dynamically; matching a logged IP to an FQDN object would be unreliable).
- **Address groups:** static groups are flattened to the set of predicates of their members, resolving nested groups recursively (with cycle protection). **Dynamic address groups are skipped** — their membership is tag-based and not knowable from config alone (each skip is logged).

Matching logic:

- **Destination (single IP per flow):** find the most-specific object that contains the IP. An exact `/32` host object wins; otherwise the longest-prefix containing subnet, or a covering range. Result shown in the **Dst Obj** column.
- **Source (set of IPs per flow):** each source IP is mapped to its best object; IPs with no object are recorded as "unmatched." Then every address group is scored by **coverage** = (observed sources it contains) ÷ (total observed sources). A group qualifies when coverage ≥ the **Cover %** setting; among qualifying groups the one with the fewest member-predicates (most specific) wins. The **Src Match** column shows either `grp <name> hits/total` or `obj x<n> (+<k> raw)`.

These results are stored on each row (`DstObject`, `SrcGroup`, `SrcObjects`, `SrcUnmatched`) so CLI generation can use names instead of raw IPs.

### 4.4 LDAP user → group matching (during Mine)
If **Resolve user groups (LDAP)** is on, for every flow with **0 < users < Max users** the runspace resolves each user's AD groups and looks for a group that fits the user set:

- Each `srcuser` is normalised to a `sAMAccountName` (strips `DOMAIN\` or `@domain`).
- `[adsisearcher]` (current-user/domain-joined context) finds the user and reads **`memberOf`**. With **Transitive** on, it instead queries nested membership via the AD matching rule `member:1.2.840.113556.1.4.1941:` (`LDAP_MATCHING_RULE_IN_CHAIN`).
- User→groups results are **cached per session** so each distinct user is queried only once, even across flows.
- For the flow, each group is tallied by how many of the flow's users belong to it. The top group qualifies when its coverage ≥ **Cover %**. The group's DN is resolved to its `sAMAccountName` and emitted as **`DOMAIN\group`** (the NetBIOS domain is taken from `$env:USERDOMAIN` — single-domain assumption). The **User Group** column shows `<group> hits/total`, and any users *not* in the group are recorded (`UserGrpMissing`) so you can decide whether to add them or fall back to `known-user`.

### 4.5 The flows grid columns
Sessions, From, To, Destination, DPort, Proto, App, Users, Top Users, Srcs, Top Sources, GB, **Dst Obj**, **Src Match**, **User Group**, Actions. Sort by clicking headers; multi-select rows (Ctrl/Shift) for CLI generation.

### 4.6 Generating rules
Select one or more flow rows, then choose:

- **⚙ Individual Rules** — one tight rule per selected flow.
- **⚙ Merge → 1 Rule** — combine **all** selected flows into a single rule (union of destinations, applications/services, sources, and users). Useful when many small flows clearly belong to one service.

For each rule the generator builds:

- **Name:** `<prefix>` + app (or `proto-port` for unknown App-ID) + destination, sanitised to `[A-Za-z0-9._-]` and clipped to 63 chars, de-duplicated. Merge rules are named `<prefix>merged-<first-app>`.
- **from / to:** the broad rule's zones if known, else the union of observed zones.
- **destination:** matched object name (quoted) if found, else the raw IP (bare). Merge unions all destinations into a list.
- **application / service:**
  - All known App-IDs → `application [apps]`, `service application-default`.
  - All unknown App-ID → `application any` with explicit `SVC-<proto>-<port>` service objects (created once each).
  - Mixed (merge only) → known apps + explicit service ports, with a log warning to review or split.
- **source** (decision order):
  1. If all sources matched and a group covers them → use the group name.
  2. Else if **Restrict source** is on and **Offer create-group** is on → build a group: create `AUTO-SRC-<ip>` `/32` objects (tagged) for unmatched IPs, combine with matched objects into a **static** `address-group <rulename>-src`, and use it. A commented **dynamic/tag-based alternative** (a DAG filtering the tag) is appended so you can switch to a dynamic group if you prefer.
  3. Else if Restrict source is on and ≤20 sources → inline the objects/IPs.
  4. Else → `source any` (with a log note suggesting you enable create-group).
- **source-user** (decision order):
  1. Matched AD group(s) → `source-user "DOMAIN\group"` (with a log note listing any users not in the group).
  2. Else if **source-user known-user** is checked → `source-user known-user`. If the flow had sessions with **0 mapped users**, a warning fires (machine traffic that `known-user` would block). When **Offer create-group** is on, a commented **New-ADGroup / Add-ADGroupMember** snippet is appended listing the flow's users, plus the steps to add the new group to Panorama group-mapping — because creating an AD group is not a Panorama operation, this is offered as a ready-to-run suggestion, not active CLI.
- A `move … before "<broad rule>"` line is emitted so each new specific rule sits above the broad rule it tightens.

The output text box is editable. **📋 Copy CLI** copies it. The commented offers (`#` lines) are inert if pasted into Panorama, so the active `set`/`move` lines apply cleanly and the suggestions are there for reference.

### 4.7 Options reference

| Control | Default | Effect |
|---------|---------|--------|
| New rule prefix | `ZT-` | Prefix for generated rule, service, group, and object names. |
| source-user known-user | on | Adds `source-user known-user` when no AD group is matched/used. |
| Restrict source to observed IPs | off | Enables source tightening (objects/group/inline IPs) instead of `source any`. |
| Match address objects/groups | on | Fetches shared objects/groups during Mine and matches dst/src. |
| Resolve user groups (LDAP) | on | Resolves AD groups for flows under the user threshold. |
| Transitive | off | Use nested (transitive) group membership in AD. Slower. |
| Max users | 50 | Only resolve user groups for flows with fewer than this many distinct users. |
| Cover % | 80 | Minimum coverage for a source group or user group to be suggested. |
| Offer create-group CLI | on | Emit create-group CLI (sources) and New-ADGroup suggestions (users) when nothing matches. |

---

## 4b. Naming-standards generation
Generated CLI follows the JH Palo Alto naming/object standards (see `Palo-Alto-Naming-Standards.md`). Per-mining-session fields on the Rule Miner toolbar drive it:

| Field | Use |
|-------|-----|
| Region / Loc / Env / Service | Tags applied to created objects; Service also names the dynamic groups and rules. |
| Profile | Security profile group attached to each rule (`profile-setting group`, default `JH-Outbound-SP`). |

When **Service** is set, the generator emits **dynamic, tag-based shared address groups** (not static): a source group `<Service>` filtered on `'<Service>' and 'Server'`, and a destination group `<Service>-Destination_Port<port>` filtered on `'<Service>' and 'Destination' and 'port<port>'`. Address objects are created/tagged in **shared** scope with Region/Location/Env/Service plus role (`Server`/`Destination`) and `port<port>` tags. Service objects are `tcp-<port>` / `udp-<port>` (shared). Rules are named `<Service>-to-Outside_Port<port>`, zones default to `INSIDE`/`OUTSIDE` when the broad rule has none, and the GP-VPN override still forces `Global Protect Subnets`. If Service is blank, the generator falls back to matched-object/IP behavior. All of this is still copy/paste-only CLI for review.

## 5. Safety model

- Rule Miner and every other tab are **read-and-suggest** for config changes. The generated `set`/`move` CLI is text only — you paste and commit it yourself in Panorama.
- AD lookups are **read-only** (`memberOf` / `tokenGroups`).
- Address-object fetch is read-only config GET on shared scope.
- The broad source/user fallbacks deliberately fail safe toward `any` / `known-user` with explicit log warnings rather than silently emitting something overly narrow that would break traffic.

## 6. Known limitations & assumptions

- **Object scope is shared-only.** Device-group-local and parent-DG objects are not matched (by configuration). Add those scopes if your objects live there.
- **Single AD domain** assumed for the `DOMAIN\group` form (`$env:USERDOMAIN`). Multi-domain/forest needs per-user domain resolution.
- **Dynamic address groups** and **FQDN objects** are not used for matching (logged when skipped).
- **Merge mode** with mixed known-app + unknown-port flows produces a best-effort rule and warns; review or use individual rules for those.
- LDAP group DNs containing LDAP-filter metacharacters are not escaped; such lookups fall back to the CN.
- The tool cannot validate that a suggested AD group actually exists in Panorama group-mapping — you must ensure the group is in the group-mapping include-list before referencing it in a rule.

## 7. Quick verification before launching
PowerShell parser sanity check (run on your machine):

```powershell
$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("$PWD\PANManager.ps1",[ref]$null,[ref]$e); $e
```

(Should output nothing.) Then run `PowerShell.exe -STA -File PANManager.ps1`.

## 8. Files
- `PANManager.ps1` — the application.
- `HANDOFF.md` — project notes, current state, known issues, dead ends to avoid.
- `RuleMiner-Matching-Design.md` — design notes for the object/group + LDAP matching features.
