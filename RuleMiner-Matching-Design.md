# Rule Miner — Object/Group & LDAP User Matching (Design)

Extends the ⛏ Rule Miner tab in `PANManager.ps1`. Goal: when generating tighter
rules, replace raw IPs and blanket `known-user` with **existing named address
objects/groups** and **LDAP-matched user groups**, so the mined rules look like
something an admin would hand-write — and are easy to review before commit.

Nothing about the push model changes: Rule Miner still only **generates CLI for
review**. These features add suggestions and annotations, never auto-commit.

---

## Part A — Address object / group matching (sources & destinations)

### What we fetch (once per Mine, cached)
Via the existing keygen + `type=config&action=get` XML API pattern already used
by `Invoke-RMLoadRules`, pull address objects and address groups from three
scopes and merge them (device-group wins over parent wins over shared on name
collisions):

1. **Shared:** `/config/shared/address` and `/config/shared/address-group`
2. **Device-group** (the one entered in the tab): `.../device-group/entry[@name='$dg']/address` and `/address-group`
3. **Parent device-group(s)** if the DG is nested (optional; see Q3)

Build two in-memory tables:
- `AddrObjects`: name → { Type = ip-netmask | ip-range | fqdn ; Value ; ParsedCIDR/Range }
- `AddrGroups`: name → resolved set of IPs/CIDRs (static groups; nested groups
  flattened. **Dynamic address groups are skipped** — membership is tag-based and
  not knowable from config alone, logged as "skipped DAG: <name>").

FQDN objects are **not** used for IP matching (they resolve dynamically; matching
a logged IP to an FQDN object would be unreliable). They're listed in the log only.

### Destination matching (single IP per flow)
For each flow's destination IP:
1. **Exact host match** — an `ip-netmask` object equal to `IP/32` (or bare IP) →
   use that object name. Most specific wins.
2. **Containing subnet** — smallest `ip-netmask` CIDR that contains the IP, or an
   `ip-range` that spans it → offer as a match (flagged "subnet/range match").
3. **Group membership** — if the IP resolves into one or more `AddrGroups`, list
   the smallest such group as an alternative.
4. If nothing matches → keep the raw IP (current behavior) and flag
   "no object — consider creating one".

### Source matching (set of IPs per flow)
1. Map each observed source IP to an address object (same logic as destinations).
2. **Group fit:** find address groups whose resolved IP set best covers the
   observed sources. A group "matches well" when
   `covered = |observed ∩ group| / |observed| ≥ COVER_THRESHOLD` **and**
   `bloat = |group| / |observed| ≤ BLOAT_MAX` (group isn't wildly larger than
   what we saw). Default `COVER_THRESHOLD = 0.80`, `BLOAT_MAX = 3`. Rank by
   highest cover, then lowest bloat, then smallest group.
3. Output preference when "Restrict source" is on:
   - one group covers all observed sources → `source <group>`
   - else, sources that are individual objects → `source [ obj1 obj2 ... ]`
   - else fall back to raw IPs (≤20) or `any` (current behavior), with the same
     ">20 sources, consider a group" log line.

Every substitution is written to the log (`[RuleMiner] dst 10.x → object "SRV-..."`,
`src set 8/9 covered by group "GRP-..." (bloat 1.4)`), so you can sanity-check
before pasting.

---

## Part B — LDAP user → group matching (flows with < 50 users)

### Gate
Only runs for flows where `0 < UserCount < 50` (configurable threshold, default
**50**). Flows with 0 users are machine traffic (already flagged); flows with ≥50
users are too broad to bother resolving — left as `known-user`.

### Lookup
For each user in the flow's `AllUsers` (normalizing `DOMAIN\user`, `user@domain`,
and bare `sAMAccountName`):
1. Resolve the user object in AD and read `memberOf` (and, with a flag, transitive
   groups via `tokenGroups` / recursive `memberOf`).
2. Tally group → count of flow-users who are members.

### "Group matches well"
A group is a candidate when `members_in_flow / UserCount ≥ USER_COVER_THRESHOLD`
(default **0.80**). Rank by highest coverage, then **smallest total group size**
(most specific), then alphabetical. Surface the top 1–3 candidates per flow.

- Full coverage (all flow-users in one group) → suggest `source-user <group>`.
- Partial (e.g. 9/10) → suggest the group **and** log the 1 user not covered, so
  you can decide (add them to the group, or keep known-user).
- No group ≥ threshold → keep `known-user` (or `any` if known-user is off), logged
  as "no group fit — left as known-user".

### Group name format in generated CLI
PAN-OS `source-user` references groups using the name as it appears in your
**group-mapping** (this is the part I need to confirm — see Q2). The tool will
store each matched group's `sAMAccountName`, `domain\sAMAccountName`, and full DN,
and emit whichever format you choose (default `domain\group`).

---

## UI additions to the Rule Miner tab
- New columns in the flows grid: **Dst Obj**, **Src Match** (e.g. "grp GRP-X 8/9"),
  **User Group** (top candidate + coverage).
- Checkboxes: **Match address objects/groups** (default on), **Resolve user groups
  via LDAP** (default on), **Transitive group membership** (default off).
- Fields: **User threshold** (default 50), **Cover %** (default 80).
- Matching for objects runs as part of Mine Flows (we already have a runspace
  there). LDAP resolution runs in its own background runspace after Mine completes
  (AD calls can be slow), updating the grid as results arrive.

## Performance / safety notes
- Address objects/groups: one extra config GET per scope, cached for the session
  (re-fetched on next Mine). Group resolution is in-memory set math.
- LDAP: dedupe users across flows so each user is queried once; cache user→groups
  for the session. With <50 users/flow and dedupe, this is well bounded.
- All AD reads are read-only (`memberOf`/`tokenGroups`). No writes.
- Everything stays advisory: generated CLI is still copy/paste-only.

---

## Part C — Multi-flow generation & create-group offers (added)

### Two generate buttons
- **⚙ Individual Rules** — one rule per selected flow (original behavior, now object/group/user-group aware).
- **⚙ Merge → 1 Rule** — all selected flows collapse into ONE rule: union of destinations,
  applications, service ports, sources, and user groups. Zones come from the broad rule (or
  union of observed). Mixed known-app + unknown-port selections produce a best-effort rule and
  log a "review / consider individual rules" warning.

### Create-group offers (when no existing match)
Gated by **Offer create-group CLI** (default on).
- **Sources:** when no existing address-group matches and Restrict-source is on, emit CLI to
  create `AUTO-SRC-<ip>` /32 objects (tagged with the group name) for unmatched IPs, combine
  with any matched objects into a **static** `address-group <rule>-src`, and use it in the rule.
  A commented **dynamic/tag-based** alternative (DAG filtering the tag) is appended so the admin
  can choose a dynamic group instead — this is the tag-driven option requested.
- **Users:** when no AD group matches, append a commented, ready-to-run **New-ADGroup +
  Add-ADGroupMember** snippet listing the flow's users (sAMAccountNames), plus the step to add
  the new group to Panorama group-mapping. AD group creation isn't a Panorama op, so it's a
  suggestion, not active CLI. Partial matches log which users are missing from the chosen group.

All create-group output is either active `set` CLI (sources, since they're Panorama objects) or
`#`-commented suggestions (AD groups). Commented lines are inert if pasted into Panorama.

## Decisions taken (from clarifying answers)
- LDAP via domain-joined `[ADSISearcher]` (current user). 2) Group CLI form `DOMAIN\group`
  (`$env:USERDOMAIN`). 3) Address matching scope = **shared only**.

## Open questions (resolved — kept for history)
1. **LDAP access** — is the box running PANManager domain-joined, so I can use
   `[ADSISearcher]` with the running user's context? Or should it bind to a
   specific DC/LDAP URI with a service account?
2. **Group name format** — in your existing security rules, how do group-based
   `source-user` entries look (e.g. `jameshardie\grp-app-x`, or a full
   `cn=grp-app-x,ou=...,dc=...` DN)? That dictates what the generated CLI emits.
3. **Object scope** — match destinations/sources only against the entered
   device-group + shared, or also walk parent device-groups if nested?
