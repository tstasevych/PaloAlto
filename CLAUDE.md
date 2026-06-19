# CLAUDE.md — working agreement for PANManager.ps1

Guidance for any AI agent (or new contributor) working on this project. Read this before editing. It encodes conventions and hard-won lessons; following it avoids re-introducing solved bugs and wasted cycles.

## What this is
`PANManager.ps1` — a Windows PowerShell **5.1 + WPF** GUI that manages Palo Alto firewalls via Panorama using the `pan-power` module. Single ~5,400-line script. Run with `PowerShell.exe -STA -File PANManager.ps1`. See `README.md` for full feature docs. GitHub repo: `tstasevych/PaloAlto`.

## Environment & constraints (do not "modernize" away)
- **PowerShell 5.1** only. No PS7-isms. WPF requires **`-STA`**; runspaces set `$rs.ApartmentState='STA'`.
- Talks to **Panorama** (IP captured on Connect → `$script:PanCred` {IP,User,Pass}; API key generated, memory-only).
- **LDAP** features assume a **domain-joined** host using the running user's context (`[ADSISearcher]`).
- **Ping/Trace** uses the **Posh-SSH** module (XML API blocks ping — see below).

## Architecture rules — keep these
1. **One `pan-power` runspace at a time.** Concurrency corrupts module state. The gate is `$script:FetchLock`; every long action calls `Begin-Fetch '<name>'`. When busy it **queues** (captures the clicked button; a `DispatcherTimer` re-raises it later) rather than rejecting.
2. **Never touch WPF controls from a background runspace.** Marshal via `UI { … }` (dispatcher). Read control *values* on the UI thread and pass them into the runspace with `SetVariable`.
3. **No exception may escape a WPF event handler.** If one does, the whole PowerShell session is poisoned (later: even `Where-Object` becomes "not recognized"). Wrap every handler (`Add_Click`, `Add_SelectionChanged`, mouse capture, timers) in `try/catch` and null-guard controls. Recovery = restart PowerShell; it can't be fixed in-process.
4. **TLS callback = compiled .NET class (`SSLAcceptAll`), never a scriptblock.** A scriptblock callback persists process-wide after its runspace dies and breaks all later TLS. Don't reintroduce one.
5. **No `Start-Sleep` on the UI thread.** Sleeps live only in background runspaces.
6. **Reads use `&target=<serial>`; writes/reboots use `-Target <serial>`.**
7. **Confirm state-changing actions** with a detailed `Confirm-Impact`-style dialog (reboot/install/commit/HA/clears/resync/etc.).
8. **Defer slow per-row work** (e.g., LDAP/AD lookups) to a second pass after rows are shown, then `$dgRM.Items.Refresh()` — so the grid appears immediately.

## You cannot test live systems — so don't guess at API output
The agent has **no access to Panorama, AD, or SSH**. For any bug that's "shows 0 / empty / wrong field" the cause is almost always a **response-shape/field-name mismatch specific to the customer's PAN-OS build**. Do **not** rewrite parsing from a guess.
- Each fetch already (or should) dump the raw XML to the trace log on the empty/first case (`[IPsec DIAG]`, `[Certs DIAG]`, session sample). **Ask the user to run the fetch and paste that raw XML**, then fix the parser exactly. One diagnostic round beats five blind rewrites.
- Known PAN-OS facts: **ping/traceroute are blocked for the XML-API client** (`code="17"`, needs a PTY) → use SSH. IPsec up/down state may live in `show vpn flow`, not `show vpn ipsec-sa`.

## Editing & verification workflow (important)
- **This folder is OneDrive-synced. Shell/`cp`/`cat` reads frequently return a *truncated, partially-synced* copy** (looks like the file ends mid-statement, brace counts off). **Do not trust shell file reads to verify edits.** Use the **Read tool** (authoritative) to confirm content, and verify brace balance with a **string/here-string-aware lexer** (skip `'…'`, `"…"`, `@'…'@`, `#` comments before counting `{}`), checking the copy actually reaches `ShowDialog` (real EOF) before trusting any count.
- The agent can't run PowerShell. After edits, give the user the parser check: `$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("$PWD\PANManager.ps1",[ref]$null,[ref]$e);$e` (should print nothing).
- Make **small, localized, brace-balanced** edits. The script is one giant file; a stray brace is costly to find.
- Trace log lives at `PANManager-debug.log` next to the script (Write-Log mirrors there).

## User working style (follow it)
- **One step at a time.** Give ONE next action, wait for the result, then proceed. Avoid "if X then Y" branches and multi-action dumps when troubleshooting.
- **Confirm before running commands on the user's devices/machine.** Provide commands for them to run, or get explicit OK first.
- **Be concise.** Lead with the outcome; don't recap every step.
- GitHub: the agent's sandbox **cannot reach GitHub** (proxy blocks it). The user pushes manually — provide commit messages/commands, don't attempt the push.

## Naming standards
Rule Miner output must follow `Palo-Alto-Naming-Standards.md` (dynamic tag-based shared groups; Region/Loc/Type/Env/Service tags; `tcp-<port>` services; profile `JH-Outbound-SP`; rule names `<USER-GROUP|SrcGroup>-to-<Dst>`; `description` before `profile-setting` in CLI; GP-VPN zone → `Global Protect Subnets`). Reuse existing tags/services/groups/object-tags (inventoried during Mine) instead of re-creating.

## Project boundary
PANManager is **separate** from the *Panlogs → Azure* log-pipeline project. Don't mix their files.
