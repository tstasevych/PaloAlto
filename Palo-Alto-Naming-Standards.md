# Palo Alto Panorama — Naming & Object Management Standards

Reference for how PANManager's Rule Miner should name and tag generated objects, groups, services, and rules.

## 1. General principles
- **Avoid static address groups** for resources that may change (e.g. servers). Use **dynamic address groups based on tags**.
- All objects must be **shared** (not tied to a single device group).
- Consistent naming + tagging for scalability and clarity.
- Create security rules at the **highest logical level** (e.g. `US-Data-Centers`, `EU-Plants-IT`) to minimize duplication.

## 2. Tagging standards
Every address object carries these tags:

| Tag type | Examples |
|----------|----------|
| Region | US, EU, APAC |
| Location | IRV, CH3, DUS, PVP, VAP (3-letter code) |
| Type | Server, Destination, ESXI, NET, Port |
| Environment | PROD, DEV, QA |
| Service | Informatica, BusinessObjects, SAP, Tableau |

- For **ports**, use a `Port` tag with a value like `port22`, `port443`, `port80`.
- For **destinations**, always include the `Destination` tag.

## 3. Address object naming
- **Servers:** DNS name or descriptive name — e.g. `PRDBOAPP01`, `PRDBOAPP02`.
- **External destinations:** descriptive name + function — e.g. `Everbridge-SFTP-01`, `Everbridge-SFTP-02`.

## 4. Dynamic address groups
- Tag-based, not static IPs.
- Naming:
  - **Servers:** common prefix of the server names — e.g. `PRDBOAPP`.
  - **Destinations:** `<SourceGroup>-Destination_Port<port>` — e.g. `PRDBOAPP-Destination_Port22`.

## 5. Security policy naming
- Format: `<SourceGroup>-to-<DestinationGroup>_Port<PortNumber>` — e.g. `PRDBOAPP-to-Outside_Port22`.
- Policy details (example):
  - Source Zone: `INSIDE`
  - Source Address: dynamic group (e.g. `PRDBOAPP`)
  - Destination Zone: `OUTSIDE`
  - Destination Address: dynamic group (e.g. `PRDBOAPP-Destination_Port22`)
  - Application: specify if possible (e.g. `ssh`)
  - Service: `tcp-22`
  - Action: Allow
  - Profile: `JH-Outbound-SP` (profile type: Group)

## 6. Best practices
- Always specify zones and addresses — **avoid `any`**.
- Anything private → RFC-1918.
- Anything public → **negate** RFC-1918.
- Use applications in rules when possible.
- Apply rules at the highest applicable device group to avoid duplication.

---

## How Rule Miner will apply this (plan)
- **Rule name:** `<SrcGroup>-to-<DstGroup>_Port<port>` (falls back to a sanitized form when a group name isn't available).
- **Groups:** create **dynamic, tag-based** groups (the static form becomes the commented alternative, flipping today's default).
- **Service objects:** named `tcp-<port>` / `udp-<port>`.
- **Profile:** append `profile-setting group JH-Outbound-SP` to each generated rule.
- **Tags:** auto-derivable tags (`Type`, `Port`, and `Destination` where applicable) are applied automatically; `Region`, `Location`, `Environment`, and `Service` come from per-mining-session fields the admin sets (a traffic log can't reveal them), and are written onto created objects and used in group/rule names.
- **Avoid `any`:** prefer matched/created groups; where a side is unavoidably broad, offer the RFC-1918 / negate-RFC-1918 convention rather than `any`.
