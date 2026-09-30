# Security policy

`stile` is security-sensitive software. Thank you for reporting issues
responsibly.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (initial release) | yes, best effort |

This project is pre-1.0 and early-stage: fixes land on `main` and are
cut into patch releases. There are no long-term support branches yet.

## Reporting a vulnerability

**Do not open a public GitHub issue for an undisclosed vulnerability.**

This project does not yet have a dedicated security email address.
Until one exists, use **GitHub Private Vulnerability Reporting**:

1. Go to the repository page on GitHub.
2. *Security* tab → *Report a vulnerability*.

(If the tab is not enabled, the maintainer must turn it on under
*Settings → Code security and analysis → Private vulnerability
reporting*. That is a one-time setup step listed in the release
checklist.)

Reports received this way stay private to the maintainer and the
GitHub Security Advisory workflow, and allow coordinated disclosure
and CVE issuance where warranted.

## What to include

- Affected version or commit (`stile --version`, git rev).
- The component and file if known (broker, CLI, protocol, deploy,
  verify, sops integration).
- A minimal reproduction: config, registry fragment, request frames.
- Impact assessment against the stated threat model — in particular
  whether it crosses the privilege boundary (secret bytes reaching an
  untrusted caller) or is a denial of service / integrity issue.
- Any proof-of-concept output. **Do not include real secret values**;
  use obviously fake sentinels (e.g. `CANARY-not-a-real-secret`).

## Expectations

- The threat model in [THREAT_MODEL.md](THREAT_MODEL.md) defines the
  intended boundary. Reports of behaviour inside that boundary (e.g.
  "root can read the secrets it is trusted to hold") will be treated
  as documentation questions, not vulnerabilities.
- The maintainer will acknowledge reports within a few days and agree
  on a fix and disclosure timeline. Confirmed boundary-crossing issues
  take priority.
