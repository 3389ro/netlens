# Security policy

## Supported versions

The current release on the [Releases page](https://github.com/3389ro/netlens/releases) is the supported version. Older tagged versions are kept for historical reference but do not receive security fixes — please upgrade.

| Version | Supported          |
|---------|-------------------|
| 1.2.x   | ✅ Latest          |
| < 1.2   | ❌ Please upgrade   |

## Reporting a vulnerability

**Do not open a public issue for security-related reports.**

Email **office@3389.ro** with:

1. A clear description of the issue and the version affected.
2. Steps to reproduce (if applicable, a minimal proof-of-concept).
3. The impact you believe the issue has.
4. Your name / handle if you want to be credited in the release notes.

We aim to acknowledge a report within **two business days** and to ship a fix or mitigation within **30 days** of confirmation, depending on severity and complexity.

## What's in scope

NetLens is a defensive utility. In-scope reports include:
- Memory-safety issues in the scanner (UAF, OOB read/write, double-free, integer overflow leading to wrong memory access).
- Crash / DoS triggered by responses from scanned hosts.
- Parser issues in the OUI lookup table loader.
- Privilege escalation paths through the binary or its installer (there is no installer, but report any unexpected privilege requirement).
- HTML / CSV report-injection that could lead to formula injection in spreadsheets or HTML injection when the report is opened in a browser.

## What's out of scope

- Reports against networks you do not own or have permission to scan. NetLens is a *tool*; misuse of it is on the user, not on us.
- Issues that require a malicious local user with admin rights on the same machine.
- Self-XSS or report-injection where the attacker controls the input the user types into the scan range field.

## Responsible disclosure

We follow coordinated disclosure: please give us a reasonable window (typically 30–90 days) to ship a fix before public disclosure. We're happy to acknowledge researchers in release notes — let us know if you want to be named.
