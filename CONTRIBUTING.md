# Contributing to NetLens

Thanks for taking a look. NetLens is maintained by [3389 Software Outsourcing](https://3389.ro); contributions are very welcome but please read this short page first so we're aligned on the basics.

## Quick checklist

- File an [issue](https://github.com/3389ro/netlens/issues) before sending a large PR — it's the fastest way to confirm we'll merge it.
- Keep PRs focused. One change per PR.
- Match the existing code style (C++20, no exceptions in hot paths, no STL streams in the scanner core).
- Include test evidence in the PR description (manual is fine — what you scanned, what changed).
- By contributing you agree that your contribution is licensed under the MIT License (the project licence), and you confirm you have the right to license it that way.

## Bug reports

Use the [Bug report](https://github.com/3389ro/netlens/issues/new?template=bug_report.md) template. Include at minimum:

- NetLens version (visible in About dialog or via `--help`).
- Windows version (`winver`).
- The exact command line or GUI settings that triggered the issue.
- What you expected vs what happened.
- A `--debug` run capturing stderr if the issue is in the scan engine.

## Feature requests

Open an issue with the **enhancement** label and describe the use case. We're particularly interested in:
- New vendor port-priority profiles (please include a few OUI prefixes that should match).
- Additional UDP service probes that fit the existing 6-probe pattern (deterministic, no admin).
- New CSV / HTML report columns.

## Pull requests

1. Fork the repo, create a feature branch (`git checkout -b feat/short-description`).
2. Make your change in `src/`. Don't touch `build/` (it's gitignored).
3. Build locally with `build-release.bat` and confirm the binary runs.
4. If you're adding a CLI flag, update the CLI help text and the README CLI table.
5. If you're changing the scan engine or risk model, note it in `CHANGELOG.md` under an `[Unreleased]` section at the top.
6. Submit the PR. CI is currently manual; we'll build and review on our side.

## Code of conduct

Be kind, stay technical, assume the other person is trying to help. We follow the spirit of the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) without formally adopting it. Spam, harassment, or off-topic political content gets the issue / PR closed and the author blocked.

## Security issues

**Do not file a public issue.** See [`SECURITY.md`](SECURITY.md) — we use coordinated disclosure with `office@3389.ro`.

## Licence and attribution

NetLens is MIT-licensed. Vendor names visible in scan results come from the publicly available [IEEE OUI registry](https://standards-oui.ieee.org/) and are property of their respective owners — see [`NOTICE.txt`](NOTICE.txt) for the full attribution statement.
