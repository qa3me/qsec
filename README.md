# Qsec Security

Qsec brings firewall reporting, login protection, security header previews, and file integrity checks to the WordPress dashboard. Reports and scans run on the site. Qsec has no cloud service or telemetry.

[English guide](docs/PROJECT-en.md) · [راهنمای فارسی](docs/PROJECT-fa.md) · [Release notes](https://github.com/qa3me/qsec/releases)

## Install

1. Download the installer from Releases and upload it in **Plugins → Add New Plugin → Upload Plugin**.
2. Activate Qsec Security and open **Settings → Qsec**.
3. Review the firewall report before enabling optional blocking.

Qsec requires WordPress 6.6 or later and PHP 8.3 or later on a single site. Authenticator apps and recovery codes are available through the separate Two-Factor plugin.

## Verify locally

Run each PHP script in `tests/`, and run `node --test tests/csp.test.cjs` for the Content Security Policy checks. These checks need no third-party packages.

Copyright © 2026 Behzad Qasemi (QA3). Qsec is distributed under [GPL-2.0-or-later](LICENSE). Michroma retains its [SIL Open Font License](assets/michroma-ofl.txt).
