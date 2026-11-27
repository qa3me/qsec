# Qsec Security

Review WordPress security before you enforce changes. Qsec keeps firewall counts, file checks and configuration review in your WordPress dashboard.

## Firewall and login

The firewall starts in report-only mode. It checks selected configuration and version-control paths on public GET and HEAD requests that reach WordPress. An administrator can enable blocking after reviewing the report. Requests handled directly by your web server or proxy need protection at that layer.

Login reporting and the password cooldown can be enabled independently. Repeated failures for the same login name and source trigger a short, fixed wait. The dark and light login designs use the native WordPress form and password recovery flow. Authenticator apps and recovery codes are managed by the optional Two-Factor plugin.

## Security headers and file checks

Preview a report-only Content Security Policy on a selected page and inspect the resource origins the browser observed. Review key pages and interactions before adopting a policy.

Compare WordPress core against an imported checksum reference or inspect uploads, plugins and themes for suspicious indicators and optional hash matches. Core checks resume in batches. File inspection is read-only and reports where coverage was limited.

## Privacy and language

Firewall and login reports store daily counts locally. The JSON summary excludes file paths, usernames, site URLs and secrets. The English and Persian interfaces include a right-to-left Persian layout and Jalali dates.

Open **Settings → Qsec** after activation. Requires WordPress 6.6 or later and PHP 8.3 or later on a single site.
