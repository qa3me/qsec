=== Qsec Security ===
Tags: security, firewall, login security, file integrity, csp
Requires at least: 6.6
Requires PHP: 8.3
Tested up to: 7.1
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Local security for WordPress with a report-first firewall, login controls, CSP previews, and resumable file integrity checks.

== Description ==

Qsec Security gives site administrators a local dashboard for reviewing WordPress security controls, checking files, and testing changes before enforcing them. Open **Settings > Qsec** to see configuration checks and scan history.

[Source code and issue tracker](https://github.com/qa3me/qsec)

* **Report-first firewall.** See daily matches for selected configuration and version-control paths on public GET and HEAD requests that reach WordPress. Choose report only, block and report, or off.
* **Native login protection.** Enable a one-minute cooldown for repeated failed password attempts from the same source and login name. Turn on aggregate login reports separately. Choose a dark, light, or device-matched style for the native login screen. The optional author credit is off by default.
* **Header preview.** Try a Content Security Policy in report-only mode on a specific page. Inspect observed resource origins and use the same-site header probe to review response headers. Review the draft in context before you use it.
* **Local file inspection.** Inspect uploads, plugins, and themes for suspicious indicators or matches against hashes you provide. Compare WordPress core files in resumable batches against an imported checksum reference.
* **Configuration review.** Review cached update information, public registration settings, and selected hardening controls. Download an aggregate JSON summary. If the separate [Two-Factor plugin](https://wordpress.org/plugins/two-factor/) is installed, Qsec can also show administrator enrollment totals.
* **English and Persian.** The Persian interface includes right-to-left layouts and Jalali dates. The English login heading uses the included Michroma webfont.

= Privacy and external services =

Qsec runs locally and does not send telemetry, scan results, or login data to a Qsec service. Firewall and optional login reports store daily counts without raw IP addresses, usernames, passwords, or request content. The cooldown uses a short-lived keyed hash for the request source and login name. Scan summaries can be cleared in the dashboard, and a resumable core scan temporarily stores the imported checksum map and progress. The exported JSON does not include site URLs, account names, file paths, or secrets.

For a core comparison, an administrator can open the [WordPress.org checksum service](https://api.wordpress.org/core/checksums/1.0/) and import the matching version and locale. The header probe sends a HEAD request to the same page on your own site. The optional Two-Factor plugin is installed separately.

= Copyright and licenses =

Qsec Security is copyright © 2026 Behzad Qasemi (QA3). The plugin is distributed under GPL-2.0-or-later. The included Michroma font retains its SIL Open Font License, included in `assets/michroma-ofl.txt`.

== Installation ==

1. Install and activate Qsec Security on a single-site WordPress installation.
2. Open **Settings > Qsec**. Check the firewall report before deciding whether to enable blocking.
3. Choose any optional login, inspection, or hardening controls you want to use.

== Frequently Asked Questions ==

= Does the firewall block requests immediately? =

The default mode records matches and leaves the normal WordPress response in place. Enable **Block and report** to return HTTP 403 on matching paths.

= Which requests are covered by the firewall? =

The firewall checks public GET and HEAD paths that reach WordPress. It does not inspect form bodies or the WordPress REST API. Configure your host or reverse proxy to protect files and traffic handled before WordPress.

= Does the file inspection remove malware? =

File inspection is read-only. It reports indicators and hash matches for review, and shows when scan coverage was limited.

= Is the Content Security Policy enforced by the preview? =

The administrator preview sends a report-only header. Each draft depends on the resources observed on the selected page.

== Screenshots ==

1. The security dashboard with configuration checks and sample scan history.
2. The dark theme for the native WordPress login and password recovery screens.
3. Sample daily login and firewall reports, with the firewall in report-only mode.
4. A report-only Content Security Policy preview showing the draft and same-site header probe.
5. The Persian dashboard with a right-to-left layout and Jalali dates.

== Changelog ==

= 1.0.0 =
* First stable release with a report-first firewall, security header previews, login controls, and resumable file integrity checks.
* Includes English and Persian dashboards and login screens, with Jalali dates in Persian.

= 0.8.0 =
* Use the Qsec PHP namespace, Michroma for English login headings, and Jalali dates in the Persian interface.
* Recognize the separately licensed local Farhang Dot 1 heading font in private builds.
* Make the public login credit an explicit opt-in.

= 0.7.0 =
* Added a local firewall with report-only by default, optional blocking, aggregate reports and recovery-mode bypass.

= 0.6.0 =
* Added opt-in local login reports, temporary password-attempt limits, and reset and recovery paths.
* Added staggered SVG point motion and locally hosted site heading fonts. The bundled Michroma font is covered by its included SIL Open Font License.

= 0.5.0 =
* Renamed to Qsec. Added dark green and light login designs, device appearance, administrator previews, optional SVG motion and copyright, and a public registration review.

= 0.4.0 =
* Renamed to Nivarban Security. Added Persian localization, an on-demand security review, and a privacy-safe report export.

= 0.3.0 =
* Resumable core comparisons, local malware heuristics and optional Two-Factor integration.

= 0.2.0 =
* Added a dashboard, bounded core integrity comparison, local scan history, optional hardening controls and native login styling.

= 0.1.0 =
* Initial private development build.
