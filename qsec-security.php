<?php
/**
 * Plugin Name: Qsec Security
 * Plugin URI: https://qsec.qa3.me/
 * Description: Local security dashboard, file integrity, header preview and WordPress hardening.
 * Version: 1.0.1
 * Requires at least: 6.6
 * Requires PHP: 8.3
 * Author: Behzad Qasemi (QA3)
 * Author URI: https://qa3.me/
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: qsec-security
 * Domain Path: /languages
 *
 * @package QA3WPSecurity
 * @copyright 2026 Behzad Qasemi (QA3)
 */

namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const VERSION = '1.0.1';
const OPTION = 'qa3_wp_security_login';
const PROJECT_URL = 'https://github.com/qa3me/qsec';

function in_recovery(): bool {
	return defined( 'QA3_SECURITY_RECOVERY_MODE' ) && true === QA3_SECURITY_RECOVERY_MODE;
}

add_action(
	'init',
	static function (): void {
		// phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- Private installs use the bundled locale, before a WordPress.org language pack exists.
		load_plugin_textdomain( 'qsec-security', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
	},
	0
);

require_once __DIR__ . '/includes/class-preview.php';
require_once __DIR__ . '/includes/class-locale.php';
require_once __DIR__ . '/includes/class-login.php';
require_once __DIR__ . '/includes/class-option-state.php';
require_once __DIR__ . '/includes/class-login-attempts.php';
require_once __DIR__ . '/includes/class-login-guard.php';
require_once __DIR__ . '/includes/class-firewall-rules.php';
require_once __DIR__ . '/includes/class-firewall.php';
require_once __DIR__ . '/includes/class-hardening.php';

Preview::register( __FILE__ );
Login::register( __FILE__ );
Login_Guard::register();
Firewall::register();
Hardening::register();

if ( is_admin() ) {
	require_once __DIR__ . '/includes/class-uploads-scanner.php';
	require_once __DIR__ . '/includes/class-integrity.php';
	require_once __DIR__ . '/includes/class-scan-history.php';
	require_once __DIR__ . '/includes/class-core-job.php';
	require_once __DIR__ . '/includes/class-core-scan.php';
	require_once __DIR__ . '/includes/class-malware.php';
	require_once __DIR__ . '/includes/class-two-factor.php';
	require_once __DIR__ . '/includes/class-dashboard.php';
	require_once __DIR__ . '/includes/class-review.php';
	require_once __DIR__ . '/includes/class-typography.php';
	require_once __DIR__ . '/includes/class-admin.php';
	Core_Scan::register();
	Review::register();
	Admin::register( __FILE__ );
}
