<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'qa3_wp_security_login' );
delete_option( 'qa3_wp_security_hardening' );
delete_option( 'qa3_wp_security_scan_history' );
delete_option( 'qa3_wp_security_core_scan' );
delete_option( 'qsec_login_guard_settings' );
delete_option( 'qsec_login_guard_state' );
delete_option( 'qsec_firewall_mode' );
delete_option( 'qsec_firewall_report' );
