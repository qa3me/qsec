<?php
declare(strict_types=1);

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

$root = dirname( __DIR__ );
define( 'ABSPATH', $root . '/' );
require $root . '/includes/class-firewall-rules.php';

use Qsec\Security\Firewall_Rules;

function check_firewall( bool $pass, string $label ): void {
	if ( ! $pass ) {
		throw new RuntimeException( $label );
	}
	echo "PASS $label\n";
}

check_firewall( 'report' === Firewall_Rules::mode( null ) && 'report' === Firewall_Rules::mode( array( 'block' ) ), 'missing and unexpected settings default to report only' );
check_firewall( 'block' === Firewall_Rules::mode( 'block' ) && 'off' === Firewall_Rules::mode( 'off' ), 'explicit block and off settings are respected' );
check_firewall( 'config' === Firewall_Rules::match( Firewall_Rules::path( 'GET', '/wp-config.php.bak' ), array( '/' ) ), 'exact configuration copy is detected' );
check_firewall( 'repository' === Firewall_Rules::match( Firewall_Rules::path( 'HEAD', '/.git/qsec-fixture' ), array( '/' ) ), 'HEAD to root repository metadata is inspected' );
check_firewall( 'config' === Firewall_Rules::match( Firewall_Rules::path( 'GET', '/wordpress/.env?display=1' ), array( '/blog/', '/wordpress/' ) ), 'the WordPress installation path works alongside a separate site path' );
check_firewall( '' === Firewall_Rules::match( '/site-other/.env', array( '/site/' ) ), 'root paths are matched on a segment boundary' );
check_firewall( 'config' === Firewall_Rules::match( '/فارسی/.env', array( '/%D9%81%D8%A7%D8%B1%D8%B3%DB%8C/' ) ), 'encoded subdirectory names match the decoded site path' );
check_firewall( '' === Firewall_Rules::match( Firewall_Rules::path( 'GET', '/search/?name=.env' ), array( '/' ) ), 'form query values are never rules inputs' );
check_firewall( '' === Firewall_Rules::path( 'POST', '/.env' ) && '' === Firewall_Rules::path( 'OPTIONS', '/.env' ), 'form writes and API preflight are outside inspection' );
check_firewall( '' === Firewall_Rules::match( '/wp-json/example/.env', array( '/' ) ), 'an application route which mentions a sensitive name is not a protected root path' );
check_firewall( '' === Firewall_Rules::match( '/.well-known/site-verification', array( '/' ) ) && '' === Firewall_Rules::match( '/wp-login.php', array( '/' ) ), 'normal verification and login locations pass' );
check_firewall( '' === Firewall_Rules::path( 'GET', '/' . str_repeat( 'x', 2048 ) ) && '' === Firewall_Rules::path( 'GET', '/' ), 'oversized paths and paths without rule candidates skip early' );
check_firewall( '/.env' === Firewall_Rules::path( 'GET', '/.env?' . str_repeat( 'x', 4000 ) ), 'path limits apply to the path alone' );

$now = 1795780800;
$report = Firewall_Rules::record( false, 'repository', 'report', $now );
$report = Firewall_Rules::record( $report, 'config', 'block', $now );
$today  = array_values( Firewall_Rules::read( $report, $now ) )[0];
check_firewall( 1 === $today['repository']['report'] && 0 === $today['repository']['block'] && 1 === $today['config']['block'], 'rule reports and actual blocks keep separate aggregates' );
check_firewall( array() === Firewall_Rules::read( $report, $now + 7 * 86400 ), 'aggregates outside the seven-day window expire' );
check_firewall( $report === Firewall_Rules::record( $report, 'unknown', 'block', $now ) && $report === Firewall_Rules::record( $report, 'config', 'off', $now ), 'unrecognized events do not create stored report fields' );
$day = array_key_first( $report );
$report[ $day ]['config']['block'] = 1000;
check_firewall( $report === Firewall_Rules::record( $report, 'config', 'block', $now ), 'a saturated counter stops making new writes' );
