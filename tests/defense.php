<?php
declare(strict_types=1);

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

$project = dirname( __DIR__ );
$modules = array( 'class-integrity.php', 'class-scan-history.php', 'class-hardening.php' );
foreach ( $modules as $module ) {
	if ( ! is_file( $project . '/includes/' . $module ) ) {
		fwrite( STDERR, "Missing defensive module: $module\n" );
		exit( 1 );
	}
}
define( 'ABSPATH', $project . '/' );
foreach ( $modules as $module ) {
	require $project . '/includes/' . $module;
}

use Qsec\Security\Hardening;
use Qsec\Security\Integrity;
use Qsec\Security\Scan_History;

function check( bool $condition, string $test ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $test );
	}
	echo "PASS $test\n";
}

$reference = '900150983cd24fb0d6963f7d28e17f72';
$manifest = json_encode(
	array( 'checksums' => array(
		'wp-load.php' => $reference,
		'wp-admin/changed.php' => $reference,
		'wp-includes/missing.php' => $reference,
		'wp-content/private.php' => $reference,
		'wp-content/plugins/akismet/.htaccess' => $reference,
		'wp-content/themes/example/font_slnt,wght.ttf' => $reference,
		'wp-config.php' => $reference,
	) ),
	JSON_THROW_ON_ERROR
);
$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qa3-core-' . bin2hex( random_bytes( 8 ) );
mkdir( $root );
mkdir( $root . '/wp-admin' );
mkdir( $root . '/wp-includes' );
file_put_contents( $root . '/wp-load.php', 'abc' );
file_put_contents( $root . '/wp-admin/changed.php', 'fixture edit' );
try {
	$report = ( new Integrity() )->scan( $root, $manifest );
	$issues = array_column( $report['findings'], 'signal', 'path' );
	check( 3 === $report['reference'] && 3 === $report['checked'] && $report['complete'], 'core scan covers only supported core paths' );
	check( $issues === array( 'wp-admin/changed.php' => 'changed', 'wp-includes/missing.php' => 'missing' ), 'core scan distinguishes differences and missing files' );
	check( 'fixture edit' === file_get_contents( $root . '/wp-admin/changed.php' ), 'core scan is read-only' );
	check( ! ( new Integrity() )->scan( $root, $manifest, 1 )['complete'], 'core scan shows partial coverage when the file budget is exhausted' );
	foreach ( array( '{', '{"checksums":{"wp-load.php":"wrong"}}', '{"checksums":{"wp-admin/../wp-load.php":"' . $reference . '"}}', '{"checksums":{"wp-config.php":"' . $reference . '"}}' ) as $bad ) {
		try {
			( new Integrity() )->scan( $root, $bad );
			check( false, 'invalid, out-of-scope or traversing manifest must fail' );
		} catch ( InvalidArgumentException ) {
			check( true, 'invalid, out-of-scope or traversing manifest is rejected' );
		}
	}
} finally {
	unlink( $root . '/wp-load.php' );
	unlink( $root . '/wp-admin/changed.php' );
	rmdir( $root . '/wp-admin' );
	rmdir( $root . '/wp-includes' );
	rmdir( $root );
}

$now = 1795780800;
$data = Scan_History::record( array(), 'uploads', 15, 2, true, $now - 3600 );
$data = Scan_History::record( $data, 'uploads', 18, 0, true, $now );
$data = Scan_History::record( $data, 'core', 4, 1, false, $now );
$days = Scan_History::days( $data, $now, new DateTimeZone( 'UTC' ) );
check( 7 === count( $days ) && null === $days[0]['uploads'], 'days without scans stay empty rather than zero' );
check( 0 === $days[6]['uploads']['issues'], 'latest scan with zero findings remains an observed zero' );
check( 1 === $days[6]['core']['issues'] && false === $days[6]['core']['complete'], 'trend keeps distinct scan types and partial coverage' );
check( array() === Scan_History::read( $data, $now + 31 * 86400 ), 'expired scan summaries are excluded' );
for ( $i = 0; $i < 70; $i++ ) {
	$data = Scan_History::record( $data, 'uploads', 10, 0, true, $now + $i );
}
check( 40 === count( $data ) && array_keys( $data[0] ) === array( 'time', 'kind', 'files', 'issues', 'complete' ), 'history has a fixed limit and only summary fields' );

$settings = Hardening::sanitize( array( 'editor' => '1', 'pingbacks' => '1', 'extra' => 'anything' ) );
check( array( 'editor' => true, 'pingbacks' => true ) === $settings, 'hardening settings accept only the defined flags' );
check( array( 'do_not_allow' ) === Hardening::editor_caps( array( 'edit_themes' ), 'edit_themes', $settings, false ), 'opt-in editor policy denies the core editor capability' );
check( array( 'edit_themes' ) === Hardening::editor_caps( array( 'edit_themes' ), 'edit_themes', $settings, true ), 'recovery restores the original editor decision' );
check( array( 'manage_options' ) === Hardening::editor_caps( array( 'manage_options' ), 'manage_options', $settings, false ), 'editor policy preserves unrelated administrator capabilities' );
$methods = array( 'pingback.ping' => 'test', 'pingback.extensions.getPingbacks' => 'test', 'wp.getUsersBlogs' => 'untouched' );
check( array( 'wp.getUsersBlogs' => 'untouched' ) === Hardening::xmlrpc_methods( $methods, $settings, false ), 'opt-in pingback policy preserves other XML-RPC methods' );
check( $methods === Hardening::xmlrpc_methods( $methods, array(), false ), 'pingback protection is off by default' );
