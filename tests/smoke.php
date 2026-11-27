<?php
declare(strict_types=1);

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

$root = dirname( __DIR__ );
if ( ! is_file( $root . '/includes/class-uploads-scanner.php' ) || ! is_file( $root . '/includes/class-preview.php' ) ) {
	fwrite( STDERR, "Missing modules for the QA3 defensive smoke tests.\n" );
	exit( 1 );
}
define( 'ABSPATH', $root . '/' );
require $root . '/includes/class-uploads-scanner.php';
require $root . '/includes/class-preview.php';
require $root . '/includes/class-login.php';

use Qsec\Security\Login;
use Qsec\Security\Preview;
use Qsec\Security\Uploads_Scanner;

function expect( bool $condition, string $name ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $name );
	}
	echo "PASS $name\n";
}

$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qa3-' . bin2hex( random_bytes( 8 ) );
mkdir( $dir );
mkdir( $dir . '/nested' );
file_put_contents( $dir . '/photo.png', 'harmless file fixture' );
file_put_contents( $dir . '/nested/maintenance.PHP', 'non-executable synthetic fixture' );
// The marker is data in a test file. The scanner never includes or executes files.
file_put_contents( $dir . '/nested/banner.jpg', 'fixture ' . '<' . '?php' . ' inert marker' );

try {
	$scan = new Uploads_Scanner();
	$report = $scan->scan( $dir );
	$findings = array_column( $report['findings'], 'signal', 'path' );
	expect( $report['complete'] && 3 === $report['files'], 'scan visits the readable fixture tree' );
	expect( ! isset( $findings['photo.png'] ), 'ordinary image does not get flagged' );
	expect( 'executable_extension' === ( $findings['nested/maintenance.PHP'] ?? null ), 'unexpected executable extension is reported' );
	expect( 'php_marker' === ( $findings['nested/banner.jpg'] ?? null ), 'PHP marker in a media file is reported' );
	expect( is_file( $dir . '/nested/maintenance.PHP' ), 'scan leaves files unchanged' );
	expect( ! $scan->scan( $dir, 1 )['complete'], 'entry budget reports partial coverage' );
	expect( ! $scan->scan( $dir . '/missing' )['complete'], 'missing scan root cannot be reported as clean' );
	expect( ! $scan->scan( '' )['complete'] && 0 === $scan->scan( '' )['files'], 'empty path does not fall back to the working directory' );
	if ( function_exists( 'symlink' ) && @symlink( $dir . '/nested', $dir . '/linked' ) ) {
		$linked = $scan->scan( $dir );
		expect( ! $linked['complete'] && 3 === $linked['files'], 'directory link is skipped without rescanning its target' );
		unlink( $dir . '/linked' );
	}
	expect( Preview::allowed( 'GET', 'token', true, true, false ), 'explicit verified administrator preview can run' );
	expect( ! Preview::allowed( 'GET', 'token', true, true, true ), 'recovery disables preview' );
	expect( ! Preview::allowed( 'GET', 'token', false, true, false ), 'non-admin cannot trigger preview' );
	expect( ! Preview::allowed( 'GET', 'token', true, false, false ), 'invalid nonce cannot trigger preview' );
	expect( ! Preview::allowed( 'POST', 'token', true, true, false ), 'preview ignores POST' );
	expect( ! Preview::allowed( 'GET', [ 'token' ], true, true, false ), 'array nonce is rejected' );
	expect( '#aabbcc' === Login::color( '#AABBCC' ), 'valid login color is normalized' );
	expect( '' === Login::color( '#fff; color:red' ), 'only six-digit hex is accepted from login settings' );
	expect( 'classic' === Login::theme( array( 'title' => 'Existing style' ) ), 'old login branding keeps its look after upgrade' );
	expect( 'wordpress' === Login::theme( array() ) && 'wordpress' === Login::theme( array( 'theme' => 'wordpress', 'title' => 'Saved title' ) ), 'native appearance stays available with or without a saved title' );
	expect( 'dark' === Login::theme( array( 'theme' => 'dark' ) ) && 'light' === Login::theme( array( 'theme' => 'light' ) ) && 'system' === Login::theme( array( 'theme' => 'system' ) ), 'both palettes and the device preference work without a custom title' );
	expect( 'wordpress' === Login::theme( array( 'theme' => array( 'dark' ) ) ) && 'wordpress' === Login::theme( array( 'theme' => 'dark extra-class' ) ), 'unknown or structured theme names use the native appearance' );
	expect( ! Login::show_credit( array( 'theme' => 'dark' ) ) && ! Login::show_credit( array( 'credit' => 'yes' ) ), 'public copyright is absent without explicit opt-in' );
	expect( Login::show_credit( array( 'credit' => '1' ) ) && Login::show_credit( array( 'credit' => true ) ) && ! Login::show_credit( array( 'credit' => '0' ) ), 'public copyright follows the saved choice' );
} finally {
	unlink( $dir . '/nested/banner.jpg' );
	unlink( $dir . '/nested/maintenance.PHP' );
	unlink( $dir . '/photo.png' );
	rmdir( $dir . '/nested' );
	rmdir( $dir );
}
