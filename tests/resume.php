<?php
declare(strict_types=1);

if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$project = dirname( __DIR__ );
if ( ! is_file( $project . '/includes/class-core-job.php' ) ) {
	fwrite( STDERR, "Missing resumable core job.\n" );
	exit( 1 );
}
define( 'ABSPATH', $project . '/' );
require $project . '/includes/class-integrity.php';
require $project . '/includes/class-core-job.php';

use Qsec\Security\Core_Job;

function check_resume( bool $pass, string $test ): void {
	if ( ! $pass ) {
		throw new RuntimeException( $test );
	}
	echo "PASS $test\n";
}

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qa3-resume-' . bin2hex( random_bytes( 8 ) );
mkdir( $directory );
mkdir( $directory . '/wp-includes' );
file_put_contents( $directory . '/wp-includes/a.php', 'abc' );
file_put_contents( $directory . '/wp-includes/b.php', 'fixture changed' );
file_put_contents( $directory . '/wp-includes/d.php', 'abc' );
$reference = '900150983cd24fb0d6963f7d28e17f72';
$json = json_encode( array( 'checksums' => array_fill_keys( array(
	'wp-includes/a.php', 'wp-includes/b.php', 'wp-includes/c.php', 'wp-includes/d.php',
), $reference ) ), JSON_THROW_ON_ERROR );

try {
	$now = 1795780800;
	$job = Core_Job::start( $json, '7.1.5|en_US', $now );
	check_resume( 0 === $job['cursor'] && 4 === $job['total'], 'core job starts with all four references pending' );
	check_resume( Core_Job::can_step( $job, $job['id'], 0, '7.1.5|en_US', $now ), 'matching job and cursor can continue' );
	check_resume( ! Core_Job::can_step( $job, $job['id'], 0, '7.2|en_US', $now ), 'site version change invalidates continuation' );
	check_resume( ! Core_Job::can_step( $job, $job['id'], 0, '7.1.5|en_US', $now + 86401 ), 'expired job cannot continue' );
	$job = Core_Job::advance( $job, $directory, $now + 1, 2 );
	check_resume( 2 === $job['cursor'] && 2 === $job['checked'] && ! $job['done'], 'first bounded batch leaves remaining files pending' );
	check_resume( ! Core_Job::can_step( $job, $job['id'], 0, '7.1.5|en_US', $now + 1 ), 'replayed cursor cannot double-count findings' );
	$job = json_decode( json_encode( $job, JSON_THROW_ON_ERROR ), true, 8, JSON_THROW_ON_ERROR );
	$job = Core_Job::advance( $job, $directory, $now + 2, 2, 1 );
	check_resume( 3 === $job['cursor'], 'a very small time budget still allows forward progress' );
	$job = Core_Job::advance( $job, $directory, $now + 3, 2 );
	check_resume( 4 === $job['cursor'] && 4 === $job['checked'] && $job['done'] && $job['complete'], 'resume finishes all references across requests' );
	check_resume( 2 === $job['issues'] && array_column( $job['findings'], 'signal' ) === array( 'changed', 'missing' ), 'matches, changes and missing files aggregate correctly' );
	check_resume( ! isset( $job['expected'] ), 'completed job drops the imported checksum map' );

	$stream = fopen( $directory . '/wp-includes/large-fixture.js', 'wb' );
	if ( false === $stream || ! ftruncate( $stream, 13 * 1024 * 1024 ) ) {
		throw new RuntimeException( 'Could not create the inert large-file fixture.' );
	}
	fclose( $stream );
	$large_map = json_encode( array( 'checksums' => array(
		'wp-includes/a.php' => $reference,
		'wp-includes/large-fixture.js' => '2397abfa719391c815cd2f0144b66391',
		'wp-includes/d.php' => $reference,
	) ), JSON_THROW_ON_ERROR );
	$large_job = Core_Job::start( $large_map, '7.1.5|en_US', $now );
	$large_job = Core_Job::advance( $large_job, $directory, $now, 10, 10000000000 );
	check_resume( 1 === $large_job['cursor'], 'an oversized core asset waits for a dedicated batch' );
	$large_job = Core_Job::advance( $large_job, $directory, $now, 10, 10000000000 );
	check_resume( 2 === $large_job['cursor'] && 2 === $large_job['checked'], 'one large core asset is streamed without skipping it' );
	$large_job = Core_Job::advance( $large_job, $directory, $now, 10, 10000000000 );
	check_resume( $large_job['complete'] && 0 === $large_job['issues'], 'later batches still reach full coverage after the large asset' );
} finally {
	unlink( $directory . '/wp-includes/a.php' );
	unlink( $directory . '/wp-includes/b.php' );
	unlink( $directory . '/wp-includes/d.php' );
	if ( is_file( $directory . '/wp-includes/large-fixture.js' ) ) {
		unlink( $directory . '/wp-includes/large-fixture.js' );
	}
	rmdir( $directory . '/wp-includes' );
	rmdir( $directory );
}
