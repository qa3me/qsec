<?php
declare(strict_types=1);

if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$project = dirname( __DIR__ );
if ( ! is_file( $project . '/includes/class-review.php' ) ) {
	fwrite( STDERR, "Missing site review.\n" );
	exit( 1 );
}
define( 'ABSPATH', $project . '/' );
require $project . '/includes/class-scan-history.php';
require $project . '/includes/class-review.php';

use Qsec\Security\Review;

function check_review( bool $pass, string $label ): void {
	if ( ! $pass ) {
		throw new RuntimeException( $label );
	}
	echo "PASS $label\n";
}

$now = 1795780800;
$core = (object) array(
	'last_checked' => $now - 60,
	'updates'      => array(
		(object) array( 'response' => 'latest' ),
		(object) array( 'response' => 'upgrade' ),
		(object) array( 'response' => 'upgrade' ),
	),
);
$plugins = (object) array( 'last_checked' => $now - 90000, 'response' => array( (object) array(), (object) array() ) );
$result = Review::updates( $core, $plugins, false, $now );
check_review( $result['core'] === array( 'state' => 'current', 'pending' => 1 ), 'core upgrade offers count as one actionable update' );
check_review( $result['plugins'] === array( 'state' => 'stale', 'pending' => 2 ), 'stale cached offers are marked with their age' );
check_review( $result['themes'] === array( 'state' => 'unknown', 'pending' => null ), 'missing cache is distinct from zero updates' );
check_review( Review::updates( false, (object) array( 'last_checked' => $now, 'response' => array(), 'no_update' => array( new stdClass() ) ), false, $now )['plugins']['pending'] === 0, 'a usable empty response is shown as zero updates' );

$admin_users = range( 1, 51 );
$counters = array();
$coverage = Review::coverage( $admin_users, static function ( int $id ) use ( &$counters ): bool {
	$counters[] = $id;
	return 0 === $id % 2;
} );
check_review( $coverage === array( 'checked' => 50, 'enrolled' => 25, 'partial' => true ) && 50 === count( $counters ), 'administrator enrollment review is bounded and aggregate-only' );

check_review( 'closed' === Review::registration( false, 'administrator', true )['state'], 'a privileged default role does not imply open registration' );
check_review( 'review' === Review::registration( true, 'editor', true )['state'], 'open registration with a publishing role deserves review' );
check_review( 'open' === Review::registration( true, 'subscriber', false )['state'], 'ordinary open registration is reported without changing access' );
check_review( 'unknown' === Review::registration( true, '', null )['state'], 'missing default role is different from a verified low-privilege role' );

$export = Review::export( array(
	array( 'time' => $now, 'kind' => 'core', 'files' => 2, 'issues' => 1, 'complete' => true, 'path' => '/private-path', 'secret' => 'never-export' ),
), array( array( 'status' => 'good', 'label' => 'fixture-private-site.example' ) ), $now );
$data = json_encode( $export, JSON_THROW_ON_ERROR );
check_review( 1 === $export['checks']['good'] && 2 === $export['scans'][0]['files'], 'export retains actual summary counts' );
check_review( ! str_contains( $data, 'private-path' ) && ! str_contains( $data, 'never-export' ) && ! str_contains( $data, 'private-site' ), 'export omits paths, secrets and site labels' );
