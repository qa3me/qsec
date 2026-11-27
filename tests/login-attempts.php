<?php
declare(strict_types=1);

if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$root = dirname( __DIR__ );
define( 'ABSPATH', $root . '/' );
require $root . '/includes/class-login-attempts.php';

use Qsec\Security\Login_Attempts;

function check_attempts( bool $pass, string $label ): void {
	if ( ! $pass ) {
		throw new RuntimeException( $label );
	}
	echo "PASS $label\n";
}

$now = 1795780800;
$key = Login_Attempts::key( '198.51.100.7', 'ADMIN', 'lab-secret' );
$other = Login_Attempts::key( '198.51.100.8', 'admin', 'lab-secret' );
check_attempts( $key === Login_Attempts::key( '198.51.100.7', 'admin', 'lab-secret' ), 'login buckets normalize ASCII case' );
check_attempts( $key !== $other && $key !== Login_Attempts::key( '198.51.100.7', 'editor', 'lab-secret' ), 'different sources and login names have independent buckets' );
check_attempts( '' === Login_Attempts::key( '198.51.100.7, 198.51.100.8', 'admin', 'lab-secret' ) && '' === Login_Attempts::key( '198.51.100.7', '', 'lab-secret' ), 'invalid source and empty name never form a bucket' );
check_attempts( $key === Login_Attempts::key( '::ffff:198.51.100.7', 'admin', 'lab-secret' ), 'mapped IPv6 and IPv4 identify the same source' );

$state = Login_Attempts::read( false, $now );
for ( $i = 0; $i < 4; ++$i ) {
	$state = Login_Attempts::record( $state, 'password', $key, $now + $i, true );
}
check_attempts( ! Login_Attempts::blocked( $state, $key, $now + 4 ), 'four failed attempts are below the threshold' );
$state = Login_Attempts::record( $state, 'password', $key, $now + 4, true );
check_attempts( Login_Attempts::blocked( $state, $key, $now + 5 ) && ! Login_Attempts::blocked( $state, $other, $now + 5 ), 'fifth failure makes only the same pair temporarily wait' );
$state = Login_Attempts::record( $state, 'limited', $key, $now + 40, true );
$state = Login_Attempts::record( $state, 'password', $key, $now + 55, true );
check_attempts( ! Login_Attempts::blocked( $state, $key, $now + 64 ), 'blocked submissions and in-flight failures never extend the fixed cooldown' );
check_attempts( ! isset( Login_Attempts::read( $state, $now + 64 )['pairs'][ $key ] ), 'expired cooldown also discards its counter' );

$state = Login_Attempts::record( $state, 'second_factor', '', $now + 55, true );
$counts = array_values( $state['days'] )[0];
check_attempts( array( 'password' => 6, 'second_factor' => 1, 'limited' => 1 ) === $counts, 'daily aggregate keeps password, second factor and limited requests separate' );
check_attempts( array() === Login_Attempts::read( $state, $now + 7 * 86400 )['days'], 'old aggregates are absent after seven UTC days' );

$bounded = Login_Attempts::read( array(), $now );
for ( $i = 0; $i < 300; ++$i ) {
	$bounded = Login_Attempts::record( $bounded, 'password', hash( 'sha256', (string) $i ), $now, false );
}
check_attempts( 256 === count( $bounded['pairs'] ) && array() === $bounded['days'], 'rate-limit storage is capped and reporting can be disabled independently' );
check_attempts( ! str_contains( serialize( $state ), '198.51.100' ) && ! str_contains( serialize( $state ), 'ADMIN' ), 'state does not keep raw addresses or usernames' );
