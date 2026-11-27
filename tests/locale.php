<?php
declare(strict_types=1);

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require ABSPATH . 'includes/class-locale.php';

use Qsec\Security\Locale;

function determine_locale(): string {
	return $GLOBALS['qsec_test_locale'];
}

function wp_timezone(): DateTimeZone {
	return new DateTimeZone( 'Asia/Tehran' );
}

function wp_date( string $format, int $timestamp, ?DateTimeZone $timezone = null ): string {
	return ( new DateTimeImmutable( '@' . $timestamp ) )->setTimezone( $timezone ?? wp_timezone() )->format( $format );
}

function get_option( string $name, string $default ): string {
	return 'date_format' === $name ? 'F j, Y' : $default;
}

function check_local_date( string $expected, string $actual, string $label ): void {
	if ( $expected !== $actual ) {
		throw new RuntimeException( "$label: expected '$expected', got '$actual'" );
	}
	echo "PASS $label\n";
}

$utc = new DateTimeZone( 'UTC' );
$GLOBALS['qsec_test_locale'] = 'fa_IR';
$cases = array(
	'2024-03-19' => '۲۹ اسفند ۱۴۰۲',
	'2024-03-20' => '۱ فروردین ۱۴۰۳',
	'2025-03-20' => '۳۰ اسفند ۱۴۰۳',
	'2025-03-21' => '۱ فروردین ۱۴۰۴',
	'2026-03-20' => '۲۹ اسفند ۱۴۰۴',
	'2026-03-21' => '۱ فروردین ۱۴۰۵',
	'2026-11-27' => '۶ آذر ۱۴۰۵',
	'2000-02-29' => '۱۰ اسفند ۱۳۷۸',
);
foreach ( $cases as $gregorian => $persian ) {
	check_local_date( $persian, Locale::date( 'report', strtotime( $gregorian . 'T12:00:00Z' ), $utc ), 'Jalali date for ' . $gregorian );
}
$boundary = strtotime( '2026-03-20T20:45:00Z' );
check_local_date( '۱ فروردین', Locale::date( 'short', $boundary ), 'site-local dashboard date crosses into the new year' );
check_local_date( '۲۹ اسفند ۱۴۰۴', Locale::date( 'report', $boundary, $utc ), 'daily report preserves its UTC calendar day' );
check_local_date( '۱۴۰۵', Locale::date( 'year', $boundary ), 'Persian copyright uses the Jalali year and Persian digits' );

$GLOBALS['qsec_test_locale'] = 'en_US';
check_local_date( '20 Mar 2026', Locale::date( 'report', $boundary, $utc ), 'English reports use Gregorian date and Latin digits' );
check_local_date( 'March 21, 2026', Locale::date( 'long', $boundary ), 'English dashboard respects the configured date format' );
check_local_date( '2026', Locale::date( 'year', $boundary ), 'English copyright uses the Gregorian year' );
