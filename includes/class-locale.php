<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Locale {
	private const PERSIAN_MONTHS = array( 'فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند' );
	private const LEAP_BREAKS = array( -61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060, 2097, 2192, 2262, 2324, 2394, 2456, 3178 );

	public static function persian(): bool {
		return 1 === preg_match( '/^fa(?:[_-]|$)/i', determine_locale() );
	}

	public static function date( string $style, int $timestamp, ?\DateTimeZone $timezone = null ): string {
		if ( self::persian() ) {
			$local = ( new \DateTimeImmutable( '@' . $timestamp ) )->setTimezone( $timezone ?? wp_timezone() );
			$year = (int) $local->format( 'Y' ) - 621;
			if ( $year > self::LEAP_BREAKS[0] && $year < self::LEAP_BREAKS[ count( self::LEAP_BREAKS ) - 1 ] ) {
				return self::persian_date( $style, $local, $year );
			}
		}
		$format = match ( $style ) {
			'short'  => 'M j',
			'report' => 'j M Y',
			'year'   => 'Y',
			default  => get_option( 'date_format', 'F j, Y' ),
		};
		return (string) wp_date( $format, $timestamp, $timezone );
	}

	private static function persian_date( string $style, \DateTimeImmutable $local, int $year ): string {
		// Convert the local civil date in UTC so daylight-saving transitions cannot change its day offset.
		$civil = new \DateTimeImmutable( $local->format( 'Y-m-d' ), new \DateTimeZone( 'UTC' ) );
		$start = $civil->setDate( $year + 621, 3, self::march_day( $year ) );
		if ( $civil < $start ) {
			--$year;
			$start = $start->setDate( $year + 621, 3, self::march_day( $year ) );
		}
		$offset = $start->diff( $civil )->days;
		$month  = $offset < 186 ? intdiv( $offset, 31 ) : 6 + intdiv( $offset - 186, 30 );
		$day    = 1 + ( $offset < 186 ? $offset % 31 : ( $offset - 186 ) % 30 );
		$value  = match ( $style ) {
			'year'  => (string) $year,
			'short' => $day . ' ' . self::PERSIAN_MONTHS[ $month ],
			default => $day . ' ' . self::PERSIAN_MONTHS[ $month ] . ' ' . $year,
		};
		return strtr( $value, array( '0' => '۰', '1' => '۱', '2' => '۲', '3' => '۳', '4' => '۴', '5' => '۵', '6' => '۶', '7' => '۷', '8' => '۸', '9' => '۹' ) );
	}

	private static function march_day( int $year ): int {
		// Borkowski's Jalali calendar: count leap days between the known cycle breaks.
		$previous = self::LEAP_BREAKS[0];
		$leaps = -14;
		$span = 0;
		foreach ( array_slice( self::LEAP_BREAKS, 1 ) as $break ) {
			$span = $break - $previous;
			if ( $year < $break ) {
				break;
			}
			$leaps += 8 * intdiv( $span, 33 ) + intdiv( $span % 33, 4 );
			$previous = $break;
		}
		$elapsed = $year - $previous;
		$leaps += 8 * intdiv( $elapsed, 33 ) + intdiv( $elapsed % 33 + 3, 4 );
		if ( 4 === $span % 33 && 4 === $span - $elapsed ) {
			++$leaps;
		}
		$gregorian_year = $year + 621;
		$gregorian_leaps = intdiv( $gregorian_year, 4 ) - intdiv( 3 * ( intdiv( $gregorian_year, 100 ) + 1 ), 4 ) - 150;
		return 20 + $leaps - $gregorian_leaps;
	}
}
