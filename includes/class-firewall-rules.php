<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Firewall_Rules {
	public const COUNT_LIMIT = 1000;
	private const DAY = 86400;
	private const TYPES = array( 'config', 'repository' );

	public static function mode( mixed $value ): string {
		return in_array( $value, array( 'off', 'report', 'block' ), true ) ? $value : 'report';
	}

	public static function path( string $method, string $target ): string {
		if ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) || ! str_starts_with( $target, '/' ) ) {
			return '';
		}
		$length = strcspn( $target, '?', 0, 2049 );
		if ( $length > 2048 ) {
			return '';
		}
		$path = rawurldecode( substr( $target, 0, $length ) );
		return str_contains( $path, '.' ) && ! preg_match( '/[\x00-\x1f\x7f]/', $path ) ? $path : '';
	}

	public static function match( string $path, array $roots ): string {
		foreach ( $roots as $root ) {
			$prefix = rtrim( rawurldecode( $root ), '/' ) . '/';
			if ( ! str_starts_with( $path, $prefix ) ) {
				continue;
			}
			$relative = substr( $path, strlen( $prefix ) );
			if ( preg_match( '~^\.(?:git|svn)(?:/|$)~iD', $relative ) ) {
				return 'repository';
			}
			if ( preg_match( '#^(?:\.env(?:\.(?:local|production|development|staging|test|bak|old))?|wp-config\.php(?:\.(?:bak|old|orig|save)|~)?)/?$#iD', $relative ) ) {
				return 'config';
			}
		}
		return '';
	}

	public static function record( mixed $stored, string $type, string $mode, int $now ): array {
		$days = self::read( $stored, $now );
		if ( in_array( $type, self::TYPES, true ) && in_array( $mode, array( 'report', 'block' ), true ) ) {
			$day = self::day( $now );
			$days[ $day ] ??= self::empty_day();
			$days[ $day ][ $type ][ $mode ] = min( self::COUNT_LIMIT, $days[ $day ][ $type ][ $mode ] + 1 );
		}
		return $days;
	}

	public static function read( mixed $stored, int $now ): array {
		$days  = array();
		$today = self::day( $now );
		for ( $day = $today - 6 * self::DAY; $day <= $today; $day += self::DAY ) {
			if ( ! isset( $stored[ $day ] ) || ! is_array( $stored[ $day ] ) ) {
				continue;
			}
			$days[ $day ] = self::empty_day();
			foreach ( self::TYPES as $type ) {
				foreach ( array( 'report', 'block' ) as $mode ) {
					$count = $stored[ $day ][ $type ][ $mode ] ?? 0;
					$days[ $day ][ $type ][ $mode ] = is_int( $count ) ? max( 0, min( self::COUNT_LIMIT, $count ) ) : 0;
				}
			}
		}
		return $days;
	}

	private static function empty_day(): array {
		return array_fill_keys( self::TYPES, array( 'report' => 0, 'block' => 0 ) );
	}

	private static function day( int $timestamp ): int {
		return $timestamp - $timestamp % self::DAY;
	}
}
