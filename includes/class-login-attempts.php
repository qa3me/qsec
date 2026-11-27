<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Login_Attempts {
	private const LIMIT = 5;
	private const WINDOW = 300;
	private const COOLDOWN = 60;
	private const MAX_PAIRS = 256;
	private const DAY = 86400;
	private const EMPTY_DAY = array( 'password' => 0, 'second_factor' => 0, 'limited' => 0 );

	public static function key( string $address, string $name, string $salt ): string {
		$name = strtolower( trim( $name ) );
		if ( '' === $name || strlen( $name ) > 254 || ! filter_var( $address, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$packed = inet_pton( $address );
		if ( str_starts_with( $packed, str_repeat( "\0", 10 ) . "\xff\xff" ) ) {
			$packed = substr( $packed, 12 );
		}
		return hash_hmac( 'sha256', bin2hex( $packed ) . ':' . $name, $salt );
	}

	public static function read( mixed $stored, int $now ): array {
		$pairs = array();
		foreach ( array_slice( (array) ( $stored['pairs'] ?? array() ), -self::MAX_PAIRS, null, true ) as $key => $pair ) {
			if ( ! is_array( $pair ) || ! is_int( $pair['count'] ?? null ) || ! is_int( $pair['until'] ?? null ) ) {
				continue;
			}
			$remaining = $pair['until'] - $now;
			$lifetime = self::LIMIT === $pair['count'] ? self::COOLDOWN : self::WINDOW;
			if ( $remaining > 0 && $remaining <= $lifetime ) {
				$pairs[ $key ] = $pair;
			}
		}
		$days = array();
		for ( $day = self::day( $now ) - 6 * self::DAY; $day <= $now; $day += self::DAY ) {
			if ( isset( $stored['days'][ $day ] ) && is_array( $stored['days'][ $day ] ) ) {
				$days[ $day ] = array_intersect_key( $stored['days'][ $day ], self::EMPTY_DAY ) + self::EMPTY_DAY;
			}
		}
		return array( 'pairs' => $pairs, 'days' => $days );
	}

	public static function blocked( array $state, string $key, int $now ): bool {
		$pair = $state['pairs'][ $key ] ?? array();
		return self::LIMIT === ( $pair['count'] ?? null ) && $now < $pair['until'] && $pair['until'] - $now <= self::COOLDOWN;
	}

	public static function record( array $state, string $event, string $key, int $now, bool $report ): array {
		if ( $report && array_key_exists( $event, self::EMPTY_DAY ) ) {
			$day = self::day( $now );
			$counts = $state['days'][ $day ] ?? self::EMPTY_DAY;
			++$counts[ $event ];
			$state['days'][ $day ] = $counts;
		}
		if ( 'password' !== $event || '' === $key || self::blocked( $state, $key, $now ) ) {
			return $state;
		}
		$pair = $state['pairs'][ $key ] ?? array( 'count' => 0, 'until' => $now + self::WINDOW );
		++$pair['count'];
		if ( self::LIMIT === $pair['count'] ) {
			$pair['until'] = $now + self::COOLDOWN;
		}
		$state['pairs'][ $key ] = $pair;
		if ( count( $state['pairs'] ) > self::MAX_PAIRS ) {
			foreach ( $state['pairs'] as $old_key => $old_pair ) {
				if ( self::LIMIT !== $old_pair['count'] ) {
					unset( $state['pairs'][ $old_key ] );
					break;
				}
			}
		}
		return $state;
	}

	private static function day( int $timestamp ): int {
		return $timestamp - $timestamp % self::DAY;
	}
}
