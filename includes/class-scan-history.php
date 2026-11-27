<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Scan_History {
	public const OPTION = 'qa3_wp_security_scan_history';
	private const KINDS = array( 'uploads', 'core', 'malware' );
	private const MAX_AGE = 2592000;
	private const MAX_ROWS = 40;

	public static function read( mixed $data, int $now ): array {
		if ( ! is_array( $data ) ) {
			return array();
		}
		$rows = array();
		foreach ( array_slice( $data, 0, self::MAX_ROWS ) as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}
			$time = $item['time'] ?? 0;
			$kind = $item['kind'] ?? '';
			if ( ! is_int( $time ) || $time > $now || $time < $now - self::MAX_AGE || ! in_array( $kind, self::KINDS, true ) ) {
				continue;
			}
			$rows[] = array(
				'time'     => $time,
				'kind'     => $kind,
				'files'    => max( 0, (int) ( $item['files'] ?? 0 ) ),
				'issues'   => max( 0, (int) ( $item['issues'] ?? 0 ) ),
				'complete' => true === ( $item['complete'] ?? false ),
			);
		}
		return $rows;
	}

	public static function record( mixed $data, string $kind, int $files, int $issues, bool $complete, int $now ): array {
		$rows = self::read( $data, $now );
		if ( in_array( $kind, self::KINDS, true ) ) {
			array_unshift( $rows, array( 'time' => $now, 'kind' => $kind, 'files' => max( 0, $files ), 'issues' => max( 0, $issues ), 'complete' => $complete ) );
		}
		return array_slice( $rows, 0, self::MAX_ROWS );
	}

	public static function days( array $rows, int $now, \DateTimeZone $zone ): array {
		$end = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $zone )->setTime( 0, 0 );
		$days = array();
		for ( $i = 6; $i >= 0; --$i ) {
			$date = $end->modify( '-' . $i . ' days' );
			$days[ $date->format( 'Y-m-d' ) ] = array( 'date' => $date->getTimestamp(), 'uploads' => null, 'core' => null, 'malware' => null );
		}
		foreach ( self::read( $rows, $now ) as $row ) {
			$key = ( new \DateTimeImmutable( '@' . $row['time'] ) )->setTimezone( $zone )->format( 'Y-m-d' );
			$kind = $row['kind'];
			if ( isset( $days[ $key ] ) && ( null === $days[ $key ][ $kind ] || $days[ $key ][ $kind ]['time'] < $row['time'] ) ) {
				$days[ $key ][ $kind ] = $row;
			}
		}
		return array_values( $days );
	}
}
