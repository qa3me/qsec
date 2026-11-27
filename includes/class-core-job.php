<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Core_Job {
	private const TTL = 86400;

	public static function start( string $reference, string $site, int $now ): array {
		$expected = Integrity::reference( $reference );
		return array(
			'id'       => bin2hex( random_bytes( 16 ) ),
			'site'     => $site,
			'updated'  => $now,
			'expected' => $expected,
			'total'    => count( $expected ),
			'cursor'   => 0,
			'checked'  => 0,
			'issues'   => 0,
			'findings' => array(),
			'done'     => false,
			'complete' => false,
		);
	}

	public static function current( array $job, string $site, int $now ): bool {
		return $site === $job['site'] && $job['updated'] >= $now - self::TTL;
	}

	public static function can_step( array $job, string $id, int $cursor, string $site, int $now ): bool {
		return ! $job['done'] && $id === $job['id'] && $cursor === $job['cursor'] && self::current( $job, $site, $now );
	}

	public static function advance( array $job, string $directory, int $now, int $max_files = 96, int $budget_ns = 450000000 ): array {
		if ( $job['done'] ) {
			return $job;
		}
		$batch = ( new Integrity() )->batch( $directory, $job['expected'], $job['cursor'], $max_files, $budget_ns );
		$job['cursor']   = $batch['cursor'];
		$job['checked'] += $batch['checked'];
		$job['issues']  += $batch['issues'];
		$job['findings'] = array_slice( array_merge( $job['findings'], $batch['findings'] ), 0, 60 );
		$job['updated']  = $now;
		$job['done']     = $job['cursor'] === $job['total'];
		$job['complete'] = $job['done'] && $job['checked'] === $job['total'];
		if ( $job['done'] ) {
			unset( $job['expected'] );
		}
		return $job;
	}
}
