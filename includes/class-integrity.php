<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Integrity {
	private const BATCH_BYTES = 8 * 1024 * 1024;
	private const MAX_FILE_BYTES = 16 * 1024 * 1024;
	private const ROOT_FILES = array(
		'index.php', 'license.txt', 'readme.html', 'wp-activate.php', 'wp-blog-header.php',
		'wp-comments-post.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php',
		'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php',
		'wp-trackback.php', 'xmlrpc.php',
	);

	public function scan( string $directory, string $json, int $max_files = 5500 ): array {
		return $this->batch( $directory, self::reference( $json ), 0, $max_files, 1500000000 );
	}

	public function batch( string $directory, array $expected, int $offset, int $max_files = 96, int $budget_ns = 450000000 ): array {
		$total  = count( $expected );
		$offset = max( 0, min( $offset, $total ) );
		$root = '' === $directory ? false : realpath( $directory );
		$result = array( 'reference' => $total, 'cursor' => $offset, 'checked' => 0, 'issues' => 0, 'complete' => false, 'findings' => array() );
		if ( false === $root || ! is_dir( $root ) ) {
			$result['cursor'] = $total;
			return $result;
		}

		$deadline   = hrtime( true ) + max( 1, $budget_ns );
		$bytes_left = self::BATCH_BYTES;

		foreach ( array_slice( $expected, $offset, max( 1, $max_files ), true ) as $path => $checksum ) {
			if ( $result['cursor'] > $offset && ( 0 === $bytes_left || hrtime( true ) >= $deadline ) ) {
				break;
			}
			$file = $root . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $path );
			clearstatcache( true, $file );
			$resolved = realpath( $file );
			$signal = '';
			if ( is_link( $file ) || ( false !== $resolved && ! self::same_path( $resolved, $file ) ) ) {
				++$result['cursor'];
				continue;
			}
			if ( false === $resolved ) {
				$signal = 'missing';
			} elseif ( is_file( $resolved ) ) {
				$size = @filesize( $resolved );
				if ( false === $size || $size > self::MAX_FILE_BYTES ) {
					++$result['cursor'];
					continue;
				}
				if ( $size > $bytes_left && $result['cursor'] > $offset ) {
					break;
				}
				// A known core asset may exceed an ordinary batch's byte budget.
				// It gets its own bounded streaming request, with no other files.
				$bytes_left = max( 0, $bytes_left - $size );
				$digest = @hash_file( 'md5', $resolved );
				if ( false === $digest ) {
					++$result['cursor'];
					continue;
				}
				$signal = hash_equals( $checksum, $digest ) ? '' : 'changed';
			} else {
				++$result['cursor'];
				continue;
			}
			++$result['cursor'];
			++$result['checked'];
			if ( '' !== $signal ) {
				++$result['issues'];
				if ( count( $result['findings'] ) < 60 ) {
					$result['findings'][] = array( 'path' => $path, 'signal' => $signal );
				}
			}
		}
		$result['complete'] = $total === $result['cursor'] && $result['checked'] === $total - $offset;
		return $result;
	}

	public static function reference( string $json ): array {
		if ( strlen( $json ) > 650000 ) {
			throw new \InvalidArgumentException( 'Reference exceeds the maximum size.' );
		}
		$decoded = json_decode( $json, true, 8 );
		$checksums = is_array( $decoded ) ? ( $decoded['checksums'] ?? null ) : null;
		if ( ! is_array( $checksums ) || count( $checksums ) > 8000 ) {
			throw new \InvalidArgumentException( 'Invalid checksum reference.' );
		}

		$expected = array();
		foreach ( $checksums as $path => $hash ) {
			if ( ! is_string( $path ) || strlen( $path ) > 240 ) {
				throw new \InvalidArgumentException( 'Invalid path in checksum reference.' );
			}
			if ( ! ( str_starts_with( $path, 'wp-admin/' ) || str_starts_with( $path, 'wp-includes/' ) || in_array( $path, self::ROOT_FILES, true ) ) ) {
				continue;
			}
			if ( ! preg_match( '~^(?:[a-zA-Z0-9_-][a-zA-Z0-9_.-]*/)*[a-zA-Z0-9_-][a-zA-Z0-9_.-]*$~D', $path ) ) {
				throw new \InvalidArgumentException( 'Invalid path in checksum reference.' );
			}
			if ( ! is_string( $hash ) || ! preg_match( '/^[0-9a-f]{32}$/iD', $hash ) ) {
				throw new \InvalidArgumentException( 'Invalid digest in checksum reference.' );
			}
			$expected[ $path ] = strtolower( $hash );
		}
		if ( ! $expected ) {
			throw new \InvalidArgumentException( 'No supported core paths in checksum reference.' );
		}
		return $expected;
	}

	private static function same_path( string $resolved, string $expected ): bool {
		if ( '\\' !== DIRECTORY_SEPARATOR ) {
			return $resolved === $expected;
		}
		return 0 === strcasecmp( str_replace( '\\', '/', $resolved ), str_replace( '\\', '/', $expected ) );
	}
}
