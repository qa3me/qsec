<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Uploads_Scanner {
	private const FILE_PREFIX_BYTES = 16384;
	private const TOTAL_PREFIX_BYTES = 2097152;
	private const MAX_FINDINGS = 60;
	private const BUDGET_NS = 750000000;

	public function scan( string $path, int $entry_limit = 1200 ): array {
		$result = array( 'files' => 0, 'findings' => array(), 'complete' => false );
		if ( '' === $path || $entry_limit < 1 ) {
			return $result;
		}
		$root   = realpath( $path );
		if ( false === $root || ! is_dir( $root ) ) {
			return $result;
		}
		$root       = self::normalize( $root );
		$prefix     = rtrim( $root, '/' ) . '/';
		$folders    = array( $root );
		$deadline   = hrtime( true ) + self::BUDGET_NS;
		$bytes_left = self::TOTAL_PREFIX_BYTES;
		$entries    = 0;
		$result['complete'] = true;

		while ( $folders ) {
			$folder = array_pop( $folders );
			if ( hrtime( true ) >= $deadline ) {
				$result['complete'] = false;
				break;
			}
			if ( ! self::same_path( realpath( $folder ), $folder ) || is_link( $folder ) ) {
				$result['complete'] = false;
				continue;
			}
			try {
				$listing = new \FilesystemIterator( $folder, \FilesystemIterator::SKIP_DOTS );
				foreach ( $listing as $entry ) {
					if ( ++$entries > $entry_limit || hrtime( true ) >= $deadline ) {
						$result['complete'] = false;
						break 2;
					}
					$file = self::normalize( $entry->getPathname() );
					if ( $entry->isLink() || ! str_starts_with( $file, $prefix ) || ! self::same_path( realpath( $file ), $file ) ) {
						$result['complete'] = false;
						continue;
					}
					if ( $entry->isDir() ) {
						$folders[] = $file;
						continue;
					}
					if ( ! $entry->isFile() ) {
						$result['complete'] = false;
						continue;
					}
					++$result['files'];
					$signal = self::file_signal( $file, $bytes_left );
					if ( null === $signal ) {
						$result['complete'] = false;
					} elseif ( '' !== $signal ) {
						$result['findings'][] = array( 'path' => substr( $file, strlen( $prefix ) ), 'signal' => $signal );
						if ( count( $result['findings'] ) >= self::MAX_FINDINGS ) {
							$result['complete'] = false;
							break 2;
						}
					}
				}
			} catch ( \RuntimeException ) {
				$result['complete'] = false;
			}
		}
		return $result;
	}

	private static function normalize( string $path ): string {
		return '\\' === DIRECTORY_SEPARATOR ? str_replace( '\\', '/', $path ) : $path;
	}

	private static function same_path( string|false $resolved, string $expected ): bool {
		if ( false === $resolved ) {
			return false;
		}
		$resolved = self::normalize( $resolved );
		return '\\' === DIRECTORY_SEPARATOR ? 0 === strcasecmp( $resolved, $expected ) : $resolved === $expected;
	}

	private static function file_signal( string $path, int &$bytes_left ): ?string {
		$extension = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
		if ( preg_match( '/^(?:php\d*|phtml|pht|phar|phps)$/D', $extension ) ) {
			return 'executable_extension';
		}
		if ( ! in_array( $extension, array( 'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg', 'pdf', 'ico' ), true ) ) {
			return '';
		}
		if ( $bytes_left < self::FILE_PREFIX_BYTES ) {
			return null;
		}
		// Local regular file only. The bytes are inspected as data.
		$bytes = @file_get_contents( $path, false, null, 0, self::FILE_PREFIX_BYTES );
		if ( false === $bytes ) {
			return null;
		}
		$bytes_left -= strlen( $bytes );
		return preg_match( '/<\?(?:php\b|=)/i', $bytes ) ? 'php_marker' : '';
	}
}
