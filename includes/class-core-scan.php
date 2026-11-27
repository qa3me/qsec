<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Core_Scan {
	public const OPTION = 'qa3_wp_security_core_scan';
	public const AJAX = 'qa3_core_next';
	public const NONCE = 'qa3_core_continue';

	public static function register(): void {
		add_action( 'wp_ajax_' . self::AJAX, array( self::class, 'ajax' ) );
	}

	public static function get(): ?array {
		$job = get_option( self::OPTION, null );
		if ( ! is_array( $job ) || ! isset( $job['id'], $job['site'], $job['updated'], $job['cursor'] ) ) {
			return null;
		}
		if ( ! Core_Job::current( $job, self::site(), time() ) ) {
			self::replace( $job, null );
			return null;
		}
		return $job;
	}

	public static function start( string $reference ): bool {
		$before = self::get();
		if ( null !== $before && ! $before['done'] ) {
			return false;
		}
		$job = Core_Job::start( $reference, self::site(), time() );
		if ( null === $before ) {
			return add_option( self::OPTION, $job, '', false );
		}
		return self::replace( $before, $job );
	}

	public static function dismiss( string $id ): bool {
		$job = self::get();
		return null !== $job && $job['id'] === $id && self::replace( $job, null );
	}

	public static function step( string $id, int $cursor ): ?array {
		$before = self::get();
		$now    = time();
		if ( null === $before || ! Core_Job::can_step( $before, $id, $cursor, self::site(), $now ) ) {
			return null;
		}
		$after = Core_Job::advance( $before, ABSPATH, $now );
		if ( ! self::replace( $before, $after ) ) {
			return null;
		}
		if ( $after['done'] ) {
			$history = Scan_History::record( get_option( Scan_History::OPTION, array() ), 'core', $after['checked'], $after['issues'], $after['complete'], $now );
			update_option( Scan_History::OPTION, $history, false );
		}
		unset( $after['expected'], $after['findings'], $after['site'] );
		return $after;
	}

	public static function ajax(): void {
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) || ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		check_ajax_referer( self::NONCE );
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- Both fields have exact format validation below.
		$id     = $_POST['qa3_job'] ?? '';
		$cursor = $_POST['qa3_cursor'] ?? '';
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput
		if ( ! is_string( $id ) || ! is_string( $cursor ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! preg_match( '/^[0-9]{1,4}$/D', $cursor ) ) {
			wp_send_json_error( null, 400 );
		}
		$next = self::step( $id, (int) $cursor );
		if ( null === $next ) {
			wp_send_json_error( null, 409 );
		}
		wp_send_json_success( $next );
	}

	private static function site(): string {
		return get_bloginfo( 'version' ) . '|' . get_locale();
	}

	/**
	 * Compare and swap the stored scan row. A duplicate or slow request cannot
	 * replace a newer cursor or resurrect a cancelled scan.
	 */
	private static function replace( array $before, ?array $after ): bool {
		global $wpdb;
		$where = array( 'option_name' => self::OPTION, 'option_value' => maybe_serialize( $before ) );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery -- The value match keeps cancellation and progression atomic.
		if ( null === $after ) {
			$changed = $wpdb->delete( $wpdb->options, $where, array( '%s', '%s' ) );
		} else {
			$changed = $wpdb->update(
				$wpdb->options,
				array( 'option_value' => maybe_serialize( $after ) ),
				$where,
				array( '%s' ),
				array( '%s', '%s' )
			);
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery
		wp_cache_delete( self::OPTION, 'options' );
		return 1 === $changed;
	}
}
