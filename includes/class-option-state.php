<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Option_State {
	public static function change( string $name, callable $update ): void {
		global $wpdb;
		for ( $attempt = 0; $attempt < 4; ++$attempt ) {
			$before = get_option( $name );
			$after  = $update( $before );
			if ( $after === $before ) {
				return;
			}
			if ( false === $before ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- add_option() can overwrite a concurrent first insert.
				$changed = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, %s)", $name, maybe_serialize( $after ), 'no' ) );
				wp_cache_delete( 'notoptions', 'options' );
			} else {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Retry when a concurrent request changed the stored value.
				$changed = $wpdb->update( $wpdb->options, array( 'option_value' => maybe_serialize( $after ) ), array( 'option_name' => $name, 'option_value' => maybe_serialize( $before ) ), array( '%s' ), array( '%s', '%s' ) );
			}
			wp_cache_delete( $name, 'options' );
			if ( 1 === $changed || false === $changed ) {
				return;
			}
		}
	}
}
