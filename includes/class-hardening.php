<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Hardening {
	public const OPTION = 'qa3_wp_security_hardening';
	private const EDITOR_CAPS = array( 'edit_files', 'edit_plugins', 'edit_themes' );

	public static function register(): void {
		if ( in_recovery() ) {
			return;
		}
		add_filter(
			'map_meta_cap',
			static function ( array $mapped, string $cap ): array {
				if ( ! in_array( $cap, self::EDITOR_CAPS, true ) ) {
					return $mapped;
				}
				return self::editor_caps( $mapped, $cap, self::settings(), false );
			},
			100,
			2
		);
		add_filter(
			'xmlrpc_methods',
			static function ( array $methods ): array {
				return self::xmlrpc_methods( $methods, self::settings(), false );
			},
			100
		);
	}

	public static function settings(): array {
		$settings = get_option( self::OPTION, array() );
		return is_array( $settings ) ? $settings : array();
	}

	public static function sanitize( mixed $raw ): array {
		$raw = is_array( $raw ) ? $raw : array();
		return array(
			'editor'    => in_array( $raw['editor'] ?? false, array( true, '1' ), true ),
			'pingbacks' => in_array( $raw['pingbacks'] ?? false, array( true, '1' ), true ),
		);
	}

	public static function editor_caps( array $mapped, string $capability, array $settings, bool $recovery ): array {
		if ( ! $recovery && true === ( $settings['editor'] ?? false ) && in_array( $capability, self::EDITOR_CAPS, true ) ) {
			return array( 'do_not_allow' );
		}
		return $mapped;
	}

	public static function xmlrpc_methods( array $methods, array $settings, bool $recovery ): array {
		if ( ! $recovery && true === ( $settings['pingbacks'] ?? false ) ) {
			unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		}
		return $methods;
	}

	public static function checks(): array {
		$https = 'https' === wp_parse_url( home_url( '/' ), PHP_URL_SCHEME );
		$local = 'local' === wp_get_environment_type();
		$debug = defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY;
		$options = self::settings();
		$caps = map_meta_cap( 'edit_plugins', get_current_user_id() );
		return array(
			array( 'label' => __( 'Public URL uses HTTPS', 'qsec-security' ), 'status' => $https ? 'good' : ( $local ? 'info' : 'review' ) ),
			array( 'label' => __( 'WordPress debug display is off', 'qsec-security' ), 'status' => $debug ? 'review' : 'good' ),
			array( 'label' => __( 'Dashboard file editor is restricted for this administrator', 'qsec-security' ), 'status' => in_array( 'do_not_allow', $caps, true ) ? 'good' : 'review' ),
			array( 'label' => __( 'Qsec blocks XML-RPC pingback methods', 'qsec-security' ), 'status' => ! in_recovery() && true === ( $options['pingbacks'] ?? false ) ? 'good' : 'info' ),
		);
	}
}
