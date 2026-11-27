<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Typography {
	private const DIRECTORY = 'nivarban-local-fonts';
	private const TITLE = 'farhang-dot1-bold.woff2';
	private const BODY = 'tahrir-regular.woff2';

	public static function dashboard( string $plugin_file ): void {
		if ( ! Locale::persian() ) {
			return;
		}
		self::face( 'qa3-dashboard', 'Qsec Farhang', 700, self::farhang( $plugin_file ), admin_url() );
		self::face( 'qa3-dashboard', 'Qsec Tahrir', 400, self::legacy_font( self::BODY ), admin_url() );
	}

	public static function login( string $plugin_file ): void {
		if ( Locale::persian() ) {
			$family = 'Qsec Farhang';
			$weight = 700;
			$url    = self::farhang( $plugin_file );
		} elseif ( preg_match( '/^en(?:[_-]|$)/i', determine_locale() ) ) {
			$family = 'Qsec Michroma';
			$weight = 400;
			$url    = plugins_url( 'assets/michroma-latin.woff2', $plugin_file );
		} else {
			return;
		}
		if ( self::face( 'qa3-login', $family, $weight, $url, wp_login_url() ) ) {
			wp_add_inline_style( 'qa3-login', '.login.qsec-login--preset .wp-login-logo a{font-family:"' . $family . '",Tahoma,system-ui,sans-serif;font-weight:' . $weight . '}' );
		}
	}

	private static function farhang( string $plugin_file ): string {
		$file = 'assets/' . self::TITLE;
		return is_file( dirname( $plugin_file ) . '/' . $file ) ? plugins_url( $file, $plugin_file ) : self::legacy_font( self::TITLE );
	}

	private static function legacy_font( string $font ): string {
		$file = self::DIRECTORY . '/' . $font;
		return defined( 'NIVARBAN_LOCAL_FONTS' ) && true === NIVARBAN_LOCAL_FONTS && is_file( WP_CONTENT_DIR . '/' . $file ) ? content_url( $file ) : '';
	}

	private static function face( string $handle, string $family, int $weight, string $url, string $page_url ): bool {
		if ( '' === self::origin( $url ) || self::origin( $url ) !== self::origin( $page_url ) ) {
			return false;
		}
		$font_url = esc_url_raw( $url, array( 'http', 'https' ) );
		return wp_add_inline_style( $handle, '@font-face{font-family:"' . $family . '";src:url("' . $font_url . '") format("woff2");font-weight:' . $weight . ';font-style:normal;font-display:swap}' );
	}

	private static function origin( string $url ): string {
		$parts = wp_parse_url( $url );
		$scheme = strtolower( $parts['scheme'] ?? '' );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) || empty( $parts['host'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return '';
		}
		$port = $parts['port'] ?? ( 'https' === $scheme ? 443 : 80 );
		return $scheme . '://' . strtolower( $parts['host'] ) . ':' . $port;
	}
}
