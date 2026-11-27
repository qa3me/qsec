<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Login {
	private const THEMES = array( 'wordpress', 'classic', 'light', 'dark', 'system' );
	private const PREVIEW_THEMES = array( 'light', 'dark' );

	public static function register( string $plugin_file ): void {
		if ( in_recovery() ) {
			return;
		}
		add_action(
			'login_enqueue_scripts',
			static function () use ( $plugin_file ): void {
				$options = self::settings();
				$theme   = self::preview_theme() ?? self::theme( $options );
				$title   = is_string( $options['title'] ?? null ) ? $options['title'] : '';
				if ( 'wordpress' === $theme || ( 'classic' === $theme && '' === $title ) ) {
					return;
				}
				wp_enqueue_style( 'qa3-login', plugins_url( 'assets/login.css', $plugin_file ), array( 'login' ), VERSION );
				$motion = ! array_key_exists( 'motion', $options ) || ! empty( $options['motion'] );
				add_filter(
					'login_body_class',
					static function ( array $classes ) use ( $theme, $motion ): array {
						$classes[] = 'qa3-branded';
						$classes[] = 'qsec-login--' . $theme;
					if ( 'classic' !== $theme ) {
						$classes[] = 'qsec-login--preset';
					}
						if ( ! $motion ) {
							$classes[] = 'qsec-login--still';
						}
						return $classes;
					}
				);
				$color = self::color( $options['color'] ?? '' );
				if ( 'classic' === $theme ) {
					add_filter( 'login_message', static fn ( mixed $message ): mixed => self::message( $message, $title, $color ) );
					return;
				}
				require_once __DIR__ . '/class-typography.php';
				Typography::login( $plugin_file );

				add_filter( 'login_headerurl', static fn (): string => home_url( '/' ) );
			add_filter( 'login_headertext', static fn (): string => esc_html( '' !== $title ? $title : get_bloginfo( 'name' ) ) );
				add_action( 'login_header', array( self::class, 'artwork' ) );
				if ( self::show_credit( $options ) ) {
					add_action( 'login_footer', array( self::class, 'credit' ) );
				}
			}
		);
	}

	public static function theme( array $options ): string {
		if ( ! array_key_exists( 'theme', $options ) ) {
			return is_string( $options['title'] ?? null ) && '' !== $options['title'] ? 'classic' : 'wordpress';
		}
		return in_array( $options['theme'], self::THEMES, true ) ? $options['theme'] : 'wordpress';
	}

	public static function preview_url( string $theme ): string {
		return add_query_arg( array( 'qsec_login_preview' => $theme, '_qsec_preview_token' => wp_create_nonce( 'qsec_login_preview_' . $theme ) ), wp_login_url() );
	}

	private static function preview_theme(): ?string {
		if ( ! isset( $_GET['qsec_login_preview'], $_GET['_qsec_preview_token'] ) ||
			'GET' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) || ! current_user_can( 'manage_options' ) ) {
			return null;
		}
		$theme = sanitize_text_field( wp_unslash( $_GET['qsec_login_preview'] ) );
		$nonce = sanitize_text_field( wp_unslash( $_GET['_qsec_preview_token'] ) );
		return in_array( $theme, self::PREVIEW_THEMES, true ) && wp_verify_nonce( $nonce, 'qsec_login_preview_' . $theme ) ? $theme : null;
	}

	public static function color( mixed $value ): string {
		return is_string( $value ) && preg_match( '/^#[0-9a-f]{6}$/iD', $value ) ? strtolower( $value ) : '';
	}

	public static function sanitize( mixed $raw ): array {
		$raw   = is_array( $raw ) ? $raw : array();
		$title = isset( $raw['title'] ) && is_string( $raw['title'] ) ? sanitize_text_field( $raw['title'] ) : '';
		return array(
			'title'  => wp_html_excerpt( $title, 120 ),
			'color'  => self::color( $raw['color'] ?? '' ),
			'theme'  => self::theme( $raw ),
			'motion' => ! array_key_exists( 'motion', $raw ) || '1' === $raw['motion'] || true === $raw['motion'],
			'credit' => self::show_credit( $raw ),
		);
	}

	public static function show_credit( array $options ): bool {
		return in_array( $options['credit'] ?? null, array( true, '1' ), true );
	}

	public static function settings(): array {
		$raw = get_option( OPTION, array() );
		return is_array( $raw ) ? $raw : array();
	}

	private static function message( mixed $message, string $title, string $color ): mixed {
		if ( ! is_string( $message ) ) {
			return $message;
		}
		$style = '' === $color ? '' : ' style="' . esc_attr( 'border-color:' . $color ) . '"';
		return '<p class="message qa3-login-brand"' . $style . '><strong>' . esc_html( $title ) . '</strong></p>' . $message;
	}

	public static function artwork(): void {
		?>
		<div class="qsec-login-art" aria-hidden="true">
			<svg class="qsec-login-graphic" viewBox="0 0 440 440" fill="none" focusable="false">
				<g class="qsec-login-grid" stroke="currentColor">
					<circle cx="220" cy="220" r="166"/><circle cx="220" cy="220" r="132"/>
					<circle cx="220" cy="220" r="100" stroke-dasharray="2 6"/>
					<path d="M220 26v388M26 220h388M83 83l274 274m0-274L83 357"/>
					<path d="M50 110V50h60m220 0h60v60m0 220v60h-60m-220 0H50v-60"/>
				</g>
				<g class="qsec-login-shield">
					<path d="M220 128c26 17 55 25 73 28v51c0 47-27 80-73 104-46-24-73-57-73-104v-51c18-3 47-11 73-28Z"/>
					<path d="m186 218 23 23 46-46" stroke-linecap="round" stroke-linejoin="round"/>
				</g>
				<g class="qsec-login-nodes" fill="currentColor">
					<circle cx="220" cy="54" r="5"/><circle cx="386" cy="220" r="5"/>
					<circle cx="54" cy="220" r="5"/><circle cx="220" cy="386" r="5"/>
				</g>
			</svg>
		</div>
		<?php
	}

	public static function credit(): void {
		/* translators: %s: Copyright year. */
		printf( '<p class="qsec-login-credit">%s</p>', esc_html( sprintf( __( '© %s Behzad Qasemi · Qsec', 'qsec-security' ), Locale::date( 'year', time() ) ) ) );
	}
}
