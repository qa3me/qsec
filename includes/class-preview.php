<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Preview {
	private const QUERY = '_qa3_csp_preview';
	private const ACTION = 'qa3_csp_preview';
	private const REPORT_HEADER = 'Content-Security-Policy-Report-Only';
	private const POLICY = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';";

	public static function register( string $plugin_file ): void {
		if ( in_recovery() ) {
			return;
		}

		add_action( 'admin_bar_menu', array( self::class, 'toolbar' ), 100 );
		// Core's canonical and legacy redirects run earlier.
		add_action(
			'template_redirect',
			static function () use ( $plugin_file ): void {
				self::start( $plugin_file );
			},
			99
		);
	}

	public static function allowed( string $method, mixed $nonce, bool $manager, bool $verified, bool $recovery ): bool {
		return ! $recovery && 'GET' === $method && is_string( $nonce ) && '' !== $nonce && $manager && $verified;
	}

	public static function url( string $url ): string {
		return add_query_arg( self::QUERY, wp_create_nonce( self::ACTION ), $url );
	}

	public static function toolbar( \WP_Admin_Bar $bar ): void {
		if ( is_admin() || ! current_user_can( 'manage_options' ) || ! ( is_singular() || is_front_page() ) ) {
			return;
		}
		$url = is_front_page() ? home_url( '/' ) : get_permalink( get_queried_object_id() );
		if ( is_string( $url ) && '' !== $url ) {
			$bar->add_node(
				array(
					'id'    => 'qa3-csp-preview',
					'title' => esc_html__( 'Qsec CSP preview', 'qsec-security' ),
					'href'  => self::url( $url ),
				)
			);
		}
	}

	private static function start( string $plugin_file ): void {
		$method = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Validate the exact nonce format before checking it with WordPress.
		$nonce  = $_GET[ self::QUERY ] ?? '';
		if ( 'GET' !== $method || ! is_string( $nonce ) || ! preg_match( '/^[a-zA-Z0-9]{10}$/D', $nonce ) ) {
			return;
		}
		$manager = current_user_can( 'manage_options' );
		if ( ! self::allowed( $method, $nonce, $manager, $manager && false !== wp_verify_nonce( $nonce, self::ACTION ), in_recovery() ) ) {
			return;
		}
		if ( headers_sent() || is_admin() || is_404() || is_feed() || is_embed() || is_robots() || is_trackback() ||
			wp_is_json_request() || ! ( is_singular() || is_front_page() ) ) {
			return;
		}

		$preview_sent = true;
		foreach ( headers_list() as $line ) {
			if ( 0 === stripos( $line, 'Location:' ) ||
				( 0 === stripos( $line, 'Content-Type:' ) && ! preg_match( '~^Content-Type:\s*text/html(?:[;\s]|$)~i', $line ) ) ) {
				return;
			}
			if ( 0 === stripos( $line, self::REPORT_HEADER . ':' ) ) {
				$preview_sent = false;
			}
		}

		nocache_headers();
		header( 'Cache-Control: private, no-store, max-age=0', true );
		if ( $preview_sent ) {
			header( self::REPORT_HEADER . ': ' . self::POLICY, false );
		}
		add_action(
			'wp_enqueue_scripts',
			static function () use ( $plugin_file ): void {
				wp_enqueue_script( 'qa3-csp-preview', plugins_url( 'assets/csp-preview.js', $plugin_file ), array(), VERSION, true );
			}
		);
		add_action(
			'wp_footer',
			static function () use ( $preview_sent ): void {
				?>
				<details id="qa3-csp-preview-panel" open>
					<summary><?php esc_html_e( 'Qsec Content Security Policy preview', 'qsec-security' ); ?></summary>
					<p><?php echo esc_html( $preview_sent
						? __( 'A report-only starter policy is active for this request. Review browser developer tools for violations.', 'qsec-security' )
						: __( 'An existing report-only policy was detected. It remains in place.', 'qsec-security' ) ); ?></p>
					<p><?php esc_html_e( 'This draft reflects resources observed in one page load. Inline code, late requests and other pages require separate review. Refresh the draft after interacting with the page.', 'qsec-security' ); ?></p>
					<p><label for="qa3-csp-draft"><?php esc_html_e( 'Draft policy', 'qsec-security' ); ?></label></p>
					<textarea id="qa3-csp-draft" rows="7" cols="50" readonly></textarea>
					<p>
						<button id="qa3-csp-refresh" type="button"><?php esc_html_e( 'Refresh draft', 'qsec-security' ); ?></button>
						<span role="status"><?php esc_html_e( 'Observations requiring manual review:', 'qsec-security' ); ?> <span id="qa3-csp-omitted">—</span></span>
					</p>
					<p>
						<button id="qa3-csp-audit" type="button"
							data-loading="<?php echo esc_attr__( 'Reading response headers…', 'qsec-security' ); ?>"
							data-error="<?php echo esc_attr__( 'The header probe failed. Inspect the page response in the browser’s Network tab.', 'qsec-security' ); ?>">
							<?php esc_html_e( 'Inspect existing security headers', 'qsec-security' ); ?>
						</button>
					</p>
					<p><?php esc_html_e( 'The probe reads a HEAD response from this page. Your host may send different headers for GET requests.', 'qsec-security' ); ?></p>
					<pre id="qa3-csp-audit-result" aria-live="polite"></pre>
				</details>
				<?php
			},
			20
		);
	}
}
