<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Firewall {
	private const OPTION = 'qsec_firewall_mode';
	private const REPORT = 'qsec_firewall_report';
	private const SETTINGS_GROUP = 'qsec_firewall';
	private const CLEAR_ACTION = 'qsec_clear_firewall_report';

	public static function register(): void {
		if ( ! in_recovery() ) {
			add_action( 'template_redirect', array( self::class, 'inspect' ), 0 );
		}
	}

	public static function inspect(): void {
		$method = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- path() bounds and decodes the raw path without inspecting the query.
		$path = Firewall_Rules::path( $method, wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) );
		if ( '' === $path ) {
			return;
		}
		$type = Firewall_Rules::match( $path, array( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), (string) wp_parse_url( site_url( '/' ), PHP_URL_PATH ) ) );
		if ( '' === $type ) {
			return;
		}
		$mode = Firewall_Rules::mode( get_option( self::OPTION ) );
		if ( 'off' === $mode ) {
			return;
		}
		$now = time();
		Option_State::change( self::REPORT, static fn ( mixed $before ): array => Firewall_Rules::record( $before, $type, $mode, $now ) );
		if ( 'block' !== $mode ) {
			return;
		}
		nocache_headers();
		if ( 'HEAD' === $method ) {
			status_header( 403 );
			exit;
		}
		wp_die( esc_html__( 'This request was blocked.', 'qsec-security' ), '', array( 'response' => 403 ) );
	}

	public static function register_admin(): void {
		add_action( 'admin_post_' . self::CLEAR_ACTION, array( self::class, 'clear' ) );
		register_setting(
			self::SETTINGS_GROUP,
			self::OPTION,
			array(
				'type'              => 'string',
				'sanitize_callback' => array( Firewall_Rules::class, 'mode' ),
				'show_in_rest'      => false,
				'default'           => 'report',
			)
		);
	}

	public static function clear(): void {
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to clear firewall reports.', 'qsec-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::CLEAR_ACTION );
		delete_option( self::REPORT );
		wp_safe_redirect( admin_url( 'options-general.php?page=qa3-wp-security#qsec-firewall' ) );
		exit;
	}

	public static function panel( int $now ): void {
		$mode = Firewall_Rules::mode( get_option( self::OPTION ) );
		$days = Firewall_Rules::read( get_option( self::REPORT ), $now );
		?>
		<section class="qa3-panel" id="qsec-firewall" aria-labelledby="qsec-firewall-title">
			<h2 id="qsec-firewall-title"><?php esc_html_e( 'Local firewall', 'qsec-security' ); ?></h2>
			<p><?php esc_html_e( 'Inspects public GET and HEAD page paths that reach WordPress for configuration files, their backups and version-control metadata. Form submissions, login and the WordPress REST API follow their normal routes.', 'qsec-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
				<?php settings_fields( self::SETTINGS_GROUP ); ?>
				<p><label for="qsec-firewall-mode"><?php esc_html_e( 'Firewall mode', 'qsec-security' ); ?></label></p>
				<select id="qsec-firewall-mode" name="<?php echo esc_attr( self::OPTION ); ?>">
					<option value="report" <?php selected( $mode, 'report' ); ?>><?php esc_html_e( 'Report only (default)', 'qsec-security' ); ?></option>
					<option value="block" <?php selected( $mode, 'block' ); ?>><?php esc_html_e( 'Block and report', 'qsec-security' ); ?></option>
					<option value="off" <?php selected( $mode, 'off' ); ?>><?php esc_html_e( 'Off', 'qsec-security' ); ?></option>
				</select>
				<?php submit_button( __( 'Save firewall mode', 'qsec-security' ), 'secondary', 'submit', false ); ?>
			</form>
			<p><?php esc_html_e( 'Reports contain only rule totals for the last seven UTC days. The counter for each rule and mode stops at 1,000 per day.', 'qsec-security' ); ?></p>
			<?php if ( $days ) : ?>
				<table class="widefat striped qa3-data-table" id="qsec-firewall-report">
					<caption class="screen-reader-text"><?php esc_html_e( 'Firewall report', 'qsec-security' ); ?></caption>
					<thead><tr>
						<th scope="col"><?php esc_html_e( 'Date (UTC)', 'qsec-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Rule', 'qsec-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Reported', 'qsec-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Blocked', 'qsec-security' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( array_reverse( $days, true ) as $day => $counts ) : ?>
						<?php foreach ( $counts as $type => $count ) : ?>
							<?php if ( $count['report'] || $count['block'] ) : ?>
								<tr>
									<td><?php echo esc_html( Locale::date( 'report', $day, new \DateTimeZone( 'UTC' ) ) ); ?></td>
									<th scope="row"><?php echo esc_html( 'config' === $type ? __( 'Configuration file', 'qsec-security' ) : __( 'Repository metadata', 'qsec-security' ) ); ?></th>
									<td><?php echo esc_html( self::formatted_count( $count['report'] ) ); ?></td>
									<td><?php echo esc_html( self::formatted_count( $count['block'] ) ); ?></td>
								</tr>
							<?php endif; ?>
						<?php endforeach; ?>
					<?php endforeach; ?>
					</tbody>
				</table>
				<form class="qa3-note" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="<?php echo esc_attr( self::CLEAR_ACTION ); ?>">
					<?php wp_nonce_field( self::CLEAR_ACTION ); ?>
					<?php submit_button( __( 'Clear firewall report', 'qsec-security' ), 'secondary', 'submit', false ); ?>
				</form>
			<?php else : ?>
				<p class="qa3-note"><?php esc_html_e( 'No firewall events in this period.', 'qsec-security' ); ?></p>
			<?php endif; ?>
		</section>
		<?php
	}

	private static function formatted_count( int $value ): string {
		return number_format_i18n( $value ) . ( Firewall_Rules::COUNT_LIMIT === $value ? '+' : '' );
	}
}
