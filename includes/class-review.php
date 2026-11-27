<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Review {
	private const ADMIN_LIMIT = 50;
	private const STALE_AFTER = 86400;
	private const EXPORT_ACTION = 'qa3_export_summary';

	public static function updates( mixed $core, mixed $plugins, mixed $themes, int $now ): array {
		$summary = array();
		foreach ( array( 'core' => $core, 'plugins' => $plugins, 'themes' => $themes ) as $kind => $cache ) {
			$checked = $cache->last_checked ?? null;
			$rows    = 'core' === $kind ? ( $cache->updates ?? null ) : ( $cache->response ?? null );
			if ( ! is_int( $checked ) || $checked <= 0 || $checked > $now ||
				( ! is_array( $rows ) && ! is_object( $rows ) ) ) {
				$summary[ $kind ] = array( 'state' => 'unknown', 'pending' => null );
				continue;
			}
			$pending = count( (array) $rows );
			if ( 'core' === $kind ) {
				$pending = 0;
				foreach ( $rows as $offer ) {
					if ( 'upgrade' === ( $offer->response ?? null ) ) {
						$pending = 1;
						break;
					}
				}
			}
			$summary[ $kind ] = array(
				'state'   => $now - $checked > self::STALE_AFTER ? 'stale' : 'current',
				'pending' => $pending,
			);
		}
		return $summary;
	}

	public static function coverage( array $ids, callable $enabled ): array {
		$limited = array_slice( $ids, 0, self::ADMIN_LIMIT );
		$active  = 0;
		foreach ( $limited as $id ) {
			if ( $enabled( (int) $id ) ) {
				++$active;
			}
		}
		return array( 'checked' => count( $limited ), 'enrolled' => $active, 'partial' => count( $ids ) > self::ADMIN_LIMIT );
	}

	public static function export( array $history, array $checks, int $now ): array {
		$tally = array( 'good' => 0, 'review' => 0, 'info' => 0 );
		foreach ( $checks as $check ) {
			$status = $check['status'] ?? '';
			if ( is_string( $status ) && array_key_exists( $status, $tally ) ) {
				++$tally[ $status ];
			}
		}
		return array(
			'schema'       => 1,
			'generated_at' => gmdate( 'c', $now ),
			'checks'       => $tally,
			'scans'        => Scan_History::read( $history, $now ),
		);
	}

	public static function registration( bool $open, string $role, ?bool $has_privileges ): array {
		return array(
			'role'  => $role,
			'state' => ! $open ? 'closed' : match ( $has_privileges ) {
				true    => 'review',
				false   => 'open',
				default => 'unknown',
			},
		);
	}

	public static function on_demand( int $now ): array {
		$totp = null;
		if ( is_callable( array( '\Two_Factor_Core', 'is_user_using_two_factor' ) ) ) {
			$ids = get_users( array( 'role' => 'administrator', 'fields' => 'ID', 'number' => self::ADMIN_LIMIT + 1, 'orderby' => 'ID', 'order' => 'ASC' ) );
			if ( $ids ) {
				cache_users( array_map( 'intval', $ids ) );
			}
			$totp = self::coverage( $ids, array( '\Two_Factor_Core', 'is_user_using_two_factor' ) );
		}
		$role_name = (string) get_option( 'default_role', '' );
		$role = get_role( $role_name );
		$privileges = array( 'edit_posts', 'edit_pages', 'upload_files', 'manage_options', 'edit_users', 'promote_users', 'delete_users', 'activate_plugins', 'install_plugins', 'moderate_comments', 'unfiltered_html' );
		$granted = $role ? array_intersect_key( array_filter( $role->capabilities ), array_fill_keys( $privileges, true ) ) : null;
		return array(
			'updates'      => self::updates( get_site_transient( 'update_core' ), get_site_transient( 'update_plugins' ), get_site_transient( 'update_themes' ), $now ),
			'totp'         => $totp,
			'registration' => self::registration( (bool) get_option( 'users_can_register' ), $role_name, null === $granted ? null : (bool) $granted ),
		);
	}

	public static function register(): void {
		add_action( 'admin_post_' . self::EXPORT_ACTION, array( self::class, 'download' ) );
	}

	public static function download(): void {
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to export this report.', 'qsec-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::EXPORT_ACTION );
		$history = get_option( Scan_History::OPTION, array() );
		nocache_headers();
		send_nosniff_header();
		header( 'Content-Disposition: attachment; filename="qsec-summary.json"' );
		wp_send_json( self::export( is_array( $history ) ? $history : array(), Hardening::checks(), time() ), 200, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
	}

	public static function panel( ?array $report, string $page_url, string $nonce_action ): void {
		?>
		<section class="qa3-panel" id="qa3-site-review" aria-labelledby="qa3-site-review-title">
			<h2 id="qa3-site-review-title"><?php esc_html_e( 'Security review and export', 'qsec-security' ); ?></h2>
			<p><?php esc_html_e( 'Review update information already on this site and the two-factor status of administrators. The review runs when requested.', 'qsec-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( $page_url . '#qa3-site-review' ); ?>">
				<?php wp_nonce_field( $nonce_action ); ?>
				<?php submit_button( __( 'Run security review', 'qsec-security' ), 'secondary', 'qa3_site_review', false ); ?>
			</form>
			<?php if ( null !== $report ) : ?>
				<?php self::findings( $report ); ?>
			<?php endif; ?>
			<form class="qa3-note" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( self::EXPORT_ACTION ); ?>
				<input type="hidden" name="action" value="<?php echo esc_attr( self::EXPORT_ACTION ); ?>">
				<?php submit_button( __( 'Download summary JSON', 'qsec-security' ), 'secondary', 'submit', false ); ?>
				<p><?php esc_html_e( 'The download contains counts and coverage. It excludes account names, site URLs, file paths and secrets.', 'qsec-security' ); ?></p>
			</form>
		</section>
		<?php
	}

	private static function findings( array $report ): void {
		$labels = array( 'core' => __( 'WordPress core', 'qsec-security' ), 'plugins' => __( 'Plugins', 'qsec-security' ), 'themes' => __( 'Themes', 'qsec-security' ) );
		?>
		<ul class="qa3-checks" id="qa3-review-result">
			<?php foreach ( $report['updates'] as $kind => $result ) : ?>
				<li>
					<span><?php echo esc_html( $labels[ $kind ] ); ?></span>
					<span>
						<?php
						if ( 'unknown' === $result['state'] ) {
							esc_html_e( 'No local update data', 'qsec-security' );
						} else {
							/* translators: %s: Number of available updates. */
							echo esc_html( sprintf( __( '%s pending', 'qsec-security' ), number_format_i18n( $result['pending'] ) ) );
							if ( 'stale' === $result['state'] ) {
								echo ' · ';
								esc_html_e( 'Cached data is older than 24 hours', 'qsec-security' );
							}
						}
						?>
					</span>
				</li>
			<?php endforeach; ?>
			<li>
				<span><?php esc_html_e( 'Administrator two-factor enrollment', 'qsec-security' ); ?></span>
				<span>
					<?php if ( null === $report['totp'] ) : ?>
						<?php esc_html_e( 'Two-Factor is unavailable', 'qsec-security' ); ?>
					<?php else : ?>
						<?php
						/* translators: 1: Administrators with a configured second factor. 2: Administrators checked. */
						echo esc_html( sprintf( __( '%1$s of %2$s enrolled', 'qsec-security' ), number_format_i18n( $report['totp']['enrolled'] ), number_format_i18n( $report['totp']['checked'] ) ) );
						if ( $report['totp']['partial'] ) {
							echo ' · ';
							esc_html_e( 'Limited to the first 50 administrators', 'qsec-security' );
						}
						?>
					<?php endif; ?>
				</span>
			</li>
			<li>
				<span><?php esc_html_e( 'Public registration', 'qsec-security' ); ?></span>
				<span><?php
					$registration = $report['registration'];
					$state = match ( $registration['state'] ) {
						'closed' => __( 'Closed in WordPress', 'qsec-security' ),
						'open'   => __( 'Open in WordPress', 'qsec-security' ),
						'review' => __( 'Review access: the default role has additional privileges', 'qsec-security' ),
						default  => __( 'Open, but the default role is unknown', 'qsec-security' ),
					};
					echo esc_html( $state );
					if ( '' !== $registration['role'] && 'closed' !== $registration['state'] ) {
						/* translators: %s: Default WordPress role identifier. */
						echo ' · ' . esc_html( sprintf( __( 'Default role: %s', 'qsec-security' ), $registration['role'] ) );
					}
				?></span>
			</li>
		</ul>
		<?php
	}
}
