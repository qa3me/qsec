<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Login_Guard {
	public const OPTION = 'qsec_login_guard_settings';
	public const STATE = 'qsec_login_guard_state';
	private const LIMITED = 'qsec_login_cooldown';
	private const SETTINGS_GROUP = 'qsec_login_guard';
	private const CLEAR_ACTION = 'qsec_clear_login_attempts';

	public static function register(): void {
		if ( in_recovery() ) {
			return;
		}
		add_action( 'login_form_login', array( self::class, 'password_form' ), 1 );
		add_action( 'login_form_validate_2fa', array( self::class, 'second_factor_form' ), 1 );
		add_action( 'after_password_reset', array( self::class, 'password_reset' ) );
	}

	public static function register_admin(): void {
		add_action( 'admin_post_' . self::CLEAR_ACTION, array( self::class, 'clear' ) );
		register_setting(
			self::SETTINGS_GROUP,
			self::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( self::class, 'sanitize' ),
				'show_in_rest'      => false,
				'default'           => self::sanitize( array() ),
			)
		);
	}

	public static function sanitize( mixed $value ): array {
		return array(
			'report' => in_array( $value['report'] ?? null, array( true, '1' ), true ),
			'limit'  => in_array( $value['limit'] ?? null, array( true, '1' ), true ),
		);
	}

	public static function password_form(): void {
		if ( ! self::is_post() ) {
			return;
		}
		$options = self::sanitize( get_option( self::OPTION, array() ) );
		if ( ! $options['report'] && ! $options['limit'] ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- This is the public WordPress login submission; no settings are changed here.
		$name = isset( $_POST['log'] ) && is_string( $_POST['log'] ) ? sanitize_user( wp_unslash( $_POST['log'] ) ) : '';
		$key = $options['limit'] ? self::key( $name ) : '';
		$now = time();
		$state = '' !== $key ? Login_Attempts::read( get_option( self::STATE ), $now ) : array();
		if ( '' !== $key && Login_Attempts::blocked( $state, $key, $now ) ) {
			$error = new \WP_Error( self::LIMITED, __( 'Too many sign-in attempts. Wait a minute and try again.', 'qsec-security' ) );
			// Core checks this before hashing a known account password. The final filter also covers unknown accounts.
			add_filter( 'wp_authenticate_user', static fn (): \WP_Error => $error, PHP_INT_MAX );
			add_filter( 'authenticate', static fn (): \WP_Error => $error, PHP_INT_MAX );
		} elseif ( isset( $state['pairs'][ $key ] ) ) {
			add_action(
				'wp_login',
				static function () use ( $key ): void {
					self::change( static function ( array $active ) use ( $key ): array {
						unset( $active['pairs'][ $key ] );
						return $active;
					} );
				},
				1
			);
		}
		add_action(
			'wp_login_failed',
			static function ( string $unused_name, \WP_Error $error ) use ( $options, $key ): void {
				$code = $error->get_error_code();
				if ( self::LIMITED === $code ) {
					if ( $options['report'] ) {
						self::record( 'limited', '', true );
					}
				} elseif ( in_array( $code, array( 'incorrect_password', 'invalid_username', 'invalid_email' ), true ) && ( $options['report'] || '' !== $key ) ) {
					self::record( 'password', $key, $options['report'] );
				}
			},
			10,
			2
		);
	}

	public static function second_factor_form(): void {
		if ( ! self::is_post() || ! self::sanitize( get_option( self::OPTION, array() ) )['report'] ) {
			return;
		}
		add_action( 'wp_login_failed', static function ( string $unused_name, \WP_Error $error ): void {
			if ( 'two_factor_invalid' === $error->get_error_code() ) {
				self::record( 'second_factor', '', true );
			}
		}, 10, 2 );
	}

	public static function password_reset( \WP_User $user ): void {
		if ( ! self::sanitize( get_option( self::OPTION, array() ) )['limit'] ) {
			return;
		}
		$login = self::key( $user->user_login );
		$email = self::key( $user->user_email );
		self::change( static function ( array $state ) use ( $login, $email ): array {
			unset( $state['pairs'][ $login ], $state['pairs'][ $email ] );
			return $state;
		} );
	}

	private static function key( string $name ): string {
		if ( '' === $name ) {
			return '';
		}
		$address = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
		return Login_Attempts::key( $address, $name, wp_salt( 'auth' ) );
	}

	private static function is_post(): bool {
		return 'POST' === sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) );
	}

	private static function record( string $event, string $key, bool $report ): void {
		self::change( static fn ( array $state, int $now ): array => Login_Attempts::record( $state, $event, $key, $now, $report ) );
	}

	private static function change( callable $update ): void {
		Option_State::change( self::STATE, static function ( mixed $before ) use ( $update ): array|false {
			$now   = time();
			$state = Login_Attempts::read( $before, $now );
			$after = $update( $state, $now );
			return false === $before && $after === $state ? false : $after;
		} );
	}

	public static function clear(): void {
		if ( ! self::is_post() || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to clear login reports.', 'qsec-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::CLEAR_ACTION );
		delete_option( self::STATE );
		wp_safe_redirect( admin_url( 'options-general.php?page=qa3-wp-security#qsec-login-guard' ) );
		exit;
	}

	public static function panel( int $now ): void {
		$options = self::sanitize( get_option( self::OPTION, array() ) );
		$state = Login_Attempts::read( get_option( self::STATE ), $now );
		?>
		<section class="qa3-panel" id="qsec-login-guard" aria-labelledby="qsec-login-guard-title">
			<h2 id="qsec-login-guard-title"><?php esc_html_e( 'Login attempts', 'qsec-security' ); ?></h2>
			<p><?php esc_html_e( 'Reports show daily totals for the last seven UTC days. They contain no usernames, addresses or passwords.', 'qsec-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
				<?php settings_fields( self::SETTINGS_GROUP ); ?>
				<p><label><input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[report]" value="1" <?php checked( $options['report'] ); ?>> <?php esc_html_e( 'Record failed sign-ins locally', 'qsec-security' ); ?></label></p>
				<p><label><input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[limit]" value="1" <?php checked( $options['limit'] ); ?>> <?php esc_html_e( 'Limit repeated password attempts', 'qsec-security' ); ?></label></p>
				<p><?php esc_html_e( 'Five failures in five minutes pause the same login name and source for one minute. Retries do not extend the wait. Password recovery and existing sessions remain available.', 'qsec-security' ); ?></p>
				<?php submit_button( __( 'Save login protection', 'qsec-security' ), 'secondary', 'submit', false ); ?>
			</form>
			<?php if ( $state['days'] ) : ?>
				<table class="widefat striped qa3-data-table" id="qsec-login-report">
					<caption class="screen-reader-text"><?php esc_html_e( 'Failed sign-in report', 'qsec-security' ); ?></caption>
					<thead><tr>
						<th scope="col"><?php esc_html_e( 'Date (UTC)', 'qsec-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Password failures', 'qsec-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Second-factor failures', 'qsec-security' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Limited requests', 'qsec-security' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( array_reverse( $state['days'], true ) as $day => $counts ) : ?>
						<tr>
							<th scope="row"><?php echo esc_html( Locale::date( 'report', $day, new \DateTimeZone( 'UTC' ) ) ); ?></th>
							<td><?php echo esc_html( number_format_i18n( $counts['password'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $counts['second_factor'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $counts['limited'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php else : ?>
				<p class="qa3-note"><?php esc_html_e( 'No recorded attempts in this period.', 'qsec-security' ); ?></p>
			<?php endif; ?>
			<?php if ( $state['days'] || $state['pairs'] ) : ?>
				<form class="qa3-note" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="<?php echo esc_attr( self::CLEAR_ACTION ); ?>">
					<?php wp_nonce_field( self::CLEAR_ACTION ); ?>
					<?php submit_button( __( 'Clear reports and temporary limits', 'qsec-security' ), 'secondary', 'submit', false ); ?>
				</form>
			<?php endif; ?>
		</section>
		<?php
	}
}
