<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Two_Factor {
	public static function panel(): void {
		$available = is_callable( array( '\Two_Factor_Core', 'is_user_using_two_factor' ) );
		$enrolled  = $available && \Two_Factor_Core::is_user_using_two_factor( get_current_user_id() );
		?>
		<section class="qa3-panel" id="qa3-two-factor" aria-labelledby="qa3-two-factor-title">
			<h2 id="qa3-two-factor-title"><?php esc_html_e( 'Two-factor authentication', 'qsec-security' ); ?></h2>
			<?php if ( $available ) : ?>
				<p><strong><?php echo esc_html( $enrolled
					? __( 'Two-factor is enabled for your account.', 'qsec-security' )
					: __( 'Two-factor is available. Your account is not enrolled.', 'qsec-security' ) ); ?></strong></p>
				<p><?php esc_html_e( 'Set up an authenticator app in your WordPress profile and save the backup codes somewhere private.', 'qsec-security' ); ?></p>
				<p><a class="button button-primary" href="<?php echo esc_url( self_admin_url( 'profile.php' ) . '#two-factor-options' ); ?>"><?php esc_html_e( 'Manage your two-factor methods', 'qsec-security' ); ?></a></p>
			<?php else : ?>
				<p><?php esc_html_e( 'Activate the optional Two-Factor plugin to use authenticator codes and backup codes with the native WordPress login.', 'qsec-security' ); ?></p>
				<p><a class="button" href="https://wordpress.org/plugins/two-factor/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Get Two-Factor from WordPress.org', 'qsec-security' ); ?></a></p>
			<?php endif; ?>
		</section>
		<?php
	}
}
