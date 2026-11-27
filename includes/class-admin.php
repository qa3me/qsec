<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Admin {
	private const SCAN_ACTION = 'qa3_wp_security_scan';
	private const SETTINGS_PAGE = 'options-general.php?page=qa3-wp-security';

	public static function register( string $plugin_file ): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_init', array( self::class, 'settings' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $hook ) use ( $plugin_file ): void {
				if ( 'settings_page_qa3-wp-security' === $hook ) {
					wp_enqueue_style( 'qa3-dashboard', plugins_url( 'assets/dashboard.css', $plugin_file ), array(), VERSION );
					Typography::dashboard( $plugin_file );
					wp_enqueue_script( 'qa3-core-scan', plugins_url( 'assets/core-scan.js', $plugin_file ), array(), VERSION, true );
				}
			}
		);
	}

	public static function settings(): void {
		Login_Guard::register_admin();
		Firewall::register_admin();
		register_setting(
			'qa3_wp_security',
			OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( Login::class, 'sanitize' ),
				'show_in_rest'      => false,
			)
		);
		register_setting(
			'qa3_wp_security_policy',
			Hardening::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( Hardening::class, 'sanitize' ),
				'show_in_rest'      => false,
			)
		);
	}

	public static function menu(): void {
		$name = __( 'Qsec', 'qsec-security' );
		add_options_page( $name, $name, 'manage_options', 'qa3-wp-security', array( self::class, 'page' ) );
	}

	public static function page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$now = time();
		$summary = get_option( Scan_History::OPTION, array() );
		$result = self::handle_post( $summary, $now );
		$core = Core_Scan::get();
		if ( null !== $core && $core['done'] ) {
			$core_report = $core;
			$core_report['reference'] = $core['total'];
		}
		$history = Scan_History::read( $summary, $now );
		?>
		<div class="wrap qa3-dashboard<?php echo Locale::persian() ? ' qa3-dashboard--fa' : ''; ?>">
			<?php settings_errors(); ?>
			<?php Dashboard::overview( Hardening::checks(), $history, $now ); ?>
			<?php if ( in_recovery() ) : ?>
				<p class="notice notice-warning inline"><?php esc_html_e( 'Recovery mode is active. Qsec previews, sign-in protection, firewall and hardening are paused.', 'qsec-security' ); ?></p>
			<?php endif; ?>
			<?php self::report( isset( $result['review'] ) ? null : $result ); ?>
			<?php self::report( $core_report ?? null, 'qa3-core-report-title' ); ?>
			<div class="qa3-tools">
				<?php self::headers(); ?>
				<?php self::scans( $core ); ?>
				<?php self::policies(); ?>
				<?php self::branding(); ?>
				<?php Login_Guard::panel( $now ); ?>
				<?php Firewall::panel( $now ); ?>
				<?php Two_Factor::panel(); ?>
				<?php Review::panel( $result['review'] ?? null, admin_url( self::SETTINGS_PAGE ), self::SCAN_ACTION ); ?>
			</div>
			<?php if ( $history ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( self::SETTINGS_PAGE ) ); ?>" class="qa3-note">
					<?php wp_nonce_field( self::SCAN_ACTION ); ?>
					<?php submit_button( __( 'Clear scan history', 'qsec-security' ), 'secondary', 'qa3_clear_history', false ); ?>
				</form>
			<?php endif; ?>
			<p class="qa3-note"><a href="<?php echo esc_url( PROJECT_URL ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Source code on GitHub', 'qsec-security' ); ?></a></p>
		</div>
		<?php
	}

	private static function handle_post( mixed &$history, int $now ): ?array {
		if ( 'POST' !== sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ||
			! ( isset( $_POST['qa3_scan'] ) || isset( $_POST['qa3_core_scan'] ) || isset( $_POST['qa3_core_step'] ) || isset( $_POST['qa3_core_discard'] ) || isset( $_POST['qa3_malware_scan'] ) || isset( $_POST['qa3_clear_history'] ) || isset( $_POST['qa3_site_review'] ) ) ) {
			return null;
		}
		check_admin_referer( self::SCAN_ACTION );
		if ( isset( $_POST['qa3_site_review'] ) ) {
			return array( 'review' => Review::on_demand( $now ) );
		}
		if ( isset( $_POST['qa3_clear_history'] ) ) {
			delete_option( Scan_History::OPTION );
			$history = array();
			return array( 'notice' => __( 'Scan history cleared.', 'qsec-security' ) );
		}

		if ( isset( $_POST['qa3_core_scan'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- The reference parser validates the unslashed JSON and its schema.
			$input = $_POST['qa3_reference'] ?? null;
			try {
				$started = Core_Scan::start( is_string( $input ) ? wp_unslash( $input ) : '' );
				return $started ? null : array( 'notice' => __( 'A core scan is already in progress. Resume it or discard it first.', 'qsec-security' ) );
			} catch ( \InvalidArgumentException ) {
				return array( 'notice' => __( 'Could not read the reference. Paste the complete JSON for this WordPress version and locale.', 'qsec-security' ) );
			}
		}
		if ( isset( $_POST['qa3_core_step'] ) || isset( $_POST['qa3_core_discard'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- The exact hexadecimal format is validated below.
			$id = $_POST['qa3_job'] ?? '';
			if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
				return null;
			}
			if ( isset( $_POST['qa3_core_discard'] ) ) {
				Core_Scan::dismiss( $id );
				return null;
			}
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- The exact numeric format is validated below.
			$cursor = $_POST['qa3_cursor'] ?? '';
			if ( is_string( $cursor ) && preg_match( '/^[0-9]{1,4}$/D', $cursor ) && null !== Core_Scan::step( $id, (int) $cursor ) ) {
				$history = get_option( Scan_History::OPTION, array() );
				return null;
			}
			return array( 'notice' => __( 'The scan changed or expired. Use the current progress below.', 'qsec-security' ) );
		}
		$uploads = wp_get_upload_dir();
		$uploads_dir = empty( $uploads['error'] ) ? $uploads['basedir'] : '';
		if ( isset( $_POST['qa3_malware_scan'] ) ) {
			$kind = 'malware';
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Only the three fixed strings below match.
			$scope = $_POST['qa3_malware_scope'] ?? '';
			$root = match ( $scope ) {
				'uploads' => $uploads_dir,
				'plugins' => WP_PLUGIN_DIR,
				'themes' => get_theme_root(),
				default => null,
			};
			if ( null === $root ) {
				return array( 'notice' => __( 'Choose a valid malware inspection scope.', 'qsec-security' ) );
			}
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- The digest parser validates each unslashed line.
			$hashes = $_POST['qa3_malware_hashes'] ?? '';
			try {
				$report = ( new Malware() )->scan( $root, Malware::digests( is_string( $hashes ) ? wp_unslash( $hashes ) : '' ), 'uploads' === $scope );
			} catch ( \InvalidArgumentException ) {
				return array( 'notice' => __( 'Enter at most 200 SHA-256 digests, one 64-character hexadecimal value per line.', 'qsec-security' ) );
			}
		} else {
			$kind = 'uploads';
			$report = ( new Uploads_Scanner() )->scan( $uploads_dir );
			$report['checked'] = $report['files'];
			$report['issues'] = count( $report['findings'] );
		}
		$history = Scan_History::record( $history, $kind, $report['checked'], $report['issues'], $report['complete'], $now );
		update_option( Scan_History::OPTION, $history, false );
		$report['kind'] = $kind;
		return $report;
	}

	private static function headers(): void {
		?>
		<section class="qa3-panel" aria-labelledby="qa3-headers-title">
			<h2 id="qa3-headers-title"><?php esc_html_e( 'Security headers', 'qsec-security' ); ?></h2>
			<p><?php esc_html_e( 'Read the site’s current headers and preview a draft Content Security Policy. Compare the pages that use different styles, fonts, scripts or APIs.', 'qsec-security' ); ?></p>
			<?php if ( ! in_recovery() ) : ?>
				<p><a class="button button-primary" href="<?php echo esc_url( Preview::url( home_url( '/' ) ) ); ?>"><?php esc_html_e( 'Preview on the home page', 'qsec-security' ); ?></a></p>
				<p class="qa3-note"><?php esc_html_e( 'Choose Qsec CSP preview in the front-end admin bar on other pages. The preview reports violations without blocking resources.', 'qsec-security' ); ?></p>
			<?php endif; ?>
		</section>
		<?php
	}

	private static function scans( ?array $core ): void {
		$reference_url = add_query_arg(
			array( 'version' => get_bloginfo( 'version' ), 'locale' => get_locale() ),
			'https://api.wordpress.org/core/checksums/1.0/'
		);
		?>
		<section class="qa3-panel" aria-labelledby="qa3-inspections">
			<h2 id="qa3-inspections"><?php esc_html_e( 'File inspections', 'qsec-security' ); ?></h2>
			<p><?php esc_html_e( 'Scans read local files and report findings for review. Qsec stores counts and coverage, and leaves the files in place.', 'qsec-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( self::SETTINGS_PAGE ) ); ?>">
				<?php wp_nonce_field( self::SCAN_ACTION ); ?>
				<?php submit_button( __( 'Inspect uploads', 'qsec-security' ), 'primary', 'qa3_scan', false ); ?>
			</form>
			<details class="qa3-note" <?php echo null !== $core ? 'open' : ''; ?>>
				<summary><?php esc_html_e( 'Compare WordPress core files', 'qsec-security' ); ?></summary>
				<?php if ( null !== $core ) : ?>
					<?php self::core_progress( $core ); ?>
				<?php endif; ?>
				<?php if ( null === $core || $core['done'] ) : ?>
				<p><?php esc_html_e( 'Paste the official checksum JSON for the installed version and locale. Qsec compares the reference locally.', 'qsec-security' ); ?> <a href="<?php echo esc_url( $reference_url ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Open WordPress.org reference', 'qsec-security' ); ?></a></p>
				<form method="post" action="<?php echo esc_url( admin_url( self::SETTINGS_PAGE ) ); ?>">
					<?php wp_nonce_field( self::SCAN_ACTION ); ?>
					<label for="qa3-reference"><?php esc_html_e( 'Core checksum JSON', 'qsec-security' ); ?></label>
					<textarea id="qa3-reference" name="qa3_reference" rows="4" maxlength="650000" spellcheck="false" required></textarea>
					<?php submit_button( __( 'Start core scan', 'qsec-security' ), 'secondary', 'qa3_core_scan', false ); ?>
				</form>
				<?php endif; ?>
			</details>
			<details class="qa3-note">
				<summary><?php esc_html_e( 'Inspect for malware indicators', 'qsec-security' ); ?></summary>
				<p><?php esc_html_e( 'A bounded, read-only inspection for suspicious PHP and embedded code. Optional SHA-256 digests match a trusted list you provide.', 'qsec-security' ); ?></p>
				<form method="post" action="<?php echo esc_url( admin_url( self::SETTINGS_PAGE ) ); ?>">
					<?php wp_nonce_field( self::SCAN_ACTION ); ?>
					<label for="qa3-malware-scope"><?php esc_html_e( 'Directory to inspect', 'qsec-security' ); ?></label>
					<select id="qa3-malware-scope" name="qa3_malware_scope">
						<option value="uploads"><?php esc_html_e( 'Uploads', 'qsec-security' ); ?></option>
						<option value="plugins"><?php esc_html_e( 'Plugins', 'qsec-security' ); ?></option>
						<option value="themes"><?php esc_html_e( 'Themes', 'qsec-security' ); ?></option>
					</select>
					<p><label for="qa3-malware-hashes"><?php esc_html_e( 'Trusted SHA-256 digests (optional)', 'qsec-security' ); ?></label></p>
					<textarea id="qa3-malware-hashes" name="qa3_malware_hashes" rows="3" maxlength="15000" spellcheck="false"></textarea>
					<?php submit_button( __( 'Run malware inspection', 'qsec-security' ), 'secondary', 'qa3_malware_scan', false ); ?>
				</form>
			</details>
		</section>
		<?php
	}

	private static function core_progress( array $core ): void {
		?>
		<div id="qa3-core-progress">
			<p>
				<label for="qa3-core-bar"><?php esc_html_e( 'Core scan progress', 'qsec-security' ); ?></label>
				<progress id="qa3-core-bar" value="<?php echo (int) $core['cursor']; ?>" max="<?php echo (int) $core['total']; ?>"></progress>
				<span id="qa3-core-count" aria-live="polite"><?php echo esc_html( $core['cursor'] . ' / ' . $core['total'] ); ?></span>
			</p>
			<?php if ( ! $core['done'] ) : ?>
				<p><?php esc_html_e( 'Each request processes a small batch. You can close this page and resume within 24 hours of the last step.', 'qsec-security' ); ?></p>
				<form id="qa3-core-continue" method="post" action="<?php echo esc_url( admin_url( self::SETTINGS_PAGE ) ); ?>"
					data-ajax="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>"
					data-nonce="<?php echo esc_attr( wp_create_nonce( Core_Scan::NONCE ) ); ?>"
					data-action="<?php echo esc_attr( Core_Scan::AJAX ); ?>"
					data-resume="<?php esc_attr_e( 'Continue automatically', 'qsec-security' ); ?>"
					data-pause="<?php esc_attr_e( 'Pause after this batch', 'qsec-security' ); ?>"
					data-error="<?php esc_attr_e( 'Scan paused. Reload this page to resume from the latest saved batch.', 'qsec-security' ); ?>">
					<?php wp_nonce_field( self::SCAN_ACTION ); ?>
					<input type="hidden" name="qa3_job" value="<?php echo esc_attr( $core['id'] ); ?>">
					<input type="hidden" name="qa3_cursor" value="<?php echo (int) $core['cursor']; ?>">
					<?php submit_button( __( 'Run next batch', 'qsec-security' ), 'secondary', 'qa3_core_step', false ); ?>
					<button type="button" class="button" id="qa3-core-auto" hidden><?php esc_html_e( 'Continue automatically', 'qsec-security' ); ?></button>
				</form>
				<p id="qa3-core-message" role="status"></p>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( self::SETTINGS_PAGE ) ); ?>">
				<?php wp_nonce_field( self::SCAN_ACTION ); ?>
				<input type="hidden" name="qa3_job" value="<?php echo esc_attr( $core['id'] ); ?>">
				<?php submit_button( $core['done'] ? __( 'Clear core report', 'qsec-security' ) : __( 'Discard core scan', 'qsec-security' ), 'secondary', 'qa3_core_discard', false ); ?>
			</form>
		</div>
		<?php
	}

	private static function policies(): void {
		$values = Hardening::settings();
		?>
		<section class="qa3-panel" id="qa3-hardening" aria-labelledby="qa3-hardening-title">
			<h2 id="qa3-hardening-title"><?php esc_html_e( 'Hardening controls', 'qsec-security' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
				<?php settings_fields( 'qa3_wp_security_policy' ); ?>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( Hardening::OPTION ); ?>[editor]" value="1" <?php checked( true, $values['editor'] ?? false ); ?> aria-describedby="qa3-editor-detail">
					<?php esc_html_e( 'Disable the dashboard file editor', 'qsec-security' ); ?>
				</label>
				<p id="qa3-editor-detail"><?php esc_html_e( 'Applies to the built-in theme and plugin code editors. Core updates and plugin management remain available.', 'qsec-security' ); ?></p>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( Hardening::OPTION ); ?>[pingbacks]" value="1" <?php checked( true, $values['pingbacks'] ?? false ); ?> aria-describedby="qa3-pingbacks-detail">
					<?php esc_html_e( 'Disable XML-RPC pingback methods', 'qsec-security' ); ?>
				</label>
				<p id="qa3-pingbacks-detail"><?php esc_html_e( 'Stops pingback requests and leaves the other XML-RPC methods available.', 'qsec-security' ); ?></p>
				<?php submit_button( __( 'Save hardening controls', 'qsec-security' ), 'primary', 'submit', false ); ?>
			</form>
		</section>
		<?php
	}

	private static function branding(): void {
		$options = Login::settings();
		?>
		<section class="qa3-panel" aria-labelledby="qa3-branding-title">
			<h2 id="qa3-branding-title"><?php esc_html_e( 'Login branding', 'qsec-security' ); ?></h2>
			<p><?php esc_html_e( 'Choose a design for the WordPress login and recovery screens.', 'qsec-security' ); ?></p>
			<?php if ( ! in_recovery() ) : ?>
				<p class="qa3-actions">
					<a class="button" href="<?php echo esc_url( Login::preview_url( 'dark' ) ); ?>"><?php esc_html_e( 'Preview dark green', 'qsec-security' ); ?></a>
					<a class="button" href="<?php echo esc_url( Login::preview_url( 'light' ) ); ?>"><?php esc_html_e( 'Preview light', 'qsec-security' ); ?></a>
				</p>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'options.php' ) ); ?>">
				<?php settings_fields( 'qa3_wp_security' ); ?>
				<p>
					<label for="qa3-login-theme"><?php esc_html_e( 'Login appearance', 'qsec-security' ); ?></label>
					<select id="qa3-login-theme" name="<?php echo esc_attr( OPTION ); ?>[theme]">
						<?php $theme = Login::theme( $options ); ?>
						<option value="wordpress" <?php selected( $theme, 'wordpress' ); ?>><?php esc_html_e( 'Standard WordPress', 'qsec-security' ); ?></option>
						<option value="dark" <?php selected( $theme, 'dark' ); ?>><?php esc_html_e( 'Dark green', 'qsec-security' ); ?></option>
						<option value="light" <?php selected( $theme, 'light' ); ?>><?php esc_html_e( 'Light', 'qsec-security' ); ?></option>
						<option value="system" <?php selected( $theme, 'system' ); ?>><?php esc_html_e( 'Match device appearance', 'qsec-security' ); ?></option>
						<option value="classic" <?php selected( $theme, 'classic' ); ?>><?php esc_html_e( 'Classic branding', 'qsec-security' ); ?></option>
					</select>
				</p>
				<p>
					<label for="qa3-login-title"><?php esc_html_e( 'Title', 'qsec-security' ); ?></label>
					<input class="regular-text" id="qa3-login-title" type="text" name="<?php echo esc_attr( OPTION ); ?>[title]" maxlength="120" value="<?php echo esc_attr( is_string( $options['title'] ?? null ) ? $options['title'] : '' ); ?>">
				</p>
				<p>
					<label for="qa3-login-color"><?php esc_html_e( 'Classic accent (optional, e.g. #1a5e79)', 'qsec-security' ); ?></label>
					<input id="qa3-login-color" type="text" name="<?php echo esc_attr( OPTION ); ?>[color]" maxlength="7" pattern="#[0-9a-fA-F]{6}" placeholder="#1a5e79" value="<?php echo esc_attr( Login::color( $options['color'] ?? '' ) ); ?>">
				</p>
				<p><label><input type="hidden" name="<?php echo esc_attr( OPTION ); ?>[motion]" value="0"><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[motion]" value="1" <?php checked( $options['motion'] ?? true ); ?>> <?php esc_html_e( 'Animate the shield and its four points in light and dark designs', 'qsec-security' ); ?></label></p>
				<p><label><input type="hidden" name="<?php echo esc_attr( OPTION ); ?>[credit]" value="0"><input type="checkbox" name="<?php echo esc_attr( OPTION ); ?>[credit]" value="1" <?php checked( Login::show_credit( $options ) ); ?>> <?php esc_html_e( 'Show the author copyright in light and dark designs', 'qsec-security' ); ?></label></p>
				<?php submit_button( __( 'Save login branding', 'qsec-security' ), 'secondary', 'submit', false ); ?>
			</form>
		</section>
		<?php
	}

	private static function report( ?array $report, string $title_id = 'qa3-report-title' ): void {
		if ( null === $report ) {
			return;
		}
		?>
		<section class="qa3-panel qa3-panel--results" aria-labelledby="<?php echo esc_attr( $title_id ); ?>">
			<h2 id="<?php echo esc_attr( $title_id ); ?>"><?php echo esc_html( isset( $report['reference'] ) ? __( 'Core scan result', 'qsec-security' ) : __( 'Latest inspection result', 'qsec-security' ) ); ?></h2>
			<?php if ( isset( $report['notice'] ) ) : ?>
				<p role="status"><?php echo esc_html( $report['notice'] ); ?></p>
			<?php else : ?>
				<?php /* translators: 1: Files checked; 2: Findings. */ ?>
				<p><?php echo esc_html( sprintf( __( 'Files checked: %1$s · Findings: %2$s', 'qsec-security' ), number_format_i18n( $report['checked'] ), number_format_i18n( $report['issues'] ) ) ); ?></p>
				<?php if ( isset( $report['reference'] ) ) : ?>
					<?php /* translators: %s: Number of files listed in the reference. */ ?>
					<p><?php echo esc_html( sprintf( __( 'Core reference entries: %s', 'qsec-security' ), number_format_i18n( $report['reference'] ) ) ); ?></p>
				<?php endif; ?>
				<?php if ( ! $report['complete'] ) : ?>
					<p><strong><?php esc_html_e( 'Partial coverage. A limit was reached or some locations could not be inspected.', 'qsec-security' ); ?></strong></p>
				<?php endif; ?>
				<?php if ( ! $report['findings'] ) : ?>
					<p><?php esc_html_e( 'No findings in the inspected portion.', 'qsec-security' ); ?></p>
				<?php else : ?>
					<ul>
						<?php foreach ( $report['findings'] as $finding ) : ?>
							<li><code><?php echo esc_html( $finding['path'] ); ?></code> <?php echo esc_html( self::signal_label( $finding['signal'] ) ); ?></li>
						<?php endforeach; ?>
					</ul>
					<?php if ( $report['issues'] > count( $report['findings'] ) ) : ?>
						<p><?php esc_html_e( 'The first 60 findings are listed.', 'qsec-security' ); ?></p>
					<?php endif; ?>
				<?php endif; ?>
			<?php endif; ?>
		</section>
		<?php
	}

	private static function signal_label( string $signal ): string {
		return match ( $signal ) {
			'changed' => __( 'Differs from reference', 'qsec-security' ),
			'missing' => __( 'Missing from this installation', 'qsec-security' ),
			'php_marker' => __( 'PHP marker in a media file', 'qsec-security' ),
			'php_in_media' => __( 'Suspicious: PHP marker in a media file', 'qsec-security' ),
			'encoded_execution' => __( 'Suspicious: code execution and decoding in the same PHP sample', 'qsec-security' ),
			'script_in_uploads' => __( 'Suspicious: executable extension in uploads', 'qsec-security' ),
			'known_digest' => __( 'Exact SHA-256 match to your reference list', 'qsec-security' ),
			default => __( 'Potentially executable file extension', 'qsec-security' ),
		};
	}
}
