<?php
namespace Qsec\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Dashboard {
	public static function overview( array $checks, array $history, int $now ): void {
		$statuses = array_count_values( array_column( $checks, 'status' ) );
		$latest   = $history[0]['time'] ?? null;
		?>
		<header class="qa3-hero">
			<div>
				<div class="qa3-brand"><?php esc_html_e( 'Qsec', 'qsec-security' ); ?> <span>QA3</span></div>
				<h1><?php esc_html_e( 'Site security', 'qsec-security' ); ?></h1>
				<p><?php esc_html_e( 'Review security headers, inspect files and manage WordPress safeguards from this site.', 'qsec-security' ); ?></p>
			</div>
			<span class="qa3-mode"><?php echo esc_html( in_recovery() ? __( 'Recovery mode', 'qsec-security' ) : __( 'Local processing', 'qsec-security' ) ); ?></span>
		</header>
		<div class="qa3-metrics" aria-label="<?php esc_attr_e( 'Security overview', 'qsec-security' ); ?>">
			<?php
			self::metric( __( 'Checks passed', 'qsec-security' ), number_format_i18n( $statuses['good'] ?? 0 ), __( 'Based on current WordPress settings', 'qsec-security' ), 'good' );
			self::metric( __( 'Needs review', 'qsec-security' ), number_format_i18n( $statuses['review'] ?? 0 ), __( 'See recommendations below', 'qsec-security' ), 'review' );
			self::metric(
				__( 'Latest file scan', 'qsec-security' ),
			null === $latest ? '—' : Locale::date( 'short', $latest ),
				null === $latest ? __( 'Run a scan to start your history', 'qsec-security' ) : wp_date( get_option( 'time_format' ), $latest ),
				'info'
			);
			?>
		</div>
		<div class="qa3-overview">
			<?php self::chart( Scan_History::days( $history, $now, wp_timezone() ) ); ?>
			<section class="qa3-panel" aria-labelledby="qa3-checklist-title">
				<h2 id="qa3-checklist-title"><?php esc_html_e( 'Configuration checks', 'qsec-security' ); ?></h2>
				<?php self::check_chart( $statuses, count( $checks ) ); ?>
				<ul class="qa3-checks">
					<?php foreach ( $checks as $check ) : ?>
						<li>
							<span><?php echo esc_html( $check['label'] ); ?></span>
							<span class="qa3-chip qa3-chip--<?php echo esc_attr( $check['status'] ); ?>"><?php echo esc_html( self::status( $check['status'] ) ); ?></span>
						</li>
					<?php endforeach; ?>
				</ul>
				<a href="#qa3-hardening"><?php esc_html_e( 'Review hardening controls', 'qsec-security' ); ?></a>
			</section>
		</div>
		<?php
	}

	private static function metric( string $label, string $value, string $caption, string $kind ): void {
		?>
		<div class="qa3-metric qa3-metric--<?php echo esc_attr( $kind ); ?>">
			<span><?php echo esc_html( $label ); ?></span>
			<strong><?php echo esc_html( $value ); ?></strong>
			<small><?php echo esc_html( $caption ); ?></small>
		</div>
		<?php
	}

	private static function status( string $status ): string {
		return match ( $status ) {
			'good' => __( 'Passed', 'qsec-security' ),
			'review' => __( 'Review', 'qsec-security' ),
			default => __( 'Info', 'qsec-security' ),
		};
	}

	private static function check_chart( array $statuses, int $total ): void {
		if ( $total < 1 ) {
			return;
		}
		$start = 0;
		?>
		<div class="qa3-check-graphic">
			<svg class="qa3-check-ring" viewBox="0 0 100 100" role="img" aria-labelledby="qa3-check-ring-title">
				<title id="qa3-check-ring-title"><?php esc_html_e( 'Breakdown of configuration checks by status', 'qsec-security' ); ?></title>
				<circle cx="50" cy="50" r="39" class="qa3-ring-track"/>
				<?php foreach ( array( 'good', 'review', 'info' ) as $status ) : ?>
					<?php
					$percent = (int) round( 100 * ( $statuses[ $status ] ?? 0 ) / $total );
					if ( $percent < 1 ) {
						continue;
					}
					?>
					<circle cx="50" cy="50" r="39" pathLength="100" stroke-dasharray="<?php echo (int) max( 1, $percent - 2 ); ?> 100" stroke-dashoffset="<?php echo (int) -$start; ?>" transform="rotate(-90 50 50)" class="qa3-ring-arc qa3-ring-arc--<?php echo esc_attr( $status ); ?>"/>
					<?php $start += $percent; ?>
				<?php endforeach; ?>
				<text x="50" y="57" text-anchor="middle"><?php echo esc_html( number_format_i18n( $total ) ); ?></text>
			</svg>
			<ul class="qa3-check-breakdown">
				<?php foreach ( array( 'good', 'review', 'info' ) as $status ) : ?>
					<li><span class="qa3-ring-key qa3-ring-key--<?php echo esc_attr( $status ); ?>" aria-hidden="true"></span><?php echo esc_html( self::status( $status ) ); ?> <strong><?php echo esc_html( number_format_i18n( $statuses[ $status ] ?? 0 ) ); ?></strong></li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php
	}

	private static function chart( array $days ): void {
		$peak      = 0;
		$has_scans = false;
		foreach ( $days as $day ) {
			foreach ( array( 'uploads', 'core', 'malware' ) as $kind ) {
				if ( null !== $day[ $kind ] ) {
					$has_scans = true;
					$peak = max( $peak, $day[ $kind ]['issues'] );
				}
			}
		}
		$tick = (int) max( 1, ceil( $peak / 4 ) );
		?>
		<section class="qa3-panel qa3-chart" aria-labelledby="qa3-chart-title">
			<h2 id="qa3-chart-title"><?php esc_html_e( 'File findings', 'qsec-security' ); ?></h2>
			<p><?php esc_html_e( 'Latest scan of each type per day, over the past seven days.', 'qsec-security' ); ?></p>
			<?php if ( ! $has_scans ) : ?>
				<p class="qa3-empty"><?php esc_html_e( 'No scans yet. Run a file scan to start tracking findings.', 'qsec-security' ); ?></p>
			<?php endif; ?>
			<svg class="qa3-trend" viewBox="0 0 600 194" role="img" aria-labelledby="qa3-trend-name qa3-trend-desc" direction="ltr">
				<title id="qa3-trend-name"><?php esc_html_e( 'Seven-day file findings bar chart', 'qsec-security' ); ?></title>
				<desc id="qa3-trend-desc"><?php esc_html_e( 'Uploads, core and malware are separate series. A short line marks zero findings, and a gap means no scan. Details are listed in the data table.', 'qsec-security' ); ?></desc>
				<?php for ( $line = 0; $line <= 4; ++$line ) : ?>
					<?php $y = 150 - $line * 32; ?>
					<line x1="47" x2="590" y1="<?php echo (int) $y; ?>" y2="<?php echo (int) $y; ?>" class="qa3-grid-line"/>
					<text x="36" y="<?php echo (int) ( $y + 4 ); ?>" text-anchor="end"><?php echo esc_html( number_format_i18n( $line * $tick ) ); ?></text>
				<?php endfor; ?>
				<?php foreach ( $days as $index => $day ) : ?>
					<?php $x = 86 + 77 * $index; ?>
					<text x="<?php echo (int) $x; ?>" y="177" text-anchor="middle"><?php echo esc_html( Locale::date( 'short', $day['date'] ) ); ?></text>
					<?php foreach ( array( 'uploads' => $x - 24, 'core' => $x - 7, 'malware' => $x + 10 ) as $kind => $bar_x ) : ?>
						<?php
						$entry = $day[ $kind ];
						if ( null === $entry ) {
							continue;
						}
						$height = max( 3, (int) round( $entry['issues'] * 32 / $tick ) );
						?>
						<rect x="<?php echo (int) $bar_x; ?>" y="<?php echo (int) ( 150 - $height ); ?>" width="14" height="<?php echo (int) $height; ?>" rx="3" class="qa3-bar qa3-bar--<?php echo esc_attr( $kind ); ?><?php echo $entry['complete'] ? '' : ' qa3-bar--partial'; ?>"/>
					<?php endforeach; ?>
				<?php endforeach; ?>
			</svg>
			<ul class="qa3-legend">
				<li><span class="qa3-key qa3-key--uploads" aria-hidden="true"></span><?php esc_html_e( 'Uploads', 'qsec-security' ); ?></li>
				<li><span class="qa3-key qa3-key--core" aria-hidden="true"></span><?php esc_html_e( 'Core files', 'qsec-security' ); ?></li>
				<li><span class="qa3-key qa3-key--malware" aria-hidden="true"></span><?php esc_html_e( 'Malware indicators', 'qsec-security' ); ?></li>
				<li><?php esc_html_e( 'Hollow bar = partial coverage', 'qsec-security' ); ?></li>
			</ul>
			<?php if ( $has_scans ) : ?>
				<details class="qa3-chart-data">
					<summary><?php esc_html_e( 'View chart data', 'qsec-security' ); ?></summary>
					<table>
						<thead><tr><th scope="col"><?php esc_html_e( 'Date', 'qsec-security' ); ?></th><th scope="col"><?php esc_html_e( 'Uploads', 'qsec-security' ); ?></th><th scope="col"><?php esc_html_e( 'Core files', 'qsec-security' ); ?></th><th scope="col"><?php esc_html_e( 'Malware', 'qsec-security' ); ?></th></tr></thead>
						<tbody>
							<?php foreach ( $days as $day ) : ?>
								<tr>
									<th scope="row"><?php echo esc_html( Locale::date( 'long', $day['date'] ) ); ?></th>
									<td><?php echo esc_html( self::chart_cell( $day['uploads'] ) ); ?></td>
									<td><?php echo esc_html( self::chart_cell( $day['core'] ) ); ?></td>
									<td><?php echo esc_html( self::chart_cell( $day['malware'] ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</details>
			<?php endif; ?>
		</section>
		<?php
	}

	private static function chart_cell( ?array $entry ): string {
		if ( null === $entry ) {
			return __( 'No scan', 'qsec-security' );
		}
		$number = number_format_i18n( $entry['issues'] );
		/* translators: %s: Number of findings in a partial scan. */
		return $entry['complete'] ? $number : sprintf( __( '%s (partial)', 'qsec-security' ), $number );
	}
}
