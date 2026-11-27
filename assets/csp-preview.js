/* global module */
(function () {
	'use strict';

	const groups = ['script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'frame-src', 'media-src'];
	const auditedHeaders = [
		'Content-Security-Policy', 'Content-Security-Policy-Report-Only',
		'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options',
		'Referrer-Policy', 'Permissions-Policy',
		'Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy',
	];

	async function probeHeaders(pageUrl, fetchHeaders) {
		const url = new URL(pageUrl);
		url.searchParams.delete('_qa3_csp_preview');
		url.hash = '';
		const response = await fetchHeaders(url.href, {
			method: 'HEAD',
			mode: 'same-origin',
			cache: 'no-store',
			redirect: 'error',
			credentials: 'same-origin',
			referrerPolicy: 'no-referrer',
			signal: AbortSignal.timeout(5000),
		});
		return {
			status: response.status,
			headers: Object.fromEntries(auditedHeaders.map((name) => [name, response.headers.get(name)])),
		};
	}

	function buildDraft(observations, pageUrl) {
		const page = new URL(pageUrl);
		const sources = new Map(groups.map((group) => [group, new Set()]));
		let omitted = 0;

		for (const [group, raw] of observations) {
			const origins = sources.get(group);
			let url;
			try {
				url = new URL(raw, page);
			} catch {
				omitted++;
				continue;
			}
			if (!origins || url.username || url.password || !['https:', 'http:'].includes(url.protocol)) {
				omitted++;
				continue;
			}
			if (url.origin === page.origin || origins.has(url.origin)) {
				continue;
			}
			if (url.protocol !== 'https:' || origins.size >= 8 || url.origin.length > 128) {
				omitted++;
				continue;
			}
			origins.add(url.origin);
		}

		const rules = ["default-src 'self'"];
		for (const [group, origins] of sources) {
			rules.push([group, "'self'", ...Array.from(origins).sort()].join(' '));
		}
		rules.push("object-src 'none'", "base-uri 'self'", "form-action 'self'");
		return { policy: rules.join('; ') + ';', omitted };
	}

	if (typeof module === 'object' && module && module.exports) {
		module.exports = { buildDraft, probeHeaders };
		return;
	}

	function initializePreview() {
		const draft = document.getElementById('qa3-csp-draft');
		const counter = document.getElementById('qa3-csp-omitted');
		const button = document.getElementById('qa3-csp-refresh');
		if (!draft || !counter || !button) {
			return;
		}

		function refresh() {
			const observations = [];
			const known = new Set();
			const mapping = {
				SCRIPT: 'script-src',
				IMG: 'img-src',
				IFRAME: 'frame-src',
				VIDEO: 'media-src',
				AUDIO: 'media-src',
				TRACK: 'media-src',
			};
			const linkAs = { font: 'font-src', style: 'style-src', script: 'script-src', image: 'img-src' };
			const initiators = {
				fetch: 'connect-src',
				xmlhttprequest: 'connect-src',
				beacon: 'connect-src',
				img: 'img-src',
				image: 'img-src',
				script: 'script-src',
				iframe: 'frame-src',
				video: 'media-src',
				audio: 'media-src',
			};
			const candidates = document.querySelectorAll('script[src], img, iframe[src], video, audio, track[src], link[rel], object[data], embed[src]');
			const inline = document.querySelectorAll('script:not([src]), style, [style]').length;
			let pending = inline + Math.max(0, candidates.length - 600);
			for (let i = 0; i < Math.min(candidates.length, 600); i++) {
				const element = candidates[i];
				let group = mapping[element.tagName];
				let source = element.currentSrc || element.src || element.data;
				if (element.tagName === 'LINK') {
					source = element.href;
					if (element.relList.contains('stylesheet')) {
						group = 'style-src';
					} else if (element.relList.contains('preload') && Object.hasOwn(linkAs, element.as)) {
						group = linkAs[element.as];
					} else if (element.relList.contains('modulepreload')) {
						group = 'script-src';
					} else {
						continue;
					}
				}
				if (source) {
					known.add(source);
					observations.push([group, source]);
				}
			}

			const entries = performance.getEntriesByType('resource');
			pending += Math.max(0, entries.length - 500);
			for (const entry of entries.slice(0, 500)) {
				if (!known.has(entry.name)) {
					const group = Object.hasOwn(initiators, entry.initiatorType) ? initiators[entry.initiatorType] : undefined;
					observations.push([group, entry.name]);
				}
			}
			const result = buildDraft(observations, window.location.href);
			draft.value = result.policy;
			counter.textContent = String(result.omitted + pending);
		}

		button.addEventListener('click', refresh);
		const audit = document.getElementById('qa3-csp-audit');
		const auditResult = document.getElementById('qa3-csp-audit-result');
		if (audit && auditResult) {
			audit.addEventListener('click', async () => {
				audit.disabled = true;
				auditResult.textContent = audit.dataset.loading;
				try {
					const result = await probeHeaders(window.location.href, (url, options) => window.fetch(url, options));
					const rows = Object.entries(result.headers).map(([name, value]) => name + ': ' + (value === null ? '—' : value));
					auditResult.textContent = 'HTTP ' + result.status + '\n' + rows.join('\n');
				} catch {
					auditResult.textContent = audit.dataset.error;
				} finally {
					audit.disabled = false;
				}
			});
		}
		if (document.readyState === 'complete') {
			refresh();
		} else {
			window.addEventListener('load', refresh, { once: true });
		}
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initializePreview, { once: true });
	} else {
		initializePreview();
	}
}());
