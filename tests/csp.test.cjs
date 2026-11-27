const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const { buildDraft, probeHeaders } = require('../assets/csp-preview.js');

const site = 'https://shop.example.test/catalog/';

test('waits for the preview panel when WordPress prints the script before the panel markup', () => {
	const listeners = {};
	const elements = {
		'qa3-csp-draft': { value: '' },
		'qa3-csp-omitted': { textContent: '' },
		'qa3-csp-refresh': { addEventListener: (name, callback) => { listeners[name] = callback; } },
	};
	const document = {
		readyState: 'loading',
		getElementById: (id) => document.readyState === 'loading' ? null : elements[id],
		addEventListener: (name, callback) => { listeners[name] = callback; },
		querySelectorAll: () => [],
	};
	const window = { location: { href: site }, addEventListener: () => {} };
	const code = readFileSync(require.resolve('../assets/csp-preview.js'), 'utf8');
	runInNewContext(code, { document, window, URL, performance: { getEntriesByType: () => [] } });
	assert.equal(typeof listeners.DOMContentLoaded, 'function');
	document.readyState = 'interactive';
	listeners.DOMContentLoaded();
	listeners.click();
	assert.match(elements['qa3-csp-draft'].value, /style-src 'self'/);
});

test('groups observed origins without including paths, query strings or wildcard permissions', () => {
	const result = buildDraft([
		['style-src', 'https://styles.example.test/a.css?private=keep-out'],
		['style-src', 'https://styles.example.test/b.css'],
		['style-src', '/wp-content/theme.css'],
		['script-src', 'https://scripts.example.test/checkout.js'],
		['connect-src', 'https://api.example.test:8443/orders'],
	], site);
	assert.match(result.policy, /style-src 'self' https:\/\/styles\.example\.test;/);
	assert.match(result.policy, /script-src 'self' https:\/\/scripts\.example\.test;/);
	assert.match(result.policy, /connect-src 'self' https:\/\/api\.example\.test:8443;/);
	assert.doesNotMatch(result.policy, /private|checkout\.js|unsafe-inline|unsafe-eval|\*/);
	assert.equal(result.omitted, 0);
});

test('skips unknown directives and insecure, opaque or credential-bearing source URLs', () => {
	const result = buildDraft([
		['report-uri', 'https://external.example.test/collect'],
		['script-src', 'http://insecure.example.test/x.js'],
		['style-src', 'data:text/css,body{}'],
		['img-src', 'https://person:password@example.test/file'],
		['font-src', 'https://other.example.test/font.woff2'],
	], site);
	assert.equal(result.omitted, 4);
	assert.match(result.policy, /font-src 'self' https:\/\/other\.example\.test;/);
	assert.doesNotMatch(result.policy, /collect|insecure|password|data:|report-uri/);
});

test('caps each group and avoids promoting loaded object resources into the draft', () => {
	const rows = Array.from({ length: 20 }, (_, i) => ['img-src', 'https://img' + i + '.example.test/a']);
	rows.push(['object-src', 'https://objects.example.test/a']);
	const result = buildDraft(rows, site);
	assert.equal((result.policy.match(/https:\/\/img\d+\.example\.test/g) || []).length, 8);
	assert.equal(result.omitted, 13);
	assert.match(result.policy, /object-src 'none';/);
});

test('the header audit probes only the current site and removes the preview nonce', async () => {
	const seen = [];
	const result = await probeHeaders(site + '?p=42&_qa3_csp_preview=secret#fragment', async (url, options) => {
		seen.push([url, options.method, options.redirect, options.credentials, options.referrerPolicy]);
		return new Response(null, { headers: {
			'X-Content-Type-Options': 'nosniff',
			'Content-Security-Policy': "default-src 'self'",
			'X-Not-A-Security-Header': 'ignore',
		} });
	});
	assert.deepEqual(seen, [[site + '?p=42', 'HEAD', 'error', 'same-origin', 'no-referrer']]);
	assert.equal(result.status, 200);
	assert.equal(result.headers['Content-Security-Policy'], "default-src 'self'");
	assert.equal(result.headers['X-Content-Type-Options'], 'nosniff');
	assert.equal(result.headers['Strict-Transport-Security'], null);
	assert.equal(result.headers['X-Not-A-Security-Header'], undefined);
});
