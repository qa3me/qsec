(function () {
	'use strict';
	const form = document.getElementById('qa3-core-continue');
	const button = document.getElementById('qa3-core-auto');
	if (!form || !button) return;
	const cursor = form.elements.namedItem('qa3_cursor');
	const manual = form.elements.namedItem('qa3_core_step');
	const message = document.getElementById('qa3-core-message');
	const bar = document.getElementById('qa3-core-bar');
	const count = document.getElementById('qa3-core-count');
	let running = false;
	let pause = false;
	button.hidden = false;

	button.addEventListener('click', async () => {
		if (running) {
			pause = true;
			button.disabled = true;
			return;
		}
		running = true;
		pause = false;
		button.textContent = form.dataset.pause;
		manual.disabled = true;
		message.textContent = '';
		try {
			while (!pause) {
				const body = new URLSearchParams({
					action: form.dataset.action,
					_ajax_nonce: form.dataset.nonce,
					qa3_job: form.elements.namedItem('qa3_job').value,
					qa3_cursor: cursor.value,
				});
				const response = await fetch(form.dataset.ajax, {
					method: 'POST',
					mode: 'same-origin',
					credentials: 'same-origin',
					redirect: 'error',
					signal: AbortSignal.timeout(20000),
					body,
				});
				const payload = response.ok ? await response.json() : null;
				if (!payload?.success || payload.data.cursor <= Number(cursor.value)) {
					throw new Error('Scan progress could not be confirmed.');
				}
				cursor.value = String(payload.data.cursor);
				bar.value = payload.data.cursor;
				count.textContent = payload.data.cursor + ' / ' + payload.data.total;
				if (payload.data.done) {
					window.location.assign(form.action);
					return;
				}
				await new Promise((resolve) => window.setTimeout(resolve, 150));
			}
		} catch {
			message.textContent = form.dataset.error;
		} finally {
			running = false;
			button.textContent = form.dataset.resume;
			button.disabled = false;
			manual.disabled = false;
		}
	});
}());
