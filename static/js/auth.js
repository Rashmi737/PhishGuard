/* PhishGuard - auth.js: password visibility toggles only. No data leaves the page. */
'use strict';

document.querySelectorAll('.toggle-visibility').forEach((btn) => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target || '');
    if (!target) return;
    const showing = target.type === 'text';
    target.type = showing ? 'password' : 'text';
    btn.textContent = showing ? 'Show' : 'Hide';
    btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  });
});
