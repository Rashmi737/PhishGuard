/* PhishGuard - history.js: copy-URL buttons with clipboard fallback. */
'use strict';

document.querySelectorAll('.copy-btn[data-copy]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const text = btn.dataset.copy || '';
    try {
      await navigator.clipboard.writeText(text);
      btn.classList.add('copied');
      btn.setAttribute('title', 'Copied!');
    } catch (_) {
      // Fallback for older browsers / non-secure contexts.
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      try { document.execCommand('copy'); btn.classList.add('copied'); } catch (_) { /* ignore */ }
      area.remove();
    }
    window.setTimeout(() => btn.classList.remove('copied'), 1600);
  });
});
