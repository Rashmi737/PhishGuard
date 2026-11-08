/* ============================================================
   PhishGuard — script.js
   All DOM injection uses textContent / createElement — the
   scanned URL is never inserted as raw HTML.
   ============================================================ */

'use strict';

/* ---------- Detection engine descriptor (mirrors detector.py) ---------- */
const ENGINE_CHECKS = [
  { name: 'URL Length', text: 'Flags abnormally long URLs padded to look legitimate (> 54 / > 75 chars, +8 / +15 pts).',
    icon: '<path fill="currentColor" d="M4 6h16v2H4V6Zm0 5h10v2H4v-2Zm0 5h16v2H4v-2Z"/>' },
  { name: 'IP Address Host', text: 'Raw IPv4/IPv6 hosts instead of a domain name (+30 pts).',
    icon: '<path fill="currentColor" d="M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Zm2 4v2h2V9H6Zm4 0v2h2V9h-2Zm4 0v2h2V9h-2Z"/>' },
  { name: 'Excessive Subdomains', text: 'Two to four+ subdomain levels, e.g. login.secure.update.example.com (+5 to +15 pts).',
    icon: '<path fill="currentColor" d="M10 3h4v4h4v4h-4v4h-4v-4H6V7h4V3Zm2 16a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z"/>' },
  { name: 'Suspicious Keywords', text: 'login, verify, update, account, password, secure and more. Capped at +18 pts.',
    icon: '<path fill="currentColor" d="M11 2a7 7 0 0 1 6.3 10.3l4.2 4.2-1.4 1.4-4.2-4.2A7 7 0 1 1 11 2Zm0 2a5 5 0 1 0 0 10 5 5 0 0 0 0-10Zm-1 3h2v3h3v2h-3v3h-2v-3H7V9h3V7Z"/>' },
  { name: "'@' Symbol", text: 'Everything before @ is ignored by browsers — a classic destination-masking trick (+25 pts).',
    icon: '<path fill="currentColor" d="M12 2a10 10 0 1 0 4.7 18.9l.6-1.7A8 8 0 1 1 20 12h-2a6 6 0 1 0-6 6h.2l.5-1.5H12a4 4 0 1 1 4-4v1a2.5 2.5 0 1 1-5 0 2.6 2.6 0 0 1 .3-1.3L9 18.2A10 10 0 0 0 12 2Z"/>' },
  { name: 'Hyphen Count', text: 'Two or more hyphens in the hostname — common in fake "secure-login-verify" domains (+8 / +15 pts).',
    icon: '<path fill="currentColor" d="M4 10a2 2 0 1 0 0 4h16a2 2 0 1 0 0-4H4Z"/>' },
  { name: 'URL Shorteners', text: 'bit.ly, tinyurl.com, t.co and 15+ services that cloak the real destination (+12 pts).',
    icon: '<path fill="currentColor" d="M7 4a2 2 0 0 1 2 2v12a2 2 0 1 1-2-2V6a2 2 0 0 1 0-2Zm10 0a2 2 0 0 1 2 2 2 2 0 1 1-2-2Zm0 4a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm0 8a2 2 0 1 1 0 4 2 2 0 0 1 0-4Z"/>' },
  { name: 'Suspicious Patterns', text: 'Punycode (xn--), digit-substitution brand lookalikes (paypa1, g00gle), abused TLDs, odd ports (+5 to +20 pts).',
    icon: '<path fill="currentColor" d="M12 2 2 21h20L12 2Zm0 4.5L17.5 19h-11L12 6.5ZM11 11h2v4h-2v-4Z"/>' },
  { name: 'HTTPS Check', text: 'Missing HTTPS adds risk (+15 pts). HTTPS is never treated as proof of safety — only as one signal.',
    icon: '<path fill="currentColor" d="M12 1a5 5 0 0 1 5 5v3h1a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2h1V6a5 5 0 0 1 5-5Zm0 2a3 3 0 0 0-3 3v3h6V6a3 3 0 0 0-3-3Z"/>' },
];

/* ---------- Cached DOM elements ---------- */
const form        = document.getElementById('scanForm');
const urlInput    = document.getElementById('urlInput');
const scanBtn     = document.getElementById('scanBtn');
const formError   = document.getElementById('formError');
const resultsSec  = document.getElementById('results');
const resultCard  = document.getElementById('resultCard');
const toastEl     = document.getElementById('toast');
const engineGrid  = document.getElementById('engineGrid');
const recentList  = document.getElementById('recentList');
const recentEmpty = document.getElementById('recentEmpty');

const RING_CIRCUMFERENCE = 2 * Math.PI * 56; // r = 56
const CSRF_TOKEN = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
const totalScansText = document.getElementById('totalScansText');

function updateTotalScans(total) {
  if (!totalScansText || typeof total !== 'number') return;
  totalScansText.textContent = total + (total === 1 ? ' scan' : ' scans');
}

/* ---------- Small helpers ---------- */
function showToast(message, isError = false) {
  toastEl.textContent = message;
  toastEl.classList.toggle('error', isError);
  toastEl.classList.add('show');
  window.clearTimeout(showToast._t);
  showToast._t = window.setTimeout(() => toastEl.classList.remove('show'), 4200);
}

function clearFormError() {
  formError.hidden = true;
  formError.textContent = '';
}

function showFormError(message) {
  formError.textContent = message;
  formError.hidden = false;
}

function timeAgo(unixSeconds) {
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - Number(unixSeconds || 0));
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + ' min ago';
  if (diff < 86400) return Math.floor(diff / 3600) + ' hr ago';
  return Math.floor(diff / 86400) + ' day(s) ago';
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/* ============================================================
   Render the detection-engine cards (kept in sync with detector.py)
   ============================================================ */
(function renderEngineGrid() {
  if (!engineGrid) return;
  const frag = document.createDocumentFragment();
  for (const check of ENGINE_CHECKS) {
    const item = el('div', 'engine-item');
    const icon = document.createElement('div');
    icon.className = 'engine-icon';
    icon.innerHTML = '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">' + check.icon + '</svg>';
    const body = el('div');
    body.appendChild(el('h3', null, check.name));
    body.appendChild(el('p', null, check.text));
    item.appendChild(icon);
    item.appendChild(body);
    frag.appendChild(item);
  }
  engineGrid.appendChild(frag);
})();

/* ============================================================
   Animated statistics counters (run once when scrolled into view)
   ============================================================ */
(function animateStats() {
  const targets = document.querySelectorAll('.stat-value[data-target]');
  if (!targets.length) return;

  const render = (node, value) => {
    const prefix = node.dataset.prefix || '';
    const suffix = node.dataset.suffix || '';
    const decimals = Number(node.dataset.decimals || 0);
    node.textContent = prefix + value.toFixed(decimals) + suffix;
  };

  const run = (node) => {
    const target = Number(node.dataset.target);
    const duration = 1400;
    const start = performance.now();
    const tick = (now) => {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(2, -10 * p); // easeOutExpo
      render(node, target * (p === 1 ? 1 : eased));
      if (p < 1) requestAnimationFrame(tick); else render(node, target);
    };
    requestAnimationFrame(tick);
  };

  if (!('IntersectionObserver' in window)) {
    targets.forEach(run);
    return;
  }
  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        run(entry.target);
        io.unobserve(entry.target);
      }
    }
  }, { threshold: 0.6 });
  targets.forEach((node) => io.observe(node));
})();

/* ============================================================
   Recent scans list
   ============================================================ */
function renderRecentScans(scans) {
  recentList.replaceChildren();
  const items = Array.isArray(scans) ? scans : [];
  recentEmpty.hidden = items.length !== 0;

  for (const scan of items) {
    const level = ['low', 'medium', 'high'].includes(scan.risk_level) ? scan.risk_level : 'low';
    const li = el('li', 'recent-item');

    const score = el('div', 'recent-score ' + level, String(scan.score));
    const meta  = el('div', 'recent-meta');
    meta.appendChild(el('div', 'recent-url', scan.url || 'unknown'));
    meta.appendChild(el('div', 'recent-sub', (scan.domain ? scan.domain + ' · ' : '') + timeAgo(scan.scanned_at)));
    const cat = el('span', 'recent-cat ' + level, scan.category || level);

    li.appendChild(score);
    li.appendChild(meta);
    li.appendChild(cat);
    recentList.appendChild(li);
  }
}

async function loadRecentScans() {
  try {
    const res = await fetch('/api/recent', { headers: { 'Accept': 'application/json' } });
    if (res.status === 401 || res.status === 403) {
      window.location.href = '/login?next=/';
      return;
    }
    if (!res.ok) return;
    const data = await res.json();
    renderRecentScans(data.scans);
  } catch (_) {
    /* silent - recent list is non-critical */
  }
}

/* ============================================================
   Result rendering
   ============================================================ */
const LEVELS = ['low', 'medium', 'high'];

function renderResult(data) {
  const level = LEVELS.includes(data.risk_level) ? data.risk_level : 'low';
  const score = Math.max(0, Math.min(100, Number(data.score) || 0));

  // Card accent + badge
  resultCard.className = 'result-card risk-' + level;
  const badge = document.getElementById('resBadge');
  badge.textContent = data.category || 'Unknown';
  badge.className = 'risk-badge ' + level;

  // URL text (textContent only — no HTML injection)
  document.getElementById('resDomain').textContent = data.domain || 'Unknown domain';
  document.getElementById('resUrl').textContent = data.normalized_url || data.url || '';

  // Score ring
  const ring = document.getElementById('ringValue');
  ring.style.strokeDasharray = String(RING_CIRCUMFERENCE);
  ring.style.strokeDashoffset = String(RING_CIRCUMFERENCE * (1 - score / 100));
  document.getElementById('resScore').textContent = String(score);
  document.getElementById('meterFill').style.width = score + '%';

  // Indicators
  const list = document.getElementById('resIndicators');
  list.replaceChildren();
  const cleanNote = document.getElementById('resClean');
  const indicators = Array.isArray(data.indicators) ? data.indicators : [];
  cleanNote.hidden = indicators.length !== 0;

  for (const item of indicators) {
    const li = el('li', 'indicator-item');
    li.appendChild(el('span', 'indicator-points', '+' + (Number(item.points) || 0)));
    const textWrap = el('span', 'indicator-text');
    textWrap.appendChild(document.createTextNode(item.label || 'Indicator'));
    if (item.detail) {
      const small = document.createElement('small');
      small.textContent = item.detail;
      textWrap.appendChild(small);
    }
    li.appendChild(textWrap);
    list.appendChild(li);
  }

  // Explanation + recommendation
  document.getElementById('resExplanation').textContent = data.explanation || 'No explanation available.';
  const rec = document.getElementById('resRecommendation');
  rec.textContent = data.recommendation || 'Stay vigilant.';
  rec.className = 'recommendation ' + level;

  // Reveal + scroll into view
  resultsSec.hidden = false;
  resultsSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ============================================================
   Scan flow
   ============================================================ */
async function runScan(rawUrl) {
  const url = (rawUrl || '').trim();
  clearFormError();

  if (!url) {
    showFormError('Please enter a URL to scan (for example: https://example.com).');
    urlInput.focus();
    return;
  }

  scanBtn.disabled = true;
  scanBtn.classList.add('is-loading');

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-CSRF-Token': CSRF_TOKEN,
      },
      body: JSON.stringify({ url }),
    });
    if (res.status === 401 || res.status === 403) {
      window.location.href = '/login?next=/';
      return;
    }
    const data = await res.json().catch(() => ({ success: false, error: 'Unexpected server response.' }));

    if (!res.ok || !data.success) {
      showFormError(data.error || 'The scan failed. Please try again.');
      showToast('Scan rejected — check the URL format.', true);
      return;
    }

    renderResult(data);
    renderRecentScans(data.recent_scans);
    updateTotalScans(Number(data.total_scans));
    showToast('Scan complete: ' + (data.category || 'Result ready'));
  } catch (err) {
    showFormError('Could not reach the PhishGuard server. Is it running?');
    showToast('Network error — is Flask running on port 5000?', true);
  } finally {
    scanBtn.disabled = false;
    scanBtn.classList.remove('is-loading');
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  runScan(urlInput.value);
});

/* Quick-test chips */
document.querySelectorAll('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    urlInput.value = chip.dataset.url || '';
    runScan(urlInput.value);
  });
});

/* Load recent scans on first paint */
loadRecentScans();
