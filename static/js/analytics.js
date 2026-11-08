/* PhishGuard - analytics.js
   Fetches /api/analytics (SQLite-backed, user-scoped) and renders charts. */
'use strict';

const statTotal  = document.getElementById('statTotal');
const statAvg    = document.getElementById('statAvg');
const statLow    = document.getElementById('statLow');
const statMedium = document.getElementById('statMedium');
const statHigh   = document.getElementById('statHigh');
const legendLow  = document.getElementById('legendLowPct');
const legendMed  = document.getElementById('legendMedPct');
const legendHigh = document.getElementById('legendHighPct');
const chartsWrap = document.getElementById('chartsWrap');
const emptyState = document.getElementById('analyticsEmpty');
const refreshBtn = document.getElementById('refreshAnalytics');

let doughnutChart = null;
let barChart = null;

const COLORS = {
  low: '#34d399',
  med: '#fbbf24',
  high: '#f87171',
  grid: 'rgba(148, 163, 184, 0.12)',
  text: '#8aa3c0',
};

function pct(part, total) {
  return total ? Math.round((part / total) * 100) + '%' : '0%';
}

function destroyCharts() {
  if (doughnutChart) { doughnutChart.destroy(); doughnutChart = null; }
  if (barChart) { barChart.destroy(); barChart = null; }
}

async function loadAnalytics() {
  const res = await fetch('/api/analytics', { headers: { 'Accept': 'application/json' } });
  if (!res.ok) throw new Error('analytics request failed');
  return res.json();
}

function render(data) {
  const total = Number(data.total) || 0;
  statTotal.textContent = String(total);
  statAvg.textContent = String(data.avg_score ?? 0);
  statLow.textContent = String(data.low ?? 0);
  statMedium.textContent = String(data.medium ?? 0);
  statHigh.textContent = String(data.high ?? 0);
  legendLow.textContent = pct(data.low, total);
  legendMed.textContent = pct(data.medium, total);
  legendHigh.textContent = pct(data.high, total);

  if (total === 0) {
    destroyCharts();
    chartsWrap.hidden = true;
    emptyState.hidden = false;
    return;
  }
  chartsWrap.hidden = false;
  emptyState.hidden = true;

  if (typeof Chart === 'undefined') return; // Chart.js failed to load - stats still visible

  const fontFamily = "'Inter', 'Segoe UI', system-ui, sans-serif";
  Chart.defaults.color = COLORS.text;
  Chart.defaults.font.family = fontFamily;
  destroyCharts();

  // --- Doughnut: risk distribution ---
  const dCtx = document.getElementById('riskDoughnut').getContext('2d');
  doughnutChart = new Chart(dCtx, {
    type: 'doughnut',
    data: {
      labels: ['Low Risk', 'Medium Risk', 'High Risk'],
      datasets: [{
        data: [data.low, data.medium, data.high],
        backgroundColor: [COLORS.low, COLORS.med, COLORS.high],
        borderColor: '#0d1930',
        borderWidth: 3,
        hoverOffset: 10,
      }],
    },
    options: {
      cutout: '58%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d1930',
          borderColor: 'rgba(56, 189, 248, .35)',
          borderWidth: 1,
          padding: 12,
          callbacks: {
            label: (ctx) => ' ' + ctx.label + ': ' + ctx.parsed + ' scan(s)',
          },
        },
      },
    },
  });

  // --- Bar: scans over last 7 days ---
  const daily = Array.isArray(data.daily) ? data.daily : [];
  const labels = daily.map((d) => d.label);
  const counts = daily.map((d) => d.count);

  const bCtx = document.getElementById('activityBar').getContext('2d');
  const gradient = bCtx.createLinearGradient(0, 0, 0, 220);
  gradient.addColorStop(0, '#67e8f9');
  gradient.addColorStop(1, '#1d4ed8');

  barChart = new Chart(bCtx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Scans',
        data: counts,
        backgroundColor: gradient,
        borderColor: 'rgba(103, 232, 249, .8)',
        borderWidth: 1,
        borderRadius: 8,
        maxBarThickness: 56,
      }],
    },
    options: {
      scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: {
          beginAtZero: true,
          grid: { color: COLORS.grid },
          ticks: { precision: 0, stepSize: 1 },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d1930',
          borderColor: 'rgba(56, 189, 248, .35)',
          borderWidth: 1,
          padding: 12,
          callbacks: {
            title: (items) => items[0].label,
            label: (ctx) => ' ' + ctx.parsed.y + ' scan(s)',
          },
        },
      },
    },
  });
}

async function refresh() {
  refreshBtn.disabled = true;
  try {
    const data = await loadAnalytics();
    render(data);
  } catch (_) {
    statTotal.textContent = '!';
    emptyState.hidden = false;
    emptyState.querySelector('h2').textContent = 'Could not load analytics';
    emptyState.querySelector('p').textContent = 'The server did not respond. Make sure Flask is running and reload the page.';
    chartsWrap.hidden = true;
  } finally {
    refreshBtn.disabled = false;
  }
}

refreshBtn.addEventListener('click', refresh);
refresh();
