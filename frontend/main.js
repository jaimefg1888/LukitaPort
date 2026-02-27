// main.js — LukitaPort
// Entry point. Imports all modules and wires up event listeners.

import { state }         from './state.js';
import { $, initLegal, applyLang, renderHistory, setDotBlink,
         updateSummary, showError, renderTable }  from './ui.js';
import { startScan, stopScan, runFingerprint,
         launchAudit, launchDiscover, launchSubdomains,
         cleanTarget, launchCVELookup }   from './api.js';

// Expose CVE function globally for inline onclick handlers
window.launchCVELookup = launchCVELookup;
import { exportJSON, exportCSV, exportHTMLReport,
         exportPDF, exportMarkdown }              from './export.js';

// ── Init ───────────────────────────────────────────────────────────────────────
initLegal();
renderHistory();

// ── Language toggle ────────────────────────────────────────────────────────────
$('lang-btn').addEventListener('click', () => {
    applyLang(state.lang === 'es' ? 'en' : 'es');
    $('lang-btn').classList.remove('pulse');
    void $('lang-btn').offsetWidth;
    $('lang-btn').classList.add('pulse');
    $('lang-btn').addEventListener('animationend', () => $('lang-btn').classList.remove('pulse'), { once: true });
});

// ── Target input cleanup ───────────────────────────────────────────────────────
$('target').addEventListener('input', function () {
    this.style.borderColor = /^https?:\/\//i.test(this.value) ? '#ffaa00' : '';
});
$('target').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !state.scanning) startScan();
});

// ── Scan mode — custom range toggle ───────────────────────────────────────────
$('scan-mode').addEventListener('change', () => {
    $('custom-range').classList.toggle('visible', $('scan-mode').value === 'custom');
});

// ── Timeout slider ─────────────────────────────────────────────────────────────
$('timeout').addEventListener('input', () => {
    $('timeout-val').textContent = parseFloat($('timeout').value).toFixed(1) + 's';
});

// ── Scan / Stop ────────────────────────────────────────────────────────────────
$('btn-scan').addEventListener('click', () => {
    state.scanning ? stopScan() : startScan();
});

// ── Filter tabs ────────────────────────────────────────────────────────────────
document.querySelectorAll('.filter-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        state.filter = tab.dataset.filter;
        renderTable();
    });
});

// ── Audit tabs ─────────────────────────────────────────────────────────────────
document.querySelectorAll('.audit-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.audit-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        document.querySelectorAll('.audit-pane').forEach(p => p.classList.remove('active'));
        $('pane-' + tab.dataset.pane).classList.add('active');
    });
});

// ── History reload ─────────────────────────────────────────────────────────────
$('history-list')?.addEventListener('click', async e => {
    const btn = e.target.closest('.btn-reload');
    if (!btn) return;
    const { loadHistory } = await import('./ui.js').catch(() => ({}));
    const items = JSON.parse(localStorage.getItem('lukita_history') || '[]');
    const item  = items[parseInt(btn.dataset.idx)];
    if (!item) return;
    $('target').value = item.target;
    startScan();
});

// ── Anon mode toggle ───────────────────────────────────────────────────────────
document.getElementById('anon-mode')?.addEventListener('change', function () {
    const dot    = document.getElementById('anon-dot');
    const status = document.getElementById('anon-status');
    if (this.checked) {
        dot.style.background  = '#00ff88';
        dot.style.boxShadow   = '0 0 8px #00ff88';
        // Force stealth profile visually
        const profileSel = document.getElementById('scan-profile');
        if (profileSel) profileSel.value = 'stealth';
        if (status) status.innerHTML = `<span class="es" style="color:#00cc66">✓ Activado — perfil Stealth forzado · delays aleatorios</span><span class="en" style="color:#00cc66">✓ Enabled — Stealth profile forced · random delays</span>`;
    } else {
        dot.style.background = '#333';
        dot.style.boxShadow  = 'none';
        if (status) status.innerHTML = `<span class="es">Desactivado — fuerza perfil Stealth + delays aleatorios</span><span class="en">Disabled — forces Stealth profile + random delays</span>`;
    }
});

// Make label click toggle the checkbox
document.querySelector('.anon-toggle')?.addEventListener('click', function(e) {
    if (e.target.tagName === 'BUTTON') return;
    const cb = document.getElementById('anon-mode');
    if (cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event('change')); }
});


$('btn-fingerprint').addEventListener('click', runFingerprint);

// ── Export buttons ─────────────────────────────────────────────────────────────
$('btn-json').addEventListener('click', exportJSON);
$('btn-csv').addEventListener('click',  exportCSV);
$('btn-html').addEventListener('click', exportHTMLReport);
$('btn-pdf').addEventListener('click',  exportPDF);
$('btn-md').addEventListener('click',   exportMarkdown);

// ── Network Discovery ──────────────────────────────────────────────────────────
$('btn-discover')?.addEventListener('click', launchDiscover);
$('discover-cidr')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') launchDiscover();
});

// ── Subdomain Enumeration ──────────────────────────────────────────────────────
$('btn-subdomains')?.addEventListener('click', launchSubdomains);
$('subdomain-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') launchSubdomains();
});

// ── Screenshot poll ─────────────────────────────────────────────────────────────
// After scan completes, poll once after 12 s to see if screenshot is ready.
// If available, show it in the audit screenshot tab.
let _screenshotPolled = false;
const _origStopScan = stopScan;
window._pollScreenshot = async function (target) {
    if (_screenshotPolled) return;
    _screenshotPolled = true;
    await new Promise(r => setTimeout(r, 12000));
    try {
        const resp = await fetch(`/api/screenshot?target=${encodeURIComponent(target)}`);
        if (resp.status === 200) {
            const blob   = await resp.blob();
            const imgUrl = URL.createObjectURL(blob);
            const pane   = $('pane-screenshot');
            if (pane) {
                pane.innerHTML = `<div style="padding:20px"><img src="${imgUrl}" style="width:100%;border-radius:4px;border:1px solid #1e1e1e" alt="Screenshot" /></div>`;
                // Activate tab
                const screenshotTab = document.querySelector('.audit-tab[data-pane="screenshot"]');
                if (screenshotTab) screenshotTab.style.display = 'inline-flex';
            }
        }
    } catch {}
};
