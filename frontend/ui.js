// ui.js
// Handles: DOM helpers, toast, legal popup, language, table rendering, audit rendering.

import { state, getRisk, RISK_LABELS } from './state.js';
import {
    tmplHeadersAudit, tmplTechAudit, tmplPathsAudit,
    tmplSSLAudit, tmplCVEAudit, tmplCVEPlaceholder,
} from './templates.js';

// ── DOM helpers ───────────────────────────────────────────────────────────────
export const $ = id => document.getElementById(id);

// ── Toast ─────────────────────────────────────────────────────────────────────
let _toastTimer = null;
export function showToast(msg, type = 'info', duration = 3500) {
    const t = $('toast');
    t.textContent = msg;
    t.className   = 'show ' + (type === 'error' ? 'toast-error' : type === 'ok' ? 'toast-ok' : '');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => { t.className = ''; }, duration);
}

// ── Legal popup ───────────────────────────────────────────────────────────────
export function initLegal() {
    const overlay = $('legal-overlay');
    if (localStorage.getItem('lukita_legal_ok') === '1') overlay.classList.add('hidden');
    $('btn-accept').addEventListener('click', () => {
        overlay.classList.add('hidden');
        localStorage.setItem('lukita_legal_ok', '1');
    });
}

// ── Language ──────────────────────────────────────────────────────────────────
export function applyLang(lang) {
    state.lang = lang;
    document.body.className = lang;
    $('lang-label').textContent = lang === 'es' ? 'ES' : 'EN';
    Array.from($('scan-mode').options).forEach(o => { o.textContent = o.dataset[lang]; });
    if (state.results.length) renderTable();
    renderHistory();
    if (state.auditData) renderAudit(state.auditData);
    if (window._lastCVEData) renderCVEAudit(window._lastCVEData.results, window._lastCVEData.versions);
    if (window._lastSSLData) renderSSLAudit(window._lastSSLData);
}

// ── Summary ───────────────────────────────────────────────────────────────────
export function updateSummary() {
    $('sum-open').textContent     = state.counts.open;
    $('sum-closed').textContent   = state.counts.closed;
    $('sum-filtered').textContent = state.counts.filtered;
    $('sum-total').textContent    = state.results.length;
}

// ── GeoIP badge ───────────────────────────────────────────────────────────────
export function renderGeo(geo) {
    if (!geo || !Object.keys(geo).length) return;
    const el = $('geo-badge');
    if (!el) return;
    const parts = [
        geo.flag || '',
        geo.city ? geo.city + ',' : '',
        geo.country || '',
        geo.asn ? '· ' + geo.asn : '',
        geo.isp ? '· ' + geo.isp : '',
    ].filter(Boolean).join(' ');
    el.textContent   = parts;
    el.style.display = 'inline-flex';
}

// ── Scan dot blink ────────────────────────────────────────────────────────────
export function setDotBlink(on) {
    on
        ? $('results-dot').classList.add('dot-blink')
        : $('results-dot').classList.remove('dot-blink');
}

// ── Table rendering ───────────────────────────────────────────────────────────
function translateState(s) {
    return (
        { en: { open: 'Open', closed: 'Closed', filtered: 'Filtered' }, es: { open: 'Abierto', closed: 'Cerrado', filtered: 'Filtrado' } }
    )[state.lang][s] || s;
}

function getRespClass(ms) {
    if (ms === null) return '';
    if (ms < 100) return 'fast';
    if (ms < 500) return 'medium';
    return 'slow';
}

function cleanBanner(s) {
    if (!s) return '';
    return s.replace(/[^\x20-\x7E]/g, '').replace(/\s+/g, ' ').trim().substring(0, 60);
}

export function appendRow(d) {
    const tr = document.createElement('tr');
    tr.dataset.state = d.state;
    tr.dataset.port  = d.port;
    const risk = getRisk(d.port);
    const rl   = RISK_LABELS[state.lang][risk];
    const riskCell = d.state === 'open'
        ? `<span class="risk risk-${risk}">${rl}</span>`
        : '<span style="color:#2a2a2a;font-family:var(--font-mono);font-size:10px">—</span>';
    const ver    = state.versions[d.port];
    const verStr = ver ? cleanBanner(ver.version) : '';
    const verHtml = verStr
        ? `<span class="version-tag loaded" title="${verStr}">${verStr.length > 36 ? verStr.substring(0, 35) + '…' : verStr}</span>`
        : '<span class="version-tag">—</span>';
    tr.innerHTML = `<td class="col-port">${d.port}</td><td><span class="badge badge-${d.state}">${translateState(d.state)}</span></td><td class="col-service">${d.service}</td><td>${riskCell}</td><td class="col-time resp-time ${getRespClass(d.response_time_ms)}">${d.response_time_ms !== null ? d.response_time_ms + ' ms' : '—'}</td><td>${verHtml}</td>`;
    $('results-body').appendChild(tr);
    const w = $('results-body').closest('.table-wrap');
    if (w.scrollTop + w.clientHeight >= w.scrollHeight - 80) w.scrollTop = w.scrollHeight;
}

export function renderTable() {
    $('results-body').innerHTML = '';
    const f = state.filter === 'all' ? state.results : state.results.filter(r => r.state === state.filter);
    if (!f.length) {
        const msg = state.lang === 'es' ? 'Sin resultados para este filtro' : 'No results for this filter';
        $('results-body').innerHTML = `<tr><td colspan="6"><div class="empty-state">[ _ ]<br>${msg}</div></td></tr>`;
        return;
    }
    f.forEach(appendRow);
}

export function showError(msg) {
    $('results-body').innerHTML = `<tr><td colspan="6"><div class="empty-state" style="color:#ff0033">✕<br>${msg}</div></td></tr>`;
}

// ── History ───────────────────────────────────────────────────────────────────
const HIST_KEY = 'lukita_history';

export const loadHistory  = () => { try { return JSON.parse(localStorage.getItem(HIST_KEY)) || []; } catch { return []; } };

export function saveHistory(entry) {
    let h = loadHistory();
    if (h.length && h[0].target === entry.target) { h[0] = entry; } else { h.unshift(entry); if (h.length > 5) h = h.slice(0, 5); }
    localStorage.setItem(HIST_KEY, JSON.stringify(h));
}

export function renderHistory() {
    const h     = loadHistory();
    const panel = $('history-panel');
    const list  = $('history-list');
    if (!h.length) { panel.style.display = 'none'; return; }
    panel.style.display = 'block';
    list.innerHTML = h.map((item, idx) => {
        const openPorts = item.openPorts || [];
        const rH = item.riskHigh ? `<span style="color:#ff0033;font-family:var(--font-mono);font-size:10px">⬤ ${item.riskHigh} ${state.lang === 'es' ? 'alto' : 'high'}</span>` : '';
        const rM = item.riskMed  ? `<span style="color:#ffaa00;font-family:var(--font-mono);font-size:10px">⬤ ${item.riskMed} ${state.lang === 'es' ? 'medio' : 'medium'}</span>` : '';
        const tagsHtml = openPorts.length
            ? openPorts.map(p => `<span class="hd-port-tag">${p.port} <span style="opacity:.5;font-size:10px">${p.service}</span></span>`).join('')
            : `<span class="hd-empty">${state.lang === 'es' ? 'Sin puertos abiertos' : 'No open ports'}</span>`;
        return `<div class="history-item" id="hi-${idx}">
            <div class="history-row">
                <div class="history-left"><span class="history-target">${item.target}</span><span class="history-meta">${item.date}</span>${rH}${rM}</div>
                <div class="history-actions">
                    <span class="history-open">● ${item.open} open</span>
                    <button class="btn-expand" data-idx="${idx}">⊞ <span class="es">Ver</span><span class="en">View</span></button>
                    <button class="btn-reload" data-idx="${idx}">↺ <span class="es">Relanzar</span><span class="en">Retry</span></button>
                </div>
            </div>
            <div class="history-detail" id="hd-${idx}">
                <div class="history-detail-inner">
                    <div class="hd-meta">
                        <span><strong>IP:</strong> ${item.ip || '—'}</span>
                        <span><strong>${state.lang === 'es' ? 'Modo' : 'Mode'}:</strong> ${item.mode || '—'}</span>
                        <span><strong>${state.lang === 'es' ? 'Perfil' : 'Profile'}:</strong> ${item.profile || 'normal'}</span>
                        <span><strong>${state.lang === 'es' ? 'Escaneados' : 'Scanned'}:</strong> ${item.total || '?'}</span>
                    </div>
                    <div class="hd-label">${state.lang === 'es' ? 'Puertos abiertos' : 'Open ports'}</div>
                    <div class="hd-ports">${tagsHtml}</div>
                </div>
            </div>
        </div>`;
    }).join('');

    list.querySelectorAll('.btn-expand').forEach(btn => {
        btn.addEventListener('click', () => {
            const d = $('hd-' + btn.dataset.idx);
            const o = d.classList.contains('open');
            list.querySelectorAll('.history-detail').forEach(x => x.classList.remove('open'));
            list.querySelectorAll('.btn-expand').forEach(b => b.classList.remove('active'));
            if (!o) { d.classList.add('open'); btn.classList.add('active'); }
        });
    });
    return list;
}

// ── Audit rendering ───────────────────────────────────────────────────────────
export function renderAudit(data) {
    if (!data) return;
    $('pane-headers').innerHTML      = tmplHeadersAudit(data.headers, state.lang);
    $('pane-technologies').innerHTML = tmplTechAudit(data.technologies, state.lang);
    $('pane-paths').innerHTML        = tmplPathsAudit(data.paths, state.lang);

    const tabs = document.querySelectorAll('.audit-tab');
    if (data.headers) {
        const miss = data.headers.missing?.length || 0;
        const t    = tabs[0];
        if (t) t.innerHTML = `🔒 <span class="es">Cabeceras HTTP</span><span class="en">HTTP Headers</span>${miss ? ` <span class="tab-badge-red">${miss}</span>` : ''}`;
    }
    if (data.technologies) {
        const cnt = data.technologies.count || 0;
        const t   = tabs[1];
        if (t) t.innerHTML = `🔬 <span class="es">Tecnologías</span><span class="en">Technologies</span>${cnt ? ` <span class="tab-badge-blue">${cnt}</span>` : ''}`;
    }
    if (data.paths) {
        const cnt  = data.paths.total_found || 0;
        const high = data.paths.found?.filter(f => f.severity === 'high').length || 0;
        const t    = tabs[2];
        if (t) t.innerHTML = `🗂 <span class="es">Rutas Sensibles</span><span class="en">Sensitive Paths</span>${cnt ? ` <span class="${high ? 'tab-badge-red' : 'tab-badge-yellow'}">${cnt}</span>` : ''}`;
    }
}

export function renderSSLAudit(data) {
    window._lastSSLData          = data;
    $('pane-ssl').innerHTML      = tmplSSLAudit(data, state.lang);
}

export function renderCVEAudit(results, versionsPayload) {
    window._lastCVEData = { results, versions: versionsPayload };

    const pane = $('pane-cve');
    const out  = tmplCVEAudit(results, versionsPayload, state.lang);

    if (typeof out === 'string') {
        pane.innerHTML = out;
        return;
    }

    pane.innerHTML = out.html;
    document.querySelectorAll('.audit-tab').forEach(t => {
        if (t.dataset.pane === 'cve') {
            t.innerHTML = `🐛 CVE${out.totalCVEs ? ` <span class="tab-badge-red">${out.totalCVEs}</span>` : ''}`;
        }
    });
}

export function renderCVEPlaceholder() {
    $('pane-cve').innerHTML = tmplCVEPlaceholder(state.lang);
}

export function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = '✓';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
    }).catch(() => {});
}
window.copyText = copyText;
