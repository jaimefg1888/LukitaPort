// ui.js — LukitaPort
// Handles: DOM helpers, toast, legal popup, language, table rendering, audit rendering.

import { state, getRisk, RISK_LABELS } from './state.js';

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
    // Re-render CVE pane if data is available
    if (window._lastCVEData) renderCVEAudit(window._lastCVEData.results, window._lastCVEData.versions);
    // Re-render SSL pane if data is available
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
        geo.asn    ? '· ' + geo.asn  : '',
        geo.isp    ? '· ' + geo.isp  : '',
    ].filter(Boolean).join(' ');
    el.textContent = parts;
    el.style.display = 'inline-flex';
}

// ── Scan dot blink ────────────────────────────────────────────────────────────
export function setDotBlink(on) {
    on ? $('results-dot').classList.add('dot-blink') : $('results-dot').classList.remove('dot-blink');
}

// ── Table rendering ───────────────────────────────────────────────────────────
function translateState(s) {
    return ({ en: { open:'Open', closed:'Closed', filtered:'Filtered' }, es: { open:'Abierto', closed:'Cerrado', filtered:'Filtrado' } })[state.lang][s] || s;
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
    const tr   = document.createElement('tr');
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
    const h = loadHistory();
    const panel = $('history-panel');
    const list  = $('history-list');
    if (!h.length) { panel.style.display = 'none'; return; }
    panel.style.display = 'block';
    list.innerHTML = h.map((item, idx) => {
        const openPorts = item.openPorts || [];
        const rH = item.riskHigh ? `<span style="color:#ff0033;font-family:var(--font-mono);font-size:10px">⬤ ${item.riskHigh} ${state.lang==='es'?'alto':'high'}</span>` : '';
        const rM = item.riskMed  ? `<span style="color:#ffaa00;font-family:var(--font-mono);font-size:10px">⬤ ${item.riskMed} ${state.lang==='es'?'medio':'medium'}</span>` : '';
        const tagsHtml = openPorts.length
            ? openPorts.map(p => `<span class="hd-port-tag">${p.port} <span style="opacity:.5;font-size:10px">${p.service}</span></span>`).join('')
            : `<span class="hd-empty">${state.lang==='es'?'Sin puertos abiertos':'No open ports'}</span>`;
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
                        <span><strong>IP:</strong> ${item.ip||'—'}</span>
                        <span><strong>${state.lang==='es'?'Modo':'Mode'}:</strong> ${item.mode||'—'}</span>
                        <span><strong>${state.lang==='es'?'Perfil':'Profile'}:</strong> ${item.profile||'normal'}</span>
                        <span><strong>${state.lang==='es'?'Escaneados':'Scanned'}:</strong> ${item.total||'?'}</span>
                    </div>
                    <div class="hd-label">${state.lang==='es'?'Puertos abiertos':'Open ports'}</div>
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
    return list; // expose for reload handlers
}

// ── Audit rendering ───────────────────────────────────────────────────────────
export function renderAudit(data) {
    if (!data) return;
    renderHeadersAudit(data.headers);
    renderTechAudit(data.technologies);
    renderPathsAudit(data.paths);

    const tabs = document.querySelectorAll('.audit-tab');
    if (data.headers) {
        const miss = data.headers.missing?.length || 0;
        const t = tabs[0];
        if (t) t.innerHTML = `🔒 <span class="es">Cabeceras HTTP</span><span class="en">HTTP Headers</span>${miss ? ` <span class="tab-badge-red">${miss}</span>` : ''}`;
    }
    if (data.technologies) {
        const cnt = data.technologies.count || 0;
        const t = tabs[1];
        if (t) t.innerHTML = `🔬 <span class="es">Tecnologías</span><span class="en">Technologies</span>${cnt ? ` <span class="tab-badge-blue">${cnt}</span>` : ''}`;
    }
    if (data.paths) {
        const cnt  = data.paths.total_found || 0;
        const high = data.paths.found?.filter(f => f.severity === 'high').length || 0;
        const t = tabs[2];
        if (t) t.innerHTML = `🗂 <span class="es">Rutas Sensibles</span><span class="en">Sensitive Paths</span>${cnt ? ` <span class="${high ? 'tab-badge-red' : 'tab-badge-yellow'}">${cnt}</span>` : ''}`;
    }
}

export function renderSSLAudit(data) {
    window._lastSSLData = data;
    const pane = $('pane-ssl');
    if (!data || data.error) {
        pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'Sin puertos HTTPS detectados':'No HTTPS ports detected'}</div>`;
        return;
    }
    const results = data.results || {};
    if (!Object.keys(results).length) { pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'Sin datos SSL':'No SSL data'}</div>`; return; }
    const gradeColor = { A:'#00ff88', B:'#44cc88', C:'#ffaa00', D:'#ff6600', F:'#ff0033' };
    let html = '';
    Object.entries(results).forEach(([port, ssl]) => {
        const gc = gradeColor[ssl.grade] || '#888';
        html += `<div style="background:#070707;border:1px solid #1e1e1e;border-radius:4px;padding:20px;margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px">
                <div style="width:52px;height:52px;border-radius:4px;border:1px solid ${gc}33;background:${gc}11;display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-size:1.6rem;font-weight:700;color:${gc}">${ssl.grade}</div>
                <div>
                    <div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:#f0f0f0">${ssl.hostname}:${port}</div>
                    <div style="font-family:var(--font-mono);font-size:11px;color:#888;margin-top:4px">${ssl.protocol||'TLS'} · ${ssl.cipher||'—'} · ${ssl.bits||'?'} bits</div>
                </div>
            </div>`;
        if (ssl.error) { html += `<div style="color:#ff5544;font-family:var(--font-mono);font-size:12px">⚠ ${ssl.error}</div></div>`; return; }
        html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">`;
        const sub = ssl.subject || {}; const iss = ssl.issuer || {};
        [
            [state.lang==='es'?'Emisor':'Issuer',           iss.organizationName || iss.commonName || '—'],
            [state.lang==='es'?'Dominio (CN)':'Common Name', sub.commonName || '—'],
            ['Not Before', ssl.not_before ? ssl.not_before.slice(0,10) : '—'],
            ['Not After',  ssl.not_after  ? ssl.not_after.slice(0,10)  : '—'],
            [state.lang==='es'?'Días restantes':'Days left', ssl.days_until_expiry !== null ? ssl.days_until_expiry + 'd' : '—'],
            [state.lang==='es'?'Autofirmado':'Self-signed',  ssl.self_signed ? '⚠ Yes' : '✓ No'],
        ].forEach(([k, v]) => {
            const isWarn = (k.includes('restante')||k.includes('left')) && ssl.expiring_soon;
            const isErr  = (k.includes('restante')||k.includes('left')) && ssl.expired;
            const vc = isErr ? '#ff3344' : isWarn ? '#ffaa00' : '#c0c0c0';
            html += `<div style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:3px;padding:10px 12px"><div style="font-family:var(--font-mono);font-size:9px;color:#555;letter-spacing:1px;text-transform:uppercase;margin-bottom:3px">${k}</div><div style="font-family:var(--font-mono);font-size:12px;color:${vc};word-break:break-all">${v}</div></div>`;
        });
        html += '</div>';
        if (ssl.sans?.length) {
            html += `<div style="margin-bottom:12px"><div style="font-family:var(--font-mono);font-size:9px;color:#555;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">Subject Alternative Names (${ssl.sans.length})</div><div style="display:flex;flex-wrap:wrap;gap:5px">${ssl.sans.slice(0,8).map(s => `<span style="font-family:var(--font-mono);font-size:11px;color:#8899ff;background:rgba(100,100,255,.08);border:1px solid rgba(100,100,255,.15);padding:2px 8px;border-radius:3px">${s}</span>`).join('')}${ssl.sans.length>8?`<span style="color:#555;font-size:11px;font-family:var(--font-mono)">+${ssl.sans.length-8} more</span>`:''}</div></div>`;
        }
        if (ssl.issues?.length) {
            html += `<div style="background:rgba(255,0,51,.04);border:1px solid rgba(255,0,51,.15);border-radius:3px;padding:10px 14px">${ssl.issues.map(i => `<div style="font-family:var(--font-mono);font-size:11px;color:#ff5544;margin-bottom:3px">⚠ ${i}</div>`).join('')}</div>`;
        } else {
            html += `<div style="color:#00cc66;font-family:var(--font-mono);font-size:11px">✓ ${state.lang==='es'?'Sin problemas detectados':'No issues detected'}</div>`;
        }
        html += '</div>';
    });
    pane.innerHTML = html;
}

export function renderCVEAudit(results, versionsPayload) {
    // Cache for language re-render
    window._lastCVEData = { results, versions: versionsPayload };

    const pane  = $('pane-cve');
    const ports = Object.keys(results);
    if (!ports.length) { pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'No se encontraron CVEs conocidos para los servicios detectados':'No known CVEs found for detected services'}</div>`; return; }
    const sevColor = { CRITICAL:'#ff0033', HIGH:'#ff4444', MEDIUM:'#ffaa00', LOW:'#00cc66', NONE:'#555' };
    const sevLabel = { CRITICAL:'CRÍTICO', HIGH:'ALTO', MEDIUM:'MEDIO', LOW:'BAJO', NONE:'NINGUNO' };
    let totalCVEs = 0;
    let html = `<div style="font-family:var(--font-mono);font-size:11px;color:#555;margin-bottom:16px;padding:10px 14px;background:#070707;border:1px solid #161616;border-radius:3px">${state.lang==='es'?'Fuente: NVD (nvd.nist.gov) · Ejecuta Fingerprinting primero para resultados precisos.':'Source: NVD (nvd.nist.gov) · Run Fingerprinting first for precise results.'}</div>`;
    ports.forEach(port => {
        const r = results[port]; const meta = versionsPayload[port] || {};
        const cves = r.cves || []; totalCVEs += cves.length;
        const keyword = r.keyword_used || `${meta.name} ${meta.version||''}`.trim();
        const totalLabel = state.lang==='es' ? 'CVEs totales' : 'total CVEs';
        html += `<div style="background:#070707;border:1px solid #1e1e1e;border-radius:4px;padding:16px;margin-bottom:12px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
                <span style="font-family:var(--font-mono);font-size:13px;color:#f0f0f0;font-weight:700">${state.lang==='es'?'Puerto':'Port'} ${port} — ${meta.name||'?'}</span>
                ${meta.version?`<span style="font-family:var(--font-mono);font-size:11px;color:#8899ff;background:rgba(100,100,255,.08);padding:2px 8px;border-radius:3px;border:1px solid rgba(100,100,255,.15)">${meta.version}</span>`:''}
                <span style="font-family:var(--font-mono);font-size:10px;color:#555;margin-left:auto">${state.lang==='es'?'Búsqueda':'Search'}: "${keyword}" · ${r.total||0} ${totalLabel}</span>
            </div>`;
        if (r.error) { html += `<div style="color:#ff8866;font-family:var(--font-mono);font-size:11px">⚠ ${r.error}</div></div>`; return; }
        if (!cves.length) { html += `<div style="color:#555;font-family:var(--font-mono);font-size:11px">${state.lang==='es'?'Sin CVEs encontrados':'No CVEs found'}</div></div>`; return; }
        cves.forEach(cve => {
            const sc = sevColor[cve.severity] || '#555';
            const sl = state.lang==='es' ? (sevLabel[cve.severity] || cve.severity) : cve.severity;
            html += `<div style="background:#0a0a0a;border:1px solid #1a1a1a;border-left:3px solid ${sc};border-radius:3px;padding:12px 14px;margin-bottom:7px">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap">
                    <a href="${cve.nvd_url}" target="_blank" style="font-family:var(--font-mono);font-size:12px;color:#8899ff;font-weight:700;text-decoration:none">${cve.id}</a>
                    ${cve.cvss_score!==null?`<span style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:${sc}">CVSS ${cve.cvss_score} — ${sl}</span>`:''}
                    <span style="font-family:var(--font-mono);font-size:10px;color:#555;margin-left:auto">${cve.published}</span>
                </div>
                <div style="font-size:12px;color:#bbb;line-height:1.6">${cve.description}</div>
            </div>`;
        });
        html += '</div>';
    });
    document.querySelectorAll('.audit-tab').forEach(t => {
        if (t.dataset.pane === 'cve') t.innerHTML = `🐛 CVE${totalCVEs ? ` <span class="tab-badge-red">${totalCVEs}</span>` : ''}`;
    });
    pane.innerHTML = html;
}

export function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent; btn.textContent = '✓'; btn.classList.add('copied');
        setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
    }).catch(() => {});
}
window.copyText = copyText; // expose for inline onclick handlers

const HEADER_EXAMPLES = {
    'Strict-Transport-Security': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy':   "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'",
    'X-Frame-Options':           'X-Frame-Options: SAMEORIGIN',
    'X-Content-Type-Options':    'X-Content-Type-Options: nosniff',
    'Referrer-Policy':           'Referrer-Policy: strict-origin-when-cross-origin',
    'Permissions-Policy':        'Permissions-Policy: camera=(), microphone=(), geolocation=()',
    'X-XSS-Protection':          'X-XSS-Protection: 1; mode=block',
};
const HEADER_NGINX = {
    'Strict-Transport-Security': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    'Content-Security-Policy':   "add_header Content-Security-Policy \"default-src 'self'\" always;",
    'X-Frame-Options':           'add_header X-Frame-Options "SAMEORIGIN" always;',
    'X-Content-Type-Options':    'add_header X-Content-Type-Options "nosniff" always;',
    'Referrer-Policy':           'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    'Permissions-Policy':        'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
    'X-XSS-Protection':          'add_header X-XSS-Protection "1; mode=block" always;',
};

function renderHeadersAudit(d) {
    const pane = $('pane-headers');
    if (!d || d.error) { pane.innerHTML = `<div class="no-results">⚠ ${d?.error||'No data'}</div>`; return; }
    const gradeColor = { A:'#00ff88', B:'#44cc88', C:'#ffaa00', D:'#ff6600', F:'#ff0033' };
    const gc = gradeColor[d.grade] || '#888';
    const gradeLabelEs = { A:'Excelente', B:'Bueno', C:'Mejorable', D:'Deficiente', F:'Suspenso' };
    const gradeLabelEn = { A:'Excellent', B:'Good',   C:'Needs work', D:'Poor',      F:'Failing' };
    const sevLabel = s => state.lang==='es' ? ({high:'ALTO',medium:'MEDIO',low:'BAJO'}[s]||s.toUpperCase()) : s.toUpperCase();
    const missingHigh = (d.missing||[]).filter(h=>h.severity==='high').length;
    const missingMed  = (d.missing||[]).filter(h=>h.severity==='medium').length;
    const missingLow  = (d.missing||[]).filter(h=>h.severity==='low').length;
    let html = `<div class="grade-row">
        <div class="grade-badge grade-${d.grade}">${d.grade}</div>
        <div class="grade-info">
            <div style="font-family:var(--font-mono);font-size:16px;color:${gc};font-weight:700">${state.lang==='es'?'Puntuación':'Score'}: ${d.score}/100 — ${state.lang==='es'?gradeLabelEs[d.grade]:gradeLabelEn[d.grade]}</div>
            <div class="grade-score">${d.present?.length||0} ${state.lang==='es'?'cabeceras correctas':'headers present'} · ${d.missing?.length||0} ${state.lang==='es'?'ausentes':'missing'}</div>
            <div class="grade-url">${d.url}</div>
        </div>
    </div>
    <div class="audit-stat-bar">
        <div class="asb-item"><div class="asb-dot" style="background:#ff0033"></div><span class="asb-label">${state.lang==='es'?'Alto':'High'}</span><span class="asb-num" style="color:#ff0033">${missingHigh}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#ffaa00"></div><span class="asb-label">${state.lang==='es'?'Medio':'Medium'}</span><span class="asb-num" style="color:#ffaa00">${missingMed}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#00bb66"></div><span class="asb-label">${state.lang==='es'?'Bajo':'Low'}</span><span class="asb-num" style="color:#00bb66">${missingLow}</span></div>
        <div class="asb-item" style="margin-left:auto"><span class="asb-label">${state.lang==='es'?'Presentes':'Present'}</span><span class="asb-num" style="color:#aaa">${d.present?.length||0}</span></div>
    </div>`;

    if (d.missing?.length) {
        html += `<div class="subsection-label">⚠ ${state.lang==='es'?'Cabeceras ausentes':'Missing headers'} (${d.missing.length})</div>`;
        d.missing.forEach(h => {
            const example = HEADER_EXAMPLES[h.header] || '';
            const nginx   = HEADER_NGINX[h.header]   || '';
            html += `<div class="missing-header-card sev-${h.severity}-card">
                <div class="mhc-top"><div class="mhc-name">${h.header}</div><span class="sev-badge sev-${h.severity}">${sevLabel(h.severity)}</span></div>
                <div class="mhc-desc">${state.lang==='es'?h.description_es:h.description_en}</div>
                ${example ? `<div class="mhc-example-label">${state.lang==='es'?'Añadir a tu servidor:':'Add to your server:'}</div>
                <div class="mhc-example">${example.replace(/</g,'&lt;').replace(/>/g,'&gt;')}<button class="copy-btn" style="position:absolute;top:5px;right:7px" onclick="copyText(${JSON.stringify(nginx||example)},this)">${state.lang==='es'?'Copiar nginx':'Copy nginx'}</button></div>` : ''}
            </div>`;
        });
    }
    if (d.present?.length) {
        html += `<div class="subsection-label" style="margin-top:20px">✓ ${state.lang==='es'?'Cabeceras presentes':'Present headers'} (${d.present.length})</div>`;
        d.present.forEach(h => {
            html += `<div class="present-header-card"><div class="phc-top"><div><div class="phc-name">✓ ${h.header}</div><div class="phc-val">${h.value}</div></div></div></div>`;
        });
    }
    if (d.dangerous?.length) {
        html += `<div class="subsection-label" style="margin-top:20px;color:#ffaa00">⚠ ${state.lang==='es'?'Cabeceras que revelan información':'Information disclosure headers'}</div>`;
        d.dangerous.forEach(h => {
            html += `<div class="danger-card">
                <div class="danger-card-top"><span class="danger-card-key">${h.header}:</span><span class="danger-card-val">${h.value}</span><button class="copy-btn" style="margin-left:auto" onclick="copyText(${JSON.stringify(h.header+': '+h.value)},this)">${state.lang==='es'?'Copiar':'Copy'}</button></div>
                <div class="danger-card-desc">${h.description}</div>
                <div class="danger-card-tip">💡 ${state.lang==='es'?'Eliminar con nginx: ':'Remove with nginx: '}<code style="color:#ffcc77">server_tokens off;</code></div>
            </div>`;
        });
    }
    pane.innerHTML = html;
}

function renderTechAudit(d) {
    const pane = $('pane-technologies');
    if (!d || d.error) { pane.innerHTML = `<div class="no-results">⚠ ${d?.error||'No data'}</div>`; return; }
    if (!d.technologies?.length) { pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'No se detectaron tecnologías':'No technologies detected'}</div>`; return; }
    const cats = d.by_category || {};
    let html = '';
    Object.entries(cats).forEach(([cat, techs]) => {
        html += `<div class="subsection-label">${cat}</div><div class="tech-list">`;
        techs.forEach(t => {
            html += `<div class="tech-row"><span class="tech-icon-sm">${t.icon}</span><span class="tech-name-sm">${t.name}</span><span class="tech-cat-sm">${t.category}</span></div>`;
        });
        html += '</div>';
    });
    pane.innerHTML = html;
}

function renderPathsAudit(d) {
    const pane = $('pane-paths');
    if (!d) { pane.innerHTML = '<div class="no-results">No data</div>'; return; }
    if (!d.found?.length) { pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'No se encontraron rutas sensibles':'No sensitive paths found'}</div>`; return; }
    const sevLabel = s => state.lang==='es' ? ({high:'ALTO',medium:'MEDIO',info:'INFO'}[s]||s.toUpperCase()) : s.toUpperCase();
    const highAll  = d.found.filter(f => f.severity==='high').length;
    const medAll   = d.found.filter(f => f.severity==='medium').length;
    const acc200   = d.found.filter(f => f.accessible).length;
    const rest403  = d.found.filter(f => !f.accessible && f.status_code===403).length;
    let html = `<div class="audit-stat-bar">
        <div class="asb-item"><div class="asb-dot" style="background:#ff0033"></div><span class="asb-label">${state.lang==='es'?'Alto riesgo':'High risk'}</span><span class="asb-num" style="color:#ff0033">${highAll}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#ffaa00"></div><span class="asb-label">${state.lang==='es'?'Riesgo medio':'Medium risk'}</span><span class="asb-num" style="color:#ffaa00">${medAll}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">200 OK</span><span class="asb-num" style="color:#00ff88">${acc200}</span></div>
        <div class="asb-item" style="margin-left:auto"><span class="asb-label">403</span><span class="asb-num" style="color:#888">${rest403}</span></div>
    </div>`;
    const descFor = f => state.lang==='es' ? (f.description.split('/')[0]||f.label).trim() : (f.description.split('/')[1]||f.description).trim();
    const accessible = d.found.filter(f => f.accessible);
    const others     = d.found.filter(f => !f.accessible);
    if (accessible.length) {
        html += `<div class="subsection-label" style="color:#ff5533">🔴 ${state.lang==='es'?'Accesibles públicamente':'Publicly accessible'} (${accessible.length})</div>`;
        accessible.forEach(f => {
            html += `<div class="path-card pc-${f.severity}">
                <div class="path-card-status pcs-${f.status_code}">${f.status_code}</div>
                <div class="path-card-body"><div class="path-card-url">${f.path}</div><div class="path-card-label">${f.label}</div><div class="path-card-desc">${descFor(f)}</div></div>
                <div class="path-card-right"><span class="path-status-tag pst-${f.severity}">${sevLabel(f.severity)}</span><button class="path-copy-btn" onclick="copyText(${JSON.stringify(f.url)},this)">${state.lang==='es'?'Copiar URL':'Copy URL'}</button></div>
            </div>`;
        });
    }
    if (others.length) {
        html += `<div class="subsection-label" style="margin-top:24px">🔒 ${state.lang==='es'?'Existen pero bloqueadas':'Exist but blocked'} (${others.length})</div>`;
        others.forEach(f => {
            html += `<div class="path-card" style="opacity:.75">
                <div class="path-card-status pcs-${f.status_code}">${f.status_code}</div>
                <div class="path-card-body"><div class="path-card-url">${f.path}</div><div class="path-card-label">${f.label}</div></div>
                <div class="path-card-right"><span class="path-status-tag ${f.severity==='high'?'pst-medium':'pst-info'}">${sevLabel(f.severity)}</span></div>
            </div>`;
        });
    }
    pane.innerHTML = html;
}
