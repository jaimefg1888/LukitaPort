// export.js — LukitaPort v2.0
// Handles: JSON, CSV, HTML, PDF, MD exports.

import { state, getRisk } from './state.js';
import { $, showToast }   from './ui.js';

function getTs()   { return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19); }
function getSlug() { return (state.scanMeta?.ip ?? 'scan').replace(/\./g, '_'); }

function dl(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// ── JSON ────────────────────────────────────────────────────────────────────
export function exportJSON() {
    if (!state.results.length) return;
    const meta = state.scanMeta || {};
    const payload = {
        meta: {
            tool:         'LukitaPort v2.0.0',
            author:       'jaimefg1888',
            generated_at: new Date().toISOString(),
            target:       meta,
            geo:          state.geoData || {},
            summary:      { ...state.counts, total: state.results.length },
        },
        results: state.results.map(r => ({
            ...r,
            risk:    getRisk(r.port),
            version: state.versions[r.port] || null,
        })),
    };
    dl(JSON.stringify(payload, null, 2), `lukitaport_${getSlug()}_${getTs()}.json`, 'application/json');
    showToast('JSON exportado ✓', 'ok');
}

// ── CSV ─────────────────────────────────────────────────────────────────────
export function exportCSV() {
    if (!state.results.length) return;
    const rows = [['Port', 'State', 'Service', 'Risk', 'Response_ms', 'Version']];
    state.results.forEach(r => rows.push([
        r.port, r.state, r.service, getRisk(r.port),
        r.response_time_ms ?? '',
        state.versions[r.port]?.version || '',
    ]));
    dl(rows.map(r => r.join(',')).join('\r\n'), `lukitaport_${getSlug()}_${getTs()}.csv`, 'text/csv');
    showToast('CSV exportado ✓', 'ok');
}

// ── PDF (server-side) ────────────────────────────────────────────────────────
export async function exportPDF() {
    if (!state.results.length) return;
    const btn = $('btn-pdf');
    btn.textContent = '↻ PDF...';
    btn.disabled    = true;
    try {
        const body = {
            scan: {
                meta:    { target: state.scanMeta },
                results: state.results.map(r => ({ ...r, version: state.versions[r.port]?.version || null })),
                summary: { ...state.counts, total: state.results.length },
            },
            audit:             state.auditData || null,
            screenshot_target: state.scanMeta?.hostname || state.scanMeta?.ip || null,
        };
        const resp = await fetch('/api/export/pdf', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        if (!resp.ok) throw new Error('Server error');
        const blob = await resp.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = `lukitaport_report_${getSlug()}_${getTs()}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('PDF generado ✓', 'ok');
    } catch (e) {
        showToast((state.lang === 'es' ? 'Error generando PDF: ' : 'PDF error: ') + e.message, 'error');
    }
    btn.textContent = '↓ PDF';
    btn.disabled    = false;
}

// ── Markdown (server-side) ───────────────────────────────────────────────────
export async function exportMarkdown() {
    if (!state.results.length) return;
    const btn = $('btn-md');
    btn.textContent = '↻ MD...';
    btn.disabled    = true;
    try {
        const body = {
            scan: {
                meta:    { target: state.scanMeta },
                results: state.results.map(r => ({ ...r, version: state.versions[r.port]?.version || null })),
                summary: { ...state.counts, total: state.results.length },
            },
            audit: state.auditData || null,
        };
        const resp = await fetch('/api/export/md', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        if (!resp.ok) throw new Error('Server error');
        const text = await resp.text();
        dl(text, `lukitaport_report_${getSlug()}_${getTs()}.md`, 'text/markdown');
        showToast('Markdown exportado ✓', 'ok');
    } catch (e) {
        showToast((state.lang === 'es' ? 'Error generando MD: ' : 'MD error: ') + e.message, 'error');
    }
    btn.textContent = '↓ MD';
    btn.disabled    = false;
}

// ── HTML (client-side) ──────────────────────────────────────────────────────
export function exportHTMLReport() {
    if (!state.results.length) return;
    const meta   = state.scanMeta || {};
    const ts     = new Date().toLocaleString();
    const openP  = state.results.filter(r => r.state === 'open');
    const rc     = { high:'#ff0033', medium:'#ffaa00', low:'#00ff88', info:'#444' };
    const rl2    = { high:'HIGH', medium:'MEDIUM', low:'LOW', info:'—' };
    const geo    = state.geoData || {};

    const rows = state.results.map(r => {
        const sc  = r.state==='open'?'#00ff88':r.state==='filtered'?'#ffaa00':'#ff4444';
        const rk  = getRisk(r.port);
        const ver = state.versions[r.port]?.version || '';
        return `<tr><td>${r.port}</td><td style="color:${sc}">● ${r.state.charAt(0).toUpperCase()+r.state.slice(1)}</td><td>${r.service}</td><td style="color:${rc[rk]};font-size:10px">${rl2[rk]}</td><td>${r.response_time_ms??'—'} ms</td><td style="font-size:10px;color:#666;max-width:160px;overflow:hidden">${ver}</td></tr>`;
    }).join('');

    const geoHtml = geo.country ? `<tr><td style="color:#444;width:160px">Location</td><td>${geo.city||''} · ${geo.country||''} · ${geo.asn||''}</td></tr><tr><td style="color:#444">ISP</td><td>${geo.isp||'—'}</td></tr>` : '';

    let auditHtml = '';
    if (state.auditData) {
        const hd = state.auditData.headers;
        if (hd && !hd.error) { auditHtml += `<h2>HTTP Security Headers — Grade: <span style="color:${{A:'#00ff88',B:'#44cc88',C:'#ffaa00',D:'#ff6600',F:'#ff0033'}[hd.grade]||'#888'}">${hd.grade}</span> (${hd.score}/100)</h2>${hd.missing?.length?'<p style="color:#ff0033;margin-bottom:6px">Missing: '+hd.missing.map(h=>`<code>${h.header}</code>`).join(', ')+'</p>':''}`; }
        const td = state.auditData.technologies;
        if (td && td.technologies?.length) { auditHtml += `<h2>Detected Technologies (${td.count})</h2><p>${td.technologies.map(t=>`${t.icon} ${t.name}`).join(' · ')}</p>`; }
        const pd = state.auditData.paths;
        if (pd && pd.found?.length) { auditHtml += `<h2>Sensitive Paths (${pd.total_found} found)</h2><table><thead><tr><th>Path</th><th>Status</th><th>Severity</th></tr></thead><tbody>${pd.found.map(f=>`<tr><td>${f.path}</td><td>${f.status_code}</td><td style="color:${rc[f.severity]||'#888'}">${f.severity.toUpperCase()}</td></tr>`).join('')}</tbody></table>`; }
    }

    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>LukitaPort Report</title><link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@400;700&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#050505;color:#f0f0f0;font-family:'Inter',sans-serif;font-size:13px;padding:40px;line-height:1.6}h1{font-size:1.8rem;color:#ff0033;margin-bottom:4px;font-family:'IBM Plex Mono',monospace}.sub{color:#555;font-size:11px;letter-spacing:1.5px;margin-bottom:32px;font-family:'IBM Plex Mono',monospace}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:#1a1a1a;margin-bottom:28px;border-radius:4px;overflow:hidden}.card{background:#0d0d0d;padding:20px;text-align:center}.card .n{font-size:2.2rem;font-weight:700;line-height:1;margin-bottom:5px;font-family:'IBM Plex Mono',monospace}.card .l{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#333}h2{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#444;margin:28px 0 12px;border-bottom:1px solid #111;padding-bottom:8px;font-family:'IBM Plex Mono',monospace}table{width:100%;border-collapse:collapse}th{text-align:left;padding:9px 14px;font-size:10px;letter-spacing:1.2px;text-transform:uppercase;color:#333;border-bottom:1px solid #111;font-weight:600;font-family:'IBM Plex Mono',monospace}td{padding:10px 14px;border-bottom:1px solid rgba(20,20,20,.9);font-family:'IBM Plex Mono',monospace;font-size:12px}code{background:#111;padding:1px 6px;border-radius:2px;color:#ffaa00;font-family:'IBM Plex Mono',monospace}p{color:#888;font-size:12px;margin-bottom:12px}footer{margin-top:40px;color:#333;font-size:11px;text-align:center;border-top:1px solid #111;padding-top:18px;font-family:'IBM Plex Mono',monospace}</style></head><body><h1>LukitaPort</h1><div class="sub">PORT SCAN REPORT · ${ts}</div><div class="grid"><div class="card"><div class="n" style="color:#00ff88">${state.counts.open}</div><div class="l">Open</div></div><div class="card"><div class="n" style="color:#ff4444">${state.counts.closed}</div><div class="l">Closed</div></div><div class="card"><div class="n" style="color:#ffaa00">${state.counts.filtered}</div><div class="l">Filtered</div></div><div class="card"><div class="n" style="color:#ff0033">${state.results.length}</div><div class="l">Total</div></div></div><h2>Scan Metadata</h2><table><tr><td style="color:#444;width:160px">Target</td><td>${meta.input??'—'}</td></tr><tr><td style="color:#444">Resolved IP</td><td>${meta.ip??'—'}</td></tr><tr><td style="color:#444">Hostname</td><td>${meta.hostname??'—'}</td></tr><tr><td style="color:#444">Mode</td><td>${meta.mode??'—'}</td></tr><tr><td style="color:#444">Profile</td><td>${meta.profile??'normal'}</td></tr>${geoHtml}<tr><td style="color:#444">Generated</td><td>${ts}</td></tr></table><h2>All Results</h2><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Risk</th><th>Response</th><th>Version</th></tr></thead><tbody>${rows}</tbody></table>${auditHtml}<footer>LukitaPort v2.0.0 · jaimefg1888 · For educational use only</footer></body></html>`;

    dl(html, `lukitaport_report_${getSlug()}_${getTs()}.html`, 'text/html');
    showToast('HTML exportado ✓', 'ok');
}
