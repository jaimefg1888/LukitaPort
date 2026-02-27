// export.js
import { state, getRisk }    from './state.js';
import { $, showToast }      from './ui.js';
import { tmplHTMLReport }    from './templates.js';

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

export function exportJSON() {
    if (!state.results.length) return;
    const meta    = state.scanMeta || {};
    const payload = {
        meta: {
            tool:         'LukitaPort',
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
        const resp = await fetch('/api/export/pdf', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body),
        });
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
        const resp = await fetch('/api/export/md', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body),
        });
        if (!resp.ok) throw new Error('Server error');
        dl(await resp.text(), `lukitaport_report_${getSlug()}_${getTs()}.md`, 'text/markdown');
        showToast('Markdown exportado ✓', 'ok');
    } catch (e) {
        showToast((state.lang === 'es' ? 'Error generando MD: ' : 'MD error: ') + e.message, 'error');
    }
    btn.textContent = '↓ MD';
    btn.disabled    = false;
}

export function exportHTMLReport() {
    if (!state.results.length) return;
    const html = tmplHTMLReport({
        meta:      state.scanMeta || {},
        results:   state.results,
        counts:    state.counts,
        auditData: state.auditData,
        geoData:   state.geoData,
        versions:  state.versions,
        getRisk,
    });
    dl(html, `lukitaport_report_${getSlug()}_${getTs()}.html`, 'text/html');
    showToast('HTML exportado ✓', 'ok');
}
