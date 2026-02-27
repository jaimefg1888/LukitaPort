// api.js — LukitaPort v2.0
// Handles: EventSource streaming scan, fingerprint, audit, SSL, CVE, discover, subdomains.

import { state }  from './state.js';
import { $, showToast, appendRow, renderTable, updateSummary, setDotBlink,
         showError, saveHistory, renderHistory, renderAudit, renderSSLAudit,
         renderCVEAudit, renderGeo } from './ui.js';

// ── Helpers ────────────────────────────────────────────────────────────────────
export function cleanTarget(raw) {
    let t = raw.trim().replace(/^https?:\/\//i, '').split('/')[0].split('?')[0].split('#')[0];
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(t.split(':')[0]);
    if (!isIP) t = t.split(':')[0];
    return t.trim();
}

function getTs()   { return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19); }
function getSlug() { return (state.scanMeta?.ip ?? 'scan').replace(/\./g, '_'); }

// ── Scan (SSE) ─────────────────────────────────────────────────────────────────
export function startScan() {
    const target = cleanTarget($('target').value);
    if (!target) { $('target').focus(); return; }
    $('target').value = target;
    $('target').style.borderColor = '';

    state.results   = [];
    state.counts    = { open: 0, closed: 0, filtered: 0 };
    state.scanMeta  = null;
    state.scanning  = true;
    state.versions  = {};
    state.auditData = null;
    state.geoData   = null;

    // UI reset
    $('btn-scan').querySelector('.es').textContent = 'Detener';
    $('btn-scan').querySelector('.en').textContent = 'Stop';
    $('btn-scan').style.borderColor = '#ff4444';
    $('btn-scan').style.color       = '#ff4444';
    $('results-body').innerHTML     = '';
    $('status-bar').classList.add('visible');
    $('results-panel').classList.add('visible');
    $('summary-panel').style.display = 'none';
    $('audit-panel').classList.remove('visible');
    $('btn-fingerprint').style.display = 'none';
    $('fp-status-bar').textContent = '';
    const geoBadge = $('geo-badge');
    if (geoBadge) geoBadge.style.display = 'none';
    setDotBlink(true);
    updateSummary();

    const mode    = $('scan-mode').value;
    const profile = $('scan-profile').value;
    const anonEl  = document.getElementById('anon-mode');
    const isAnon  = anonEl?.checked || false;

    // Anon mode: force stealth profile + visual indicator
    const effectiveProfile = isAnon ? 'stealth' : profile;
    if (isAnon) {
        const dot = document.getElementById('anon-dot');
        if (dot) { dot.style.background='#00ff88'; dot.style.boxShadow='0 0 6px #00ff88'; }
    }

    const params  = new URLSearchParams({
        target,
        mode,
        profile: effectiveProfile,
        port_start: $('port-start').value,
        port_end:   $('port-end').value,
        timeout:    $('timeout').value,
        anon:       isAnon ? '1' : '0',
    });

    if (state.eventSource) state.eventSource.close();
    state.eventSource = new EventSource('/api/scan?' + params);

    state.eventSource.onmessage = e => {
        const d = JSON.parse(e.data);
        if (d.error) { showError(d.error); stopScan(); return; }

        if (d.type === 'meta') {
            state.scanMeta = d;
            $('status-target').textContent = (d.hostname && d.hostname !== d.ip)
                ? d.hostname + ' (' + d.ip + ')'
                : d.ip;
            $('st-total').textContent = d.total_ports;
            if (d.geo && Object.keys(d.geo).length) {
                state.geoData = d.geo;
                renderGeo(d.geo);
            }
            return;
        }
        if (d.type === 'port') {
            state.results.push(d);
            state.counts[d.state]++;
            // NOTE: banners from scan are raw/noisy — version column populated only after Fingerprinting
            $('st-scanned').textContent  = d.scanned;
            $('st-open').textContent     = state.counts.open;
            $('progress-fill').style.width = d.progress + '%';
            if (state.filter === 'all' || state.filter === d.state) appendRow(d);
            updateSummary();
            return;
        }
        if (d.type === 'done') stopScan(true);
    };

    state.eventSource.onerror = () => { if (state.scanning) stopScan(); };
}

export function stopScan(completed = false) {
    state.scanning = false;
    if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }

    $('btn-scan').querySelector('.es').textContent = 'Iniciar Escaneo';
    $('btn-scan').querySelector('.en').textContent = 'Start Scan';
    $('btn-scan').style.borderColor = '';
    $('btn-scan').style.color       = '';
    setDotBlink(false);

    if (completed) {
        $('progress-fill').style.width   = '100%';
        $('summary-panel').style.display = 'block';

        if (state.scanMeta) {
            const openPorts = state.results.filter(r => r.state === 'open').map(r => ({ port: r.port, service: r.service }));
            saveHistory({
                target:   state.scanMeta.input || state.scanMeta.ip,
                ip:       state.scanMeta.ip,
                mode:     state.scanMeta.mode,
                profile:  state.scanMeta.profile || 'normal',
                open:     state.counts.open,
                total:    state.results.length,
                riskHigh: openPorts.filter(p => { import('./state.js').then(m => m.getRisk(p.port) === 'high'); return false; }).length,
                riskMed:  0,
                openPorts,
                date:     new Date().toLocaleString(),
            });
            renderHistory();

            const webPorts = state.results.filter(r => r.state === 'open' && [80, 443, 8080, 8443, 8888].includes(r.port));
            if (webPorts.length > 0) {
                $('audit-panel').classList.add('visible');
                launchAudit();

                // Trigger background screenshot on first web port found
                const firstWebPort = webPorts[0];
                const screenshotTarget = state.scanMeta.hostname || state.scanMeta.ip;
                fetch(`/api/screenshot/capture?target=${encodeURIComponent(screenshotTarget)}&port=${firstWebPort.port}`, { method: 'POST' })
                    .catch(() => {});
            }
            if (state.counts.open > 0) {
                $('btn-fingerprint').style.display   = 'inline-flex';
                $('btn-fingerprint').disabled        = false;
                $('btn-fingerprint').className       = 'btn-fingerprint';
                $('btn-fingerprint').innerHTML       = '🔍 <span class="es">Fingerprinting</span><span class="en">Fingerprint</span>';
            }
        }
    }
    if (!state.results.length) {
        const msg = state.lang === 'es' ? 'Sin resultados' : 'No results found';
        $('results-body').innerHTML = `<tr><td colspan="6"><div class="empty-state">[ _ ]<br>${msg}</div></td></tr>`;
    }
}

// ── Fingerprinting ─────────────────────────────────────────────────────────────
export async function runFingerprint() {
    const btn      = $('btn-fingerprint');
    const statusEl = $('fp-status-bar');
    btn.disabled   = true;
    btn.className  = 'btn-fingerprint running';
    btn.innerHTML  = '<span class="spinner"></span><span class="es">Fingerprinting...</span><span class="en">Fingerprinting...</span>';
    statusEl.style.cssText = 'color:var(--text-dim)';
    statusEl.textContent   = state.lang === 'es' ? '⟳ Consultando nmap — puede tardar 15–30s...' : '⟳ Querying nmap — may take 15–30s...';

    const openPorts = state.results.filter(r => r.state === 'open').map(r => r.port);
    const target    = state.scanMeta?.input || state.scanMeta?.ip;
    if (!target || !openPorts.length) { btn.disabled = false; statusEl.textContent = ''; return; }

    const resetBtn = () => { setTimeout(() => { btn.disabled = false; btn.className = 'btn-fingerprint'; btn.innerHTML = '🔍 <span class="es">Fingerprinting</span><span class="en">Fingerprint</span>'; }, 6000); };

    try {
        const resp = await fetch(`/api/fingerprint?target=${encodeURIComponent(target)}&ports=${openPorts.join(',')}&timeout=8`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        if (data.error) {
            btn.className = 'btn-fingerprint fp-error'; btn.innerHTML = '⚠ Error';
            statusEl.style.cssText = 'color:#cc3344'; statusEl.textContent = 'Error: ' + data.error;
            resetBtn(); return;
        }

        const results = data.results || {};
        if (results._error === 'nmap_not_installed') {
            btn.className = 'btn-fingerprint fp-error'; btn.innerHTML = '⚠ nmap';
            const isWin = navigator.userAgent.includes('Windows');
            const cmd   = isWin ? 'winget install Insecure.Nmap' : 'sudo apt install nmap';
            statusEl.style.cssText = '';
            statusEl.innerHTML = `<div class="nmap-error-box">⚠ <strong>nmap no está instalado</strong>. ${state.lang==='es'?'Instalar con:':'Install with:'} <code>${cmd}</code></div>`;
            resetBtn(); return;
        }

        let updated = 0;
        Object.entries(results).forEach(([portKey, info]) => {
            const p = parseInt(portKey); if (isNaN(p)) return;
            const vStr = [info.product, info.version, info.extrainfo].filter(Boolean).join(' ').trim();
            if (vStr) { state.versions[p] = { version: vStr, source: 'nmap', cpe: info.cpe || '' }; updated++; }
        });

        import('./ui.js').then(({ renderTable }) => renderTable());
        btn.className = 'btn-fingerprint fp-done'; btn.innerHTML = '✓ <span class="es">Actualizado</span><span class="en">Updated</span>';
        statusEl.style.cssText = 'color:#00cc66';
        statusEl.textContent = updated > 0
            ? (state.lang==='es' ? `✓ ${updated} versiones detectadas` : `✓ ${updated} versions detected`)
            : (state.lang==='es' ? 'nmap no detectó versiones conocidas' : 'nmap could not identify versions');
        setTimeout(() => { btn.disabled = false; btn.className = 'btn-fingerprint'; btn.innerHTML = '🔍 <span class="es">Fingerprinting</span><span class="en">Fingerprint</span>'; statusEl.style.cssText=''; statusEl.textContent=''; }, 10000);

        // Re-launch CVE after fingerprinting
        launchCVELookup();
    } catch (e) {
        btn.className = 'btn-fingerprint fp-error'; btn.innerHTML = '⚠ Timeout';
        statusEl.style.cssText = 'color:#cc3344'; statusEl.textContent = (state.lang==='es'?'Error: ':'Error: ') + e.message;
        resetBtn();
    }
}

// ── Full Audit ─────────────────────────────────────────────────────────────────
export async function launchAudit() {
    const target    = state.scanMeta?.input || state.scanMeta?.ip;
    if (!target) return;
    const openPorts = state.results.filter(r => r.state === 'open').map(r => r.port).join(',');
    const statusEl  = $('audit-status');
    statusEl.innerHTML = '<span class="spinner"></span><span class="es">Analizando...</span><span class="en">Analyzing...</span>';

    const allPanes = ['headers','technologies','paths','ssl','cve'];
    const texts = {
        headers:      { es:'Auditando cabeceras HTTP...', en:'Auditing HTTP headers...' },
        technologies: { es:'Detectando tecnologías...',  en:'Detecting technologies...' },
        paths:        { es:'Escaneando rutas sensibles...',en:'Scanning sensitive paths...' },
        ssl:          { es:'Analizando SSL/TLS...',       en:'Analyzing SSL/TLS...' },
        cve:          { es:'Buscando CVEs conocidos...',  en:'Searching known CVEs...' },
    };
    allPanes.forEach(p => {
        $('pane-'+p).innerHTML = `<div class="audit-loading"><span class="spinner"></span>${state.lang==='es'?texts[p].es:texts[p].en}</div>`;
    });

    const sslPorts    = state.results.filter(r => r.state==='open' && [443,8443].includes(r.port)).map(r=>r.port);
    const auditFetch  = fetch(`/api/audit?target=${encodeURIComponent(target)}&open_ports=${encodeURIComponent(openPorts)}`).then(r=>r.json()).catch(()=>null);
    const sslFetch    = sslPorts.length > 0
        ? fetch(`/api/ssl?target=${encodeURIComponent(target)}&open_ports=${encodeURIComponent(sslPorts.join(','))}`).then(r=>r.json()).catch(()=>null)
        : Promise.resolve(null);

    try {
        const [auditData, sslData] = await Promise.all([auditFetch, sslFetch]);
        if (auditData) { state.auditData = auditData; renderAudit(auditData); }
        else { allPanes.slice(0,3).forEach(p => { $('pane-'+p).innerHTML=`<div class="no-results">⚠ ${state.lang==='es'?'Error al conectar':'Connection error'}</div>`; }); }
        renderSSLAudit(sslData);
        // CVE is NOT auto-launched here — user must click or run Fingerprinting first
        // (auto CVE without version data gives poor, slow results)
        $('pane-cve').innerHTML = `<div class="no-results" style="padding:36px 24px">[ 🐛 ]<br>
            <span style="display:block;margin:12px 0 20px;font-size:12px">${state.lang==='es'?'Ejecuta <b style=color:#aaa>Fingerprinting</b> para resultados precisos, o lanza el análisis ahora.':'Run <b style=color:#aaa>Fingerprinting</b> for precise results, or launch analysis now.'}</span>
            <button id="btn-launch-cve" onclick="window.launchCVELookup && window.launchCVELookup()" style="padding:8px 22px;background:transparent;border:1px solid #333;border-radius:4px;color:#888;font-family:var(--font-mono);font-size:11px;cursor:pointer;letter-spacing:.8px;transition:all .2s" onmouseover="this.style.borderColor='#ff0033';this.style.color='#ff0033'" onmouseout="this.style.borderColor='#333';this.style.color='#888'">
                🐛 ${state.lang==='es'?'Buscar CVEs ahora':'Search CVEs now'}
            </button></div>`;
        statusEl.textContent = '';
    } catch {
        statusEl.textContent = state.lang==='es'?'Error en auditoría':'Audit error';
    }
}

// ── CVE Lookup ─────────────────────────────────────────────────────────────────
export async function launchCVELookup() {
    const pane      = $('pane-cve');
    const openPorts = state.results.filter(r => r.state === 'open');

    // Show loading immediately so user sees it's working
    pane.innerHTML = `<div class="audit-loading"><span class="spinner"></span><span class="es">Buscando CVEs conocidos... (puede tardar ~${Math.ceil(openPorts.length * 6.5)}s por límite de NVD)</span><span class="en">Searching CVEs... (~${Math.ceil(openPorts.length * 6.5)}s due to NVD rate limit)</span></div>`;

    if (!openPorts.length) {
        pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'Sin puertos abiertos':'No open ports'}</div>`;
        return;
    }

    const versionsPayload = {};
    openPorts.forEach(r => {
        const v = state.versions[r.port];
        if (v?.version) versionsPayload[r.port] = { name: r.service, version: v.version };
        else if (r.service && r.service !== 'Unknown') versionsPayload[r.port] = { name: r.service, version: '' };
    });

    if (!Object.keys(versionsPayload).length) {
        pane.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'Ejecuta Fingerprinting primero':'Run Fingerprinting first for better results'}</div>`;
        return;
    }

    try {
        const resp = await fetch('/api/cve/batch', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(versionsPayload) });
        const data = await resp.json();
        renderCVEAudit(data.results || {}, versionsPayload);
    } catch {
        pane.innerHTML = `<div class="no-results">⚠ ${state.lang==='es'?'No se pudo conectar con NVD':'Could not connect to NVD'}</div>`;
    }
}

// ── Network Discovery (CIDR ping sweep) ───────────────────────────────────────
export async function launchDiscover() {
    const cidr   = $('discover-cidr')?.value?.trim();
    const output = $('discover-output');
    if (!cidr || !output) return;

    const btn = $('btn-discover');
    if (btn) { btn.disabled = true; btn.textContent = state.lang==='es'?'Escaneando...':'Scanning...'; }
    output.innerHTML = `<div class="audit-loading"><span class="spinner"></span>${state.lang==='es'?'Escaneando red...':'Scanning network...'}</div>`;

    try {
        const resp = await fetch(`/api/discover?cidr=${encodeURIComponent(cidr)}`);
        const data = await resp.json();

        if (data.error) { output.innerHTML = `<div class="no-results">⚠ ${data.error}</div>`; return; }

        if (!data.alive?.length) { output.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'No se encontraron hosts activos':'No live hosts found'} en ${cidr}</div>`; return; }

        output.innerHTML = `<div class="audit-stat-bar" style="margin-bottom:14px">
            <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">${state.lang==='es'?'Hosts activos':'Live hosts'}</span><span class="asb-num" style="color:#00ff88">${data.alive_count}</span></div>
            <div class="asb-item" style="margin-left:auto"><span class="asb-label">${state.lang==='es'?'Rango':'Range'}</span><span class="asb-num" style="color:#888">${data.total_hosts}</span></div>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${data.alive.map(h => `
                <div style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:#0a0a0a;border:1px solid rgba(0,255,136,.15);border-radius:4px;cursor:pointer;transition:border-color .15s"
                     onclick="document.getElementById('target').value='${h.ip}';document.getElementById('target').dispatchEvent(new Event('input'));"
                     title="${state.lang==='es'?'Clic para escanear':'Click to scan'}">
                    <span style="width:7px;height:7px;border-radius:50%;background:#00ff88;box-shadow:0 0 4px #00ff88;flex-shrink:0"></span>
                    <span style="font-family:var(--font-mono);font-size:13px;color:#00cc66;font-weight:600">${h.ip}</span>
                    ${h.rtt_ms !== null ? `<span style="font-family:var(--font-mono);font-size:10px;color:#555">${h.rtt_ms} ms</span>` : ''}
                </div>`).join('')}
        </div>`;
    } catch (e) {
        output.innerHTML = `<div class="no-results">⚠ ${e.message}</div>`;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = state.lang==='es'?'Descubrir':'Discover'; }
    }
}

// ── Subdomain Enumeration ──────────────────────────────────────────────────────
export async function launchSubdomains() {
    const domain = $('subdomain-input')?.value?.trim();
    const output = $('subdomain-output');
    if (!domain || !output) return;

    const btn = $('btn-subdomains');
    if (btn) { btn.disabled = true; btn.textContent = state.lang==='es'?'Buscando...':'Searching...'; }
    output.innerHTML = `<div class="audit-loading"><span class="spinner"></span>${state.lang==='es'?'Consultando crt.sh...':'Querying crt.sh...'}</div>`;

    try {
        const resp = await fetch(`/api/subdomains?domain=${encodeURIComponent(domain)}`);
        const data = await resp.json();

        if (data.error) { output.innerHTML = `<div class="no-results">⚠ ${data.error}</div>`; return; }
        if (!data.subdomains?.length) { output.innerHTML = `<div class="no-results">[ _ ]<br>${state.lang==='es'?'No se encontraron subdominios':'No subdomains found'} para ${domain}</div>`; return; }

        output.innerHTML = `<div class="audit-stat-bar" style="margin-bottom:14px">
            <div class="asb-item"><div class="asb-dot" style="background:#8899ff"></div><span class="asb-label">${state.lang==='es'?'Subdominios encontrados':'Subdomains found'}</span><span class="asb-num" style="color:#8899ff">${data.total}</span></div>
            <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">${state.lang==='es'?'Resueltos':'Resolved'}</span><span class="asb-num" style="color:#00ff88">${data.subdomains.filter(s=>s.resolves).length}</span></div>
        </div>
        <div class="table-wrap" style="max-height:320px">
            <table>
                <thead><tr>
                    <th>${state.lang==='es'?'Subdominio':'Subdomain'}</th>
                    <th>IP</th>
                    <th>${state.lang==='es'?'Cert válido hasta':'Cert expiry'}</th>
                    <th></th>
                </tr></thead>
                <tbody>
                    ${data.subdomains.map(s => `
                        <tr>
                            <td class="col-service">${s.subdomain}</td>
                            <td style="font-family:var(--font-mono);font-size:11px;color:${s.resolves?'#00cc66':'#555'}">${s.ip || (s.resolves===false?'✗ NXDOMAIN':'—')}</td>
                            <td style="font-family:var(--font-mono);font-size:10px;color:#666">${s.not_after||'—'}</td>
                            <td><button class="btn-export" style="padding:3px 9px;font-size:10px" onclick="document.getElementById('target').value='${s.subdomain}';">→ ${state.lang==='es'?'Escanear':'Scan'}</button></td>
                        </tr>`).join('')}
                </tbody>
            </table>
        </div>`;
    } catch (e) {
        output.innerHTML = `<div class="no-results">⚠ ${e.message}</div>`;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = state.lang==='es'?'Buscar Subdominios':'Find Subdomains'; }
    }
}
