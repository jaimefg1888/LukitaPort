// templates.js
// Pure HTML template functions. No DOM access — receive data, return HTML strings.
// Imported by ui.js, export.js, and api.js.

// ── Constants used only in templates ─────────────────────────────────────────

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

const GRADE_COLOR = { A: '#00ff88', B: '#44cc88', C: '#ffaa00', D: '#ff6600', F: '#ff0033' };

// ── Headers Audit ─────────────────────────────────────────────────────────────

export function tmplHeadersAudit(d, lang) {
    if (!d || d.error) return `<div class="no-results">⚠ ${d?.error || 'No data'}</div>`;

    const gc = GRADE_COLOR[d.grade] || '#888';
    const gradeLabelEs = { A: 'Excelente', B: 'Bueno', C: 'Mejorable', D: 'Deficiente', F: 'Suspenso' };
    const gradeLabelEn = { A: 'Excellent', B: 'Good',  C: 'Needs work', D: 'Poor',      F: 'Failing' };
    const sevLabel     = s => lang === 'es'
        ? ({ high: 'ALTO', medium: 'MEDIO', low: 'BAJO' }[s] || s.toUpperCase())
        : s.toUpperCase();

    const missingHigh = (d.missing || []).filter(h => h.severity === 'high').length;
    const missingMed  = (d.missing || []).filter(h => h.severity === 'medium').length;
    const missingLow  = (d.missing || []).filter(h => h.severity === 'low').length;

    let html = `<div class="grade-row">
        <div class="grade-badge grade-${d.grade}">${d.grade}</div>
        <div class="grade-info">
            <div style="font-family:var(--font-mono);font-size:16px;color:${gc};font-weight:700">${lang === 'es' ? 'Puntuación' : 'Score'}: ${d.score}/100 — ${lang === 'es' ? gradeLabelEs[d.grade] : gradeLabelEn[d.grade]}</div>
            <div class="grade-score">${d.present?.length || 0} ${lang === 'es' ? 'cabeceras correctas' : 'headers present'} · ${d.missing?.length || 0} ${lang === 'es' ? 'ausentes' : 'missing'}</div>
            <div class="grade-url">${d.url}</div>
        </div>
    </div>
    <div class="audit-stat-bar">
        <div class="asb-item"><div class="asb-dot" style="background:#ff0033"></div><span class="asb-label">${lang === 'es' ? 'Alto' : 'High'}</span><span class="asb-num" style="color:#ff0033">${missingHigh}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#ffaa00"></div><span class="asb-label">${lang === 'es' ? 'Medio' : 'Medium'}</span><span class="asb-num" style="color:#ffaa00">${missingMed}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#00bb66"></div><span class="asb-label">${lang === 'es' ? 'Bajo' : 'Low'}</span><span class="asb-num" style="color:#00bb66">${missingLow}</span></div>
        <div class="asb-item" style="margin-left:auto"><span class="asb-label">${lang === 'es' ? 'Presentes' : 'Present'}</span><span class="asb-num" style="color:#aaa">${d.present?.length || 0}</span></div>
    </div>`;

    if (d.missing?.length) {
        html += `<div class="subsection-label">⚠ ${lang === 'es' ? 'Cabeceras ausentes' : 'Missing headers'} (${d.missing.length})</div>`;
        d.missing.forEach(h => {
            const example = HEADER_EXAMPLES[h.header] || '';
            const nginx   = HEADER_NGINX[h.header]   || '';
            html += `<div class="missing-header-card sev-${h.severity}-card">
                <div class="mhc-top"><div class="mhc-name">${h.header}</div><span class="sev-badge sev-${h.severity}">${sevLabel(h.severity)}</span></div>
                <div class="mhc-desc">${lang === 'es' ? h.description_es : h.description_en}</div>
                ${example ? `<div class="mhc-example-label">${lang === 'es' ? 'Añadir a tu servidor:' : 'Add to your server:'}</div>
                <div class="mhc-example">${example.replace(/</g, '&lt;').replace(/>/g, '&gt;')}<button class="copy-btn" style="position:absolute;top:5px;right:7px" onclick="copyText(${JSON.stringify(nginx || example)},this)">${lang === 'es' ? 'Copiar nginx' : 'Copy nginx'}</button></div>` : ''}
            </div>`;
        });
    }
    if (d.present?.length) {
        html += `<div class="subsection-label" style="margin-top:20px">✓ ${lang === 'es' ? 'Cabeceras presentes' : 'Present headers'} (${d.present.length})</div>`;
        d.present.forEach(h => {
            html += `<div class="present-header-card"><div class="phc-top"><div><div class="phc-name">✓ ${h.header}</div><div class="phc-val">${h.value}</div></div></div></div>`;
        });
    }
    if (d.dangerous?.length) {
        html += `<div class="subsection-label" style="margin-top:20px;color:#ffaa00">⚠ ${lang === 'es' ? 'Cabeceras que revelan información' : 'Information disclosure headers'}</div>`;
        d.dangerous.forEach(h => {
            html += `<div class="danger-card">
                <div class="danger-card-top"><span class="danger-card-key">${h.header}:</span><span class="danger-card-val">${h.value}</span><button class="copy-btn" style="margin-left:auto" onclick="copyText(${JSON.stringify(h.header + ': ' + h.value)},this)">${lang === 'es' ? 'Copiar' : 'Copy'}</button></div>
                <div class="danger-card-desc">${h.description}</div>
                <div class="danger-card-tip">💡 ${lang === 'es' ? 'Eliminar con nginx: ' : 'Remove with nginx: '}<code style="color:#ffcc77">server_tokens off;</code></div>
            </div>`;
        });
    }
    return html;
}

// ── Technology Audit ─────────────────────────────────────────────────────────

export function tmplTechAudit(d, lang) {
    if (!d || d.error) return `<div class="no-results">⚠ ${d?.error || 'No data'}</div>`;
    if (!d.technologies?.length) return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se detectaron tecnologías' : 'No technologies detected'}</div>`;

    const cats = d.by_category || {};
    let html = '';
    Object.entries(cats).forEach(([cat, techs]) => {
        html += `<div class="subsection-label">${cat}</div><div class="tech-list">`;
        techs.forEach(t => {
            html += `<div class="tech-row"><span class="tech-icon-sm">${t.icon}</span><span class="tech-name-sm">${t.name}</span><span class="tech-cat-sm">${t.category}</span></div>`;
        });
        html += '</div>';
    });
    return html;
}

// ── Paths Audit ───────────────────────────────────────────────────────────────

export function tmplPathsAudit(d, lang) {
    if (!d) return '<div class="no-results">No data</div>';
    if (!d.found?.length) return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se encontraron rutas sensibles' : 'No sensitive paths found'}</div>`;

    const sevLabel = s => lang === 'es'
        ? ({ high: 'ALTO', medium: 'MEDIO', info: 'INFO' }[s] || s.toUpperCase())
        : s.toUpperCase();

    const highAll = d.found.filter(f => f.severity === 'high').length;
    const medAll  = d.found.filter(f => f.severity === 'medium').length;
    const acc200  = d.found.filter(f => f.accessible).length;
    const rest403 = d.found.filter(f => !f.accessible && f.status_code === 403).length;

    let html = `<div class="audit-stat-bar">
        <div class="asb-item"><div class="asb-dot" style="background:#ff0033"></div><span class="asb-label">${lang === 'es' ? 'Alto riesgo' : 'High risk'}</span><span class="asb-num" style="color:#ff0033">${highAll}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#ffaa00"></div><span class="asb-label">${lang === 'es' ? 'Riesgo medio' : 'Medium risk'}</span><span class="asb-num" style="color:#ffaa00">${medAll}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">200 OK</span><span class="asb-num" style="color:#00ff88">${acc200}</span></div>
        <div class="asb-item" style="margin-left:auto"><span class="asb-label">403</span><span class="asb-num" style="color:#888">${rest403}</span></div>
    </div>`;

    const descFor  = f => lang === 'es'
        ? (f.description.split('/')[0] || f.label).trim()
        : (f.description.split('/')[1] || f.description).trim();
    const accessible = d.found.filter(f => f.accessible);
    const others     = d.found.filter(f => !f.accessible);

    if (accessible.length) {
        html += `<div class="subsection-label" style="color:#ff5533">🔴 ${lang === 'es' ? 'Accesibles públicamente' : 'Publicly accessible'} (${accessible.length})</div>`;
        accessible.forEach(f => {
            html += `<div class="path-card pc-${f.severity}">
                <div class="path-card-status pcs-${f.status_code}">${f.status_code}</div>
                <div class="path-card-body"><div class="path-card-url">${f.path}</div><div class="path-card-label">${f.label}</div><div class="path-card-desc">${descFor(f)}</div></div>
                <div class="path-card-right"><span class="path-status-tag pst-${f.severity}">${sevLabel(f.severity)}</span><button class="path-copy-btn" onclick="copyText(${JSON.stringify(f.url)},this)">${lang === 'es' ? 'Copiar URL' : 'Copy URL'}</button></div>
            </div>`;
        });
    }
    if (others.length) {
        html += `<div class="subsection-label" style="margin-top:24px">🔒 ${lang === 'es' ? 'Existen pero bloqueadas' : 'Exist but blocked'} (${others.length})</div>`;
        others.forEach(f => {
            html += `<div class="path-card" style="opacity:.75">
                <div class="path-card-status pcs-${f.status_code}">${f.status_code}</div>
                <div class="path-card-body"><div class="path-card-url">${f.path}</div><div class="path-card-label">${f.label}</div></div>
                <div class="path-card-right"><span class="path-status-tag ${f.severity === 'high' ? 'pst-medium' : 'pst-info'}">${sevLabel(f.severity)}</span></div>
            </div>`;
        });
    }
    return html;
}

// ── SSL Audit ─────────────────────────────────────────────────────────────────

export function tmplSSLAudit(data, lang) {
    if (!data || data.error) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'Sin puertos HTTPS detectados' : 'No HTTPS ports detected'}</div>`;
    }
    const results = data.results || {};
    if (!Object.keys(results).length) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'Sin datos SSL' : 'No SSL data'}</div>`;
    }

    const gradeColor = { A: '#00ff88', B: '#44cc88', C: '#ffaa00', D: '#ff6600', F: '#ff0033' };
    let html = '';

    Object.entries(results).forEach(([port, ssl]) => {
        const gc = gradeColor[ssl.grade] || '#888';
        html += `<div style="background:#070707;border:1px solid #1e1e1e;border-radius:4px;padding:20px;margin-bottom:16px">
            <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px">
                <div style="width:52px;height:52px;border-radius:4px;border:1px solid ${gc}33;background:${gc}11;display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-size:1.6rem;font-weight:700;color:${gc}">${ssl.grade}</div>
                <div>
                    <div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:#f0f0f0">${ssl.hostname}:${port}</div>
                    <div style="font-family:var(--font-mono);font-size:11px;color:#888;margin-top:4px">${ssl.protocol || 'TLS'} · ${ssl.cipher || '—'} · ${ssl.bits || '?'} bits</div>
                </div>
            </div>`;

        if (ssl.error) {
            html += `<div style="color:#ff5544;font-family:var(--font-mono);font-size:12px">⚠ ${ssl.error}</div></div>`;
            return;
        }

        html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">`;
        const sub = ssl.subject || {};
        const iss = ssl.issuer  || {};
        [
            [lang === 'es' ? 'Emisor' : 'Issuer',           iss.organizationName || iss.commonName || '—'],
            [lang === 'es' ? 'Dominio (CN)' : 'Common Name', sub.commonName || '—'],
            ['Not Before', ssl.not_before ? ssl.not_before.slice(0, 10) : '—'],
            ['Not After',  ssl.not_after  ? ssl.not_after.slice(0, 10)  : '—'],
            [lang === 'es' ? 'Días restantes' : 'Days left', ssl.days_until_expiry !== null ? ssl.days_until_expiry + 'd' : '—'],
            [lang === 'es' ? 'Autofirmado' : 'Self-signed',  ssl.self_signed ? '⚠ Yes' : '✓ No'],
        ].forEach(([k, v]) => {
            const isWarn = (k.includes('restante') || k.includes('left')) && ssl.expiring_soon;
            const isErr  = (k.includes('restante') || k.includes('left')) && ssl.expired;
            const vc     = isErr ? '#ff3344' : isWarn ? '#ffaa00' : '#c0c0c0';
            html += `<div style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:3px;padding:10px 12px"><div style="font-family:var(--font-mono);font-size:9px;color:#555;letter-spacing:1px;text-transform:uppercase;margin-bottom:3px">${k}</div><div style="font-family:var(--font-mono);font-size:12px;color:${vc};word-break:break-all">${v}</div></div>`;
        });
        html += '</div>';

        if (ssl.sans?.length) {
            html += `<div style="margin-bottom:12px"><div style="font-family:var(--font-mono);font-size:9px;color:#555;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">Subject Alternative Names (${ssl.sans.length})</div><div style="display:flex;flex-wrap:wrap;gap:5px">${ssl.sans.slice(0, 8).map(s => `<span style="font-family:var(--font-mono);font-size:11px;color:#8899ff;background:rgba(100,100,255,.08);border:1px solid rgba(100,100,255,.15);padding:2px 8px;border-radius:3px">${s}</span>`).join('')}${ssl.sans.length > 8 ? `<span style="color:#555;font-size:11px;font-family:var(--font-mono)">+${ssl.sans.length - 8} more</span>` : ''}</div></div>`;
        }
        if (ssl.issues?.length) {
            html += `<div style="background:rgba(255,0,51,.04);border:1px solid rgba(255,0,51,.15);border-radius:3px;padding:10px 14px">${ssl.issues.map(i => `<div style="font-family:var(--font-mono);font-size:11px;color:#ff5544;margin-bottom:3px">⚠ ${i}</div>`).join('')}</div>`;
        } else {
            html += `<div style="color:#00cc66;font-family:var(--font-mono);font-size:11px">✓ ${lang === 'es' ? 'Sin problemas detectados' : 'No issues detected'}</div>`;
        }
        html += '</div>';
    });
    return html;
}

// ── CVE Audit ─────────────────────────────────────────────────────────────────

export function tmplCVEAudit(results, versionsPayload, lang) {
    const ports = Object.keys(results);
    if (!ports.length) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se encontraron CVEs conocidos para los servicios detectados' : 'No known CVEs found for detected services'}</div>`;
    }

    const sevColor = { CRITICAL: '#ff0033', HIGH: '#ff4444', MEDIUM: '#ffaa00', LOW: '#00cc66', NONE: '#555' };
    const sevLabel = { CRITICAL: 'CRÍTICO', HIGH: 'ALTO', MEDIUM: 'MEDIO', LOW: 'BAJO', NONE: 'NINGUNO' };
    let totalCVEs = 0;

    let html = `<div style="font-family:var(--font-mono);font-size:11px;color:#555;margin-bottom:16px;padding:10px 14px;background:#070707;border:1px solid #161616;border-radius:3px">${lang === 'es' ? 'Fuente: NVD (nvd.nist.gov) · Ejecuta Fingerprinting primero para resultados precisos.' : 'Source: NVD (nvd.nist.gov) · Run Fingerprinting first for precise results.'}</div>`;

    ports.forEach(port => {
        const r       = results[port];
        const meta    = versionsPayload[port] || {};
        const cves    = r.cves || [];
        totalCVEs    += cves.length;
        const keyword = r.keyword_used || `${meta.name} ${meta.version || ''}`.trim();
        const totalLbl = lang === 'es' ? 'CVEs totales' : 'total CVEs';

        html += `<div style="background:#070707;border:1px solid #1e1e1e;border-radius:4px;padding:16px;margin-bottom:12px">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
                <span style="font-family:var(--font-mono);font-size:13px;color:#f0f0f0;font-weight:700">${lang === 'es' ? 'Puerto' : 'Port'} ${port} — ${meta.name || '?'}</span>
                ${meta.version ? `<span style="font-family:var(--font-mono);font-size:11px;color:#8899ff;background:rgba(100,100,255,.08);padding:2px 8px;border-radius:3px;border:1px solid rgba(100,100,255,.15)">${meta.version}</span>` : ''}
                <span style="font-family:var(--font-mono);font-size:10px;color:#555;margin-left:auto">${lang === 'es' ? 'Búsqueda' : 'Search'}: "${keyword}" · ${r.total || 0} ${totalLbl}</span>
            </div>`;

        if (r.error) {
            html += `<div style="color:#ff8866;font-family:var(--font-mono);font-size:11px">⚠ ${r.error}</div></div>`;
            return;
        }
        if (!cves.length) {
            html += `<div style="color:#555;font-family:var(--font-mono);font-size:11px">${lang === 'es' ? 'Sin CVEs encontrados' : 'No CVEs found'}</div></div>`;
            return;
        }

        cves.forEach(cve => {
            const sc = sevColor[cve.severity] || '#555';
            const sl = lang === 'es' ? (sevLabel[cve.severity] || cve.severity) : cve.severity;
            html += `<div style="background:#0a0a0a;border:1px solid #1a1a1a;border-left:3px solid ${sc};border-radius:3px;padding:12px 14px;margin-bottom:7px">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap">
                    <a href="${cve.nvd_url}" target="_blank" style="font-family:var(--font-mono);font-size:12px;color:#8899ff;font-weight:700;text-decoration:none">${cve.id}</a>
                    ${cve.cvss_score !== null ? `<span style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:${sc}">CVSS ${cve.cvss_score} — ${sl}</span>` : ''}
                    <span style="font-family:var(--font-mono);font-size:10px;color:#555;margin-left:auto">${cve.published}</span>
                </div>
                <div style="font-size:12px;color:#bbb;line-height:1.6">${cve.description}</div>
            </div>`;
        });
        html += '</div>';
    });

    return { html, totalCVEs };
}

// ── CVE placeholder (before user launches lookup) ─────────────────────────────

export function tmplCVEPlaceholder(lang, openPortsCount) {
    return `<div class="no-results" style="padding:36px 24px">[ 🐛 ]<br>
        <span style="display:block;margin:12px 0 20px;font-size:12px">${lang === 'es' ? 'Ejecuta <b style=color:#aaa>Fingerprinting</b> para resultados precisos, o lanza el análisis ahora.' : 'Run <b style=color:#aaa>Fingerprinting</b> for precise results, or launch analysis now.'}</span>
        <button id="btn-launch-cve" onclick="window.launchCVELookup && window.launchCVELookup()" style="padding:8px 22px;background:transparent;border:1px solid #333;border-radius:4px;color:#888;font-family:var(--font-mono);font-size:11px;cursor:pointer;letter-spacing:.8px;transition:all .2s" onmouseover="this.style.borderColor='#ff0033';this.style.color='#ff0033'" onmouseout="this.style.borderColor='#333';this.style.color='#888'">
            🐛 ${lang === 'es' ? 'Buscar CVEs ahora' : 'Search CVEs now'}
        </button></div>`;
}

// ── CVE loading placeholder ────────────────────────────────────────────────────

export function tmplCVELoading(lang, openPortsCount) {
    const est = Math.ceil(openPortsCount * 6.5);
    return `<div class="audit-loading"><span class="spinner"></span><span class="es">Buscando CVEs conocidos... (puede tardar ~${est}s por límite de NVD)</span><span class="en">Searching CVEs... (~${est}s due to NVD rate limit)</span></div>`;
}

// ── Discover output ───────────────────────────────────────────────────────────

export function tmplDiscoverOutput(data, cidr, lang) {
    if (!data.alive?.length) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se encontraron hosts activos' : 'No live hosts found'} en ${cidr}</div>`;
    }

    const hostCards = data.alive.map(h => `
        <div style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:#0a0a0a;border:1px solid rgba(0,255,136,.15);border-radius:4px;cursor:pointer;transition:border-color .15s"
             onclick="document.getElementById('target').value='${h.ip}';document.getElementById('target').dispatchEvent(new Event('input'));"
             title="${lang === 'es' ? 'Clic para escanear' : 'Click to scan'}">
            <span style="width:7px;height:7px;border-radius:50%;background:#00ff88;box-shadow:0 0 4px #00ff88;flex-shrink:0"></span>
            <span style="font-family:var(--font-mono);font-size:13px;color:#00cc66;font-weight:600">${h.ip}</span>
            ${h.rtt_ms !== null ? `<span style="font-family:var(--font-mono);font-size:10px;color:#555">${h.rtt_ms} ms</span>` : ''}
        </div>`).join('');

    return `<div class="audit-stat-bar" style="margin-bottom:14px">
        <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">${lang === 'es' ? 'Hosts activos' : 'Live hosts'}</span><span class="asb-num" style="color:#00ff88">${data.alive_count}</span></div>
        <div class="asb-item" style="margin-left:auto"><span class="asb-label">${lang === 'es' ? 'Rango' : 'Range'}</span><span class="asb-num" style="color:#888">${data.total_hosts}</span></div>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:6px">${hostCards}</div>`;
}

// ── Subdomains output ─────────────────────────────────────────────────────────

export function tmplSubdomainsOutput(data, domain, lang) {
    if (!data.subdomains?.length) {
        return `<div class="no-results">[ _ ]<br>${lang === 'es' ? 'No se encontraron subdominios' : 'No subdomains found'} para ${domain}</div>`;
    }

    const rows = data.subdomains.map(s => `
        <tr>
            <td class="col-service">${s.subdomain}</td>
            <td style="font-family:var(--font-mono);font-size:11px;color:${s.resolves ? '#00cc66' : '#555'}">${s.ip || (s.resolves === false ? '✗ NXDOMAIN' : '—')}</td>
            <td style="font-family:var(--font-mono);font-size:10px;color:#666">${s.not_after || '—'}</td>
            <td><button class="btn-export" style="padding:3px 9px;font-size:10px" onclick="document.getElementById('target').value='${s.subdomain}';">→ ${lang === 'es' ? 'Escanear' : 'Scan'}</button></td>
        </tr>`).join('');

    return `<div class="audit-stat-bar" style="margin-bottom:14px">
        <div class="asb-item"><div class="asb-dot" style="background:#8899ff"></div><span class="asb-label">${lang === 'es' ? 'Subdominios encontrados' : 'Subdomains found'}</span><span class="asb-num" style="color:#8899ff">${data.total}</span></div>
        <div class="asb-item"><div class="asb-dot" style="background:#00ff88"></div><span class="asb-label">${lang === 'es' ? 'Resueltos' : 'Resolved'}</span><span class="asb-num" style="color:#00ff88">${data.subdomains.filter(s => s.resolves).length}</span></div>
    </div>
    <div class="table-wrap" style="max-height:320px">
        <table>
            <thead><tr>
                <th>${lang === 'es' ? 'Subdominio' : 'Subdomain'}</th>
                <th>IP</th>
                <th>${lang === 'es' ? 'Cert válido hasta' : 'Cert expiry'}</th>
                <th></th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>
    </div>`;
}

// ── HTML Report (exportHTMLReport) ────────────────────────────────────────────

export function tmplHTMLReport({ meta, results, counts, auditData, geoData, versions, getRisk }) {
    const ts    = new Date().toLocaleString();
    const rc    = { high: '#ff0033', medium: '#ffaa00', low: '#00ff88', info: '#444' };
    const rl2   = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: '—' };
    const geo   = geoData || {};

    const rows = results.map(r => {
        const sc  = r.state === 'open' ? '#00ff88' : r.state === 'filtered' ? '#ffaa00' : '#ff4444';
        const rk  = getRisk(r.port);
        const ver = versions[r.port]?.version || '';
        return `<tr><td>${r.port}</td><td style="color:${sc}">● ${r.state.charAt(0).toUpperCase() + r.state.slice(1)}</td><td>${r.service}</td><td style="color:${rc[rk]};font-size:10px">${rl2[rk]}</td><td>${r.response_time_ms ?? '—'} ms</td><td style="font-size:10px;color:#666;max-width:160px;overflow:hidden">${ver}</td></tr>`;
    }).join('');

    const geoHtml = geo.country
        ? `<tr><td style="color:#444;width:160px">Location</td><td>${geo.city || ''} · ${geo.country || ''} · ${geo.asn || ''}</td></tr><tr><td style="color:#444">ISP</td><td>${geo.isp || '—'}</td></tr>`
        : '';

    let auditHtml = '';
    if (auditData) {
        const hd = auditData.headers;
        if (hd && !hd.error) {
            auditHtml += `<h2>HTTP Security Headers — Grade: <span style="color:${GRADE_COLOR[hd.grade] || '#888'}">${hd.grade}</span> (${hd.score}/100)</h2>${hd.missing?.length ? '<p style="color:#ff0033;margin-bottom:6px">Missing: ' + hd.missing.map(h => `<code>${h.header}</code>`).join(', ') + '</p>' : ''}`;
        }
        const td = auditData.technologies;
        if (td && td.technologies?.length) {
            auditHtml += `<h2>Detected Technologies (${td.count})</h2><p>${td.technologies.map(t => `${t.icon} ${t.name}`).join(' · ')}</p>`;
        }
        const pd = auditData.paths;
        if (pd && pd.found?.length) {
            auditHtml += `<h2>Sensitive Paths (${pd.total_found} found)</h2><table><thead><tr><th>Path</th><th>Status</th><th>Severity</th></tr></thead><tbody>${pd.found.map(f => `<tr><td>${f.path}</td><td>${f.status_code}</td><td style="color:${rc[f.severity] || '#888'}">${f.severity.toUpperCase()}</td></tr>`).join('')}</tbody></table>`;
        }
    }

    return `<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>LukitaPort Report</title><link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@400;700&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#050505;color:#f0f0f0;font-family:'Inter',sans-serif;font-size:13px;padding:40px;line-height:1.6}h1{font-size:1.8rem;color:#ff0033;margin-bottom:4px;font-family:'IBM Plex Mono',monospace}.sub{color:#555;font-size:11px;letter-spacing:1.5px;margin-bottom:32px;font-family:'IBM Plex Mono',monospace}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:#1a1a1a;margin-bottom:28px;border-radius:4px;overflow:hidden}.card{background:#0d0d0d;padding:20px;text-align:center}.card .n{font-size:2.2rem;font-weight:700;line-height:1;margin-bottom:5px;font-family:'IBM Plex Mono',monospace}.card .l{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#333}h2{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#444;margin:28px 0 12px;border-bottom:1px solid #111;padding-bottom:8px;font-family:'IBM Plex Mono',monospace}table{width:100%;border-collapse:collapse}th{text-align:left;padding:9px 14px;font-size:10px;letter-spacing:1.2px;text-transform:uppercase;color:#333;border-bottom:1px solid #111;font-weight:600;font-family:'IBM Plex Mono',monospace}td{padding:10px 14px;border-bottom:1px solid rgba(20,20,20,.9);font-family:'IBM Plex Mono',monospace;font-size:12px}code{background:#111;padding:1px 6px;border-radius:2px;color:#ffaa00;font-family:'IBM Plex Mono',monospace}p{color:#888;font-size:12px;margin-bottom:12px}footer{margin-top:40px;color:#333;font-size:11px;text-align:center;border-top:1px solid #111;padding-top:18px;font-family:'IBM Plex Mono',monospace}</style></head><body><h1>LukitaPort</h1><div class="sub">PORT SCAN REPORT · ${ts}</div><div class="grid"><div class="card"><div class="n" style="color:#00ff88">${counts.open}</div><div class="l">Open</div></div><div class="card"><div class="n" style="color:#ff4444">${counts.closed}</div><div class="l">Closed</div></div><div class="card"><div class="n" style="color:#ffaa00">${counts.filtered}</div><div class="l">Filtered</div></div><div class="card"><div class="n" style="color:#ff0033">${results.length}</div><div class="l">Total</div></div></div><h2>Scan Metadata</h2><table><tr><td style="color:#444;width:160px">Target</td><td>${meta.input ?? '—'}</td></tr><tr><td style="color:#444">Resolved IP</td><td>${meta.ip ?? '—'}</td></tr><tr><td style="color:#444">Hostname</td><td>${meta.hostname ?? '—'}</td></tr><tr><td style="color:#444">Mode</td><td>${meta.mode ?? '—'}</td></tr><tr><td style="color:#444">Profile</td><td>${meta.profile ?? 'normal'}</td></tr>${geoHtml}<tr><td style="color:#444">Generated</td><td>${ts}</td></tr></table><h2>All Results</h2><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Risk</th><th>Response</th><th>Version</th></tr></thead><tbody>${rows}</tbody></table>${auditHtml}<footer>LukitaPort · jaimefg1888 · For educational use only</footer></body></html>`;
}
