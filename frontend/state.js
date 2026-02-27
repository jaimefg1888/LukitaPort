// state.js — LukitaPort v2.0
// Single source of truth — imported by all other modules.

export const state = {
    results:     [],    // [{port, state, service, ...}]
    scanMeta:    null,  // meta event from SSE
    scanning:    false,
    filter:      'all',
    counts:      { open: 0, closed: 0, filtered: 0 },
    eventSource: null,
    lang:        'es',
    auditData:   null,
    versions:    {},    // {port: {version, source, cpe}}
    geoData:     null,  // GeoIP enrichment
};

export const PORT_RISK = {
    21:'high', 23:'high', 25:'high', 110:'high', 139:'high', 445:'high',
    1433:'high', 1521:'high', 3306:'high', 3389:'high', 5432:'high',
    5900:'high', 6379:'high', 27017:'high', 1723:'high',
    22:'medium', 53:'medium', 111:'medium', 135:'medium', 143:'medium',
    8080:'medium', 8888:'medium', 9200:'medium',
    80:'low', 443:'low', 465:'low', 587:'low', 993:'low', 995:'low', 8443:'low',
};

export const RISK_LABELS = {
    es: { high: 'Alto riesgo', medium: 'Riesgo medio', low: 'Bajo riesgo', info: '—' },
    en: { high: 'High risk',   medium: 'Medium risk',  low: 'Low risk',    info: '—' },
};

export const getRisk = p => PORT_RISK[p] || 'info';
