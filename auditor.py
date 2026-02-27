import re
import asyncio
from typing import Optional
import httpx


def _make_client(timeout: float = 6.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0 (LukitaPort Security Audit)"},
        limits=httpx.Limits(max_connections=40, max_keepalive_connections=10),
    )


async def _fetch_async(client: httpx.AsyncClient, url: str, timeout: float = 6.0) -> Optional[tuple[int, dict, str]]:
    try:
        resp = await client.get(url, timeout=timeout)
        return resp.status_code, dict(resp.headers), resp.text[:200_000]
    except httpx.HTTPStatusError as e:
        return e.response.status_code, dict(e.response.headers), e.response.text[:16_384]
    except Exception:
        return None


def _choose_base_url(target: str, open_ports: list) -> str:
    if 443 in open_ports or 8443 in open_ports:
        return f"https://{target}"
    if 80 in open_ports or 8080 in open_ports:
        return f"http://{target}"
    return f"https://{target}"


async def _prefetch(target: str, open_ports: list, client: httpx.AsyncClient) -> tuple[str, Optional[tuple[int, dict, str]]]:
    base_url = _choose_base_url(target, open_ports)
    result   = await _fetch_async(client, base_url)
    if result is None and base_url.startswith("https://"):
        base_url = f"http://{target}"
        result   = await _fetch_async(client, base_url)
    return base_url, result


# ─── HTTP Security Headers ─────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "label": "HSTS",
        "description_es": "Obliga a usar HTTPS. Previene ataques de downgrade y cookies robadas.",
        "description_en": "Forces HTTPS. Prevents downgrade attacks and cookie theft.",
        "severity": "high",
        "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "label": "CSP",
        "description_es": "Limita las fuentes de scripts y recursos. Mitiga XSS.",
        "description_en": "Restricts script/resource sources. Mitigates XSS.",
        "severity": "high",
        "example": "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Frame-Options": {
        "label": "X-Frame-Options",
        "description_es": "Previene que la página sea cargada en un iframe (clickjacking).",
        "description_en": "Prevents the page from being loaded in an iframe (clickjacking).",
        "severity": "medium",
        "example": "X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "label": "X-Content-Type-Options",
        "description_es": "Evita que el navegador interprete el contenido con un MIME diferente.",
        "description_en": "Prevents MIME type sniffing.",
        "severity": "medium",
        "example": "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "label": "Referrer-Policy",
        "description_es": "Controla qué información del referer se envía en las peticiones.",
        "description_en": "Controls how much referrer info is sent with requests.",
        "severity": "low",
        "example": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "label": "Permissions-Policy",
        "description_es": "Controla el acceso a APIs del navegador (cámara, micrófono, geolocalización).",
        "description_en": "Controls access to browser APIs (camera, mic, geolocation).",
        "severity": "low",
        "example": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "label": "X-XSS-Protection",
        "description_es": "Filtro XSS del navegador (legacy, pero sigue siendo buena práctica).",
        "description_en": "Browser XSS filter (legacy, but still good practice).",
        "severity": "low",
        "example": "X-XSS-Protection: 1; mode=block",
    },
}

DANGEROUS_HEADERS = {
    "Server":               "Reveals server software and version.",
    "X-Powered-By":         "Reveals backend language/framework.",
    "X-AspNet-Version":     "Reveals ASP.NET version.",
    "X-AspNetMvc-Version":  "Reveals ASP.NET MVC version.",
}


def _audit_headers_from_prefetch(base_url: str, prefetch: Optional[tuple[int, dict, str]]) -> dict:
    if prefetch is None:
        return {"error": "Could not connect", "url": base_url, "present": [], "missing": [], "dangerous": [], "score": 0}

    status, headers, _ = prefetch
    headers_norm = {k.title(): v for k, v in headers.items()}

    present, missing = [], []
    for header, info in SECURITY_HEADERS.items():
        entry = {
            "header": header, "label": info["label"],
            "description_es": info["description_es"], "description_en": info["description_en"],
            "severity": info["severity"], "example": info.get("example", ""),
        }
        if header.title() in headers_norm:
            entry["value"]  = headers_norm[header.title()]
            entry["status"] = "present"
            present.append(entry)
        else:
            entry["status"] = "missing"
            missing.append(entry)

    dangerous = [
        {"header": h, "value": headers_norm[h.title()], "description": desc}
        for h, desc in DANGEROUS_HEADERS.items()
        if h.title() in headers_norm
    ]

    high_p = sum(1 for h in present if h["severity"] == "high")
    med_p  = sum(1 for h in present if h["severity"] == "medium")
    low_p  = sum(1 for h in present if h["severity"] == "low")
    score  = max(0, min(100, high_p * 30 + med_p * 20 + low_p * 10 - len(dangerous) * 5))
    grade  = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"

    return {
        "url": base_url, "status_code": status,
        "present": present, "missing": missing, "dangerous": dangerous,
        "score": score, "grade": grade,
    }


# ─── Technology Detection ──────────────────────────────────────────────────────

TECH_PATTERNS = {
    "WordPress":            {"body": [r"wp-content/", r"wp-includes/", r"/wp-json/", r"wordpress"], "headers": {"X-Pingback": r"xmlrpc\.php"}, "icon": "📝", "category": "CMS"},
    "Joomla":               {"body": [r"/components/com_", r"Joomla!", r"/media/jui/"], "icon": "📝", "category": "CMS"},
    "Drupal":               {"body": [r"Drupal\.settings", r"/sites/default/files/", r"drupal\.js"], "headers": {"X-Generator": r"Drupal"}, "icon": "📝", "category": "CMS"},
    "Shopify":              {"body": [r"cdn\.shopify\.com", r"shopify\.com/s/files"], "headers": {"X-Shopify-Stage": r"."}, "icon": "🛍", "category": "E-Commerce"},
    "WooCommerce":          {"body": [r"woocommerce", r"wc-", r"/wc-api/"], "icon": "🛍", "category": "E-Commerce"},
    "Magento":              {"body": [r"Mage\.", r"mage/", r"skin/frontend/"], "icon": "🛍", "category": "E-Commerce"},
    "PrestaShop":           {"body": [r"prestashop", r"/modules/blockcart/"], "headers": {"X-Powered-By": r"PrestaShop"}, "icon": "🛍", "category": "E-Commerce"},
    "React":                {"body": [r"react\.production\.min\.js", r"__REACT_DEVTOOLS", r"data-reactroot"], "icon": "⚛️", "category": "JavaScript Framework"},
    "Vue.js":               {"body": [r"vue\.min\.js", r"vue\.js", r"__vue__", r"data-v-"], "icon": "💚", "category": "JavaScript Framework"},
    "Angular":              {"body": [r"angular\.min\.js", r"ng-version=", r"ng-app="], "icon": "🔴", "category": "JavaScript Framework"},
    "Next.js":              {"body": [r"__NEXT_DATA__", r"/_next/static/"], "icon": "▲", "category": "JavaScript Framework"},
    "Nuxt.js":              {"body": [r"__nuxt", r"_nuxt/", r"nuxt\.js"], "icon": "💚", "category": "JavaScript Framework"},
    "jQuery":               {"body": [r"jquery\.min\.js", r"jquery-[0-9]"], "icon": "🔵", "category": "JavaScript Library"},
    "Bootstrap":            {"body": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"], "icon": "🅱", "category": "CSS Framework"},
    "Tailwind CSS":         {"body": [r"tailwind\.css", r"tailwindcss"], "icon": "🌊", "category": "CSS Framework"},
    "Apache":               {"headers": {"Server": r"Apache"}, "icon": "🪶", "category": "Web Server"},
    "Nginx":                {"headers": {"Server": r"nginx"}, "icon": "🟩", "category": "Web Server"},
    "IIS":                  {"headers": {"Server": r"IIS"}, "icon": "🪟", "category": "Web Server"},
    "Cloudflare":           {"headers": {"Server": r"cloudflare", "CF-Ray": r"."}, "icon": "🌐", "category": "CDN / WAF"},
    "PHP":                  {"headers": {"X-Powered-By": r"PHP"}, "body": [r"\.php\b"], "icon": "🐘", "category": "Backend Language"},
    "Python / Django":      {"headers": {"Server": r"WSGIServer|gunicorn|Django"}, "body": [r"csrfmiddlewaretoken"], "icon": "🐍", "category": "Backend Framework"},
    "Laravel":              {"body": [r"laravel_session", r"Laravel"], "headers": {"Set-Cookie": r"laravel_session"}, "icon": "🔴", "category": "Backend Framework"},
    "Ruby on Rails":        {"headers": {"Server": r"Passenger"}, "body": [r"rails", r"ActionController"], "icon": "💎", "category": "Backend Framework"},
    "ASP.NET":              {"headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r"."}, "body": [r"__VIEWSTATE"], "icon": "🪟", "category": "Backend Framework"},
    "Node.js / Express":    {"headers": {"X-Powered-By": r"Express"}, "icon": "🟩", "category": "Backend Framework"},
    "Google Analytics":     {"body": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d+-\d+", r"G-[A-Z0-9]+"], "icon": "📊", "category": "Analytics"},
    "Google Tag Manager":   {"body": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"], "icon": "🏷", "category": "Analytics"},
    "Hotjar":               {"body": [r"hotjar\.com"], "icon": "🔥", "category": "Analytics"},
    "Matomo":               {"body": [r"matomo\.js", r"piwik\.js"], "icon": "📊", "category": "Analytics"},
    "Zendesk":              {"body": [r"zopim\.com", r"zendesk\.com"], "icon": "💬", "category": "Chat"},
    "Tawk.to":              {"body": [r"tawk\.to"], "icon": "💬", "category": "Chat"},
    "HubSpot":              {"body": [r"hubspot\.com", r"hs-scripts\.com"], "icon": "🟠", "category": "Marketing"},
    "AWS WAF / CloudFront": {
        "headers": {"X-Amz-Cf-Id": r".", "X-Amzn-Requestid": r".", "X-Amz-Waf-Action": r".", "X-Cache": r"CloudFront"},
        "body": [r"AmazonWAF", r"Request blocked by AWS WAF"],
        "icon": "🛡", "category": "WAF",
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": r".", "X-Akamai-Session-Id": r".", "X-Check-Cacheable": r".", "X-True-Cache-Key": r".", "Akamai-Cache-Status": r"."},
        "body": [r"akamai\.net", r"Reference\s#\d+\.\d+\.\d+"],
        "icon": "🛡", "category": "WAF",
    },
    "Imperva / Incapsula": {
        "headers": {"X-Iinfo": r".", "X-Cdn": r"[Ii]mperva|[Ii]ncapsula", "X-Incap-Ses": r".", "Set-Cookie": r"incap_ses|visid_incap"},
        "body": [r"incapsula incident id", r"Powered by Incapsula"],
        "icon": "🛡", "category": "WAF",
    },
    "Sucuri": {
        "headers": {"X-Sucuri-Id": r".", "X-Sucuri-Cache": r".", "Server": r"Sucuri/Cloudproxy"},
        "body": [r"sucuri\.net", r"Access Denied - Sucuri Website Firewall"],
        "icon": "🛡", "category": "WAF",
    },
    "ModSecurity": {
        "body": [r"Mod_Security|mod_security|NOYB"], "headers": {"Server": r"[Mm]od.?[Ss]ecurity"},
        "icon": "🛡", "category": "WAF",
    },
    "F5 BIG-IP ASM": {
        "headers": {"Set-Cookie": r"BIGipServer|TS[0-9a-f]{8}", "Server": r"BigIP|BIG-IP"},
        "body": [r"The requested URL was rejected"],
        "icon": "🛡", "category": "WAF",
    },
}


async def _detect_technologies_from_prefetch(base_url: str, prefetch: Optional[tuple[int, dict, str]], client: httpx.AsyncClient) -> dict:
    if prefetch is None:
        return {"error": "Could not connect", "url": base_url, "technologies": []}

    status, headers, body = prefetch

    extra_body = ""
    for extra in ["/wp-json/wp/v2/", "/feed/", "/wp-login.php"]:
        r = await _fetch_async(client, base_url.rstrip("/") + extra, timeout=3.0)
        if r and r[0] in (200, 301, 302):
            extra_body += r[2]
            break

    full_body    = body + extra_body
    headers_norm = {k.lower(): v for k, v in headers.items()}

    gen_match = (
        re.search(r'<meta[^>]+name=["\'`]generator["\'`][^>]+content=["\'`]([^"\'`]+)["\'`]', full_body, re.IGNORECASE)
        or re.search(r'<meta[^>]+content=["\'`]([^"\'`]+)["\'`][^>]+name=["\'`]generator["\'`]', full_body, re.IGNORECASE)
    )
    generator = gen_match.group(1) if gen_match else ""

    detected, detected_names = [], set()

    if generator:
        gen_lower = generator.lower()
        ver_m = re.search(r'\d[\d.]*', generator)
        ver   = ver_m.group() if ver_m else ""
        for cms in ("wordpress", "joomla", "drupal"):
            if cms in gen_lower:
                detected.append({"name": cms.capitalize(), "icon": "📝", "category": "CMS", "version": ver})
                detected_names.add(cms.capitalize())
                break

    for name, pats in TECH_PATTERNS.items():
        if name in detected_names:
            continue
        found = any(re.search(p, full_body, re.IGNORECASE) for p in pats.get("body", []))
        if not found:
            found = any(
                (hv := headers_norm.get(hk.lower(), "")) and re.search(hp, hv, re.IGNORECASE)
                for hk, hp in pats.get("headers", {}).items()
            )
        if found:
            detected.append({"name": name, "icon": pats.get("icon", "⚙️"), "category": pats.get("category", "Other")})
            detected_names.add(name)

    categories: dict[str, list] = {}
    for t in detected:
        categories.setdefault(t["category"], []).append(t)

    return {
        "url": base_url, "status_code": status,
        "technologies": detected, "by_category": categories,
        "count": len(detected), "generator": generator,
    }


# ─── Sensitive Path Scanner ────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    ("/robots.txt",        "Robots.txt",          "info",   "Puede revelar rutas ocultas / Can reveal hidden paths"),
    ("/sitemap.xml",       "Sitemap",              "info",   "Mapa del sitio / Site structure map"),
    ("/.git/HEAD",         ".git expuesto",        "high",   "Repositorio Git accesible públicamente / Git repo exposed"),
    ("/.env",              ".env expuesto",        "high",   "Variables de entorno expuestas / Env vars exposed"),
    ("/config.php",        "config.php",           "high",   "Fichero de configuración / Config file"),
    ("/configuration.php", "configuration.php",    "high",   "Configuración Joomla / Joomla config"),
    ("/wp-config.php",     "wp-config.php",        "high",   "Configuración WordPress / WordPress config"),
    ("/phpinfo.php",       "phpinfo()",            "high",   "Información del servidor PHP / PHP server info"),
    ("/info.php",          "info.php",             "high",   "Información del servidor / Server info"),
    ("/wp-admin/",         "WordPress Admin",      "medium", "Panel de administración WordPress / WordPress admin panel"),
    ("/admin/",            "Admin Panel",          "medium", "Panel de administración genérico / Generic admin panel"),
    ("/administrator/",    "Joomla Admin",         "medium", "Panel de administración Joomla / Joomla admin panel"),
    ("/login",             "Login",                "info",   "Página de inicio de sesión / Login page"),
    ("/dashboard",         "Dashboard",            "info",   "Dashboard / Dashboard"),
    ("/phpmyadmin/",       "phpMyAdmin",           "high",   "Interfaz de base de datos expuesta / DB interface exposed"),
    ("/pma/",              "phpMyAdmin (pma)",     "high",   "Interfaz phpMyAdmin alternativa / Alt phpMyAdmin"),
    ("/api/",              "API Root",             "info",   "Raíz de API / API root endpoint"),
    ("/swagger-ui.html",   "Swagger UI",           "medium", "Documentación de API expuesta / API docs exposed"),
    ("/swagger/",          "Swagger",              "medium", "Documentación de API / API documentation"),
    ("/api/docs",          "API Docs",             "medium", "Documentación de API / API documentation"),
    ("/graphql",           "GraphQL",              "medium", "Endpoint GraphQL expuesto / GraphQL endpoint"),
    ("/debug",             "Debug endpoint",       "high",   "Endpoint de debug / Debug endpoint"),
    ("/console",           "Console",              "high",   "Consola de administración / Admin console"),
    ("/backup/",           "Backup dir",           "high",   "Directorio de backups / Backup directory"),
    ("/logs/",             "Logs dir",             "high",   "Directorio de logs / Logs directory"),
    ("/error_log",         "Error log",            "medium", "Registro de errores / Error log"),
    ("/.htaccess",         ".htaccess",            "medium", "Configuración Apache / Apache config"),
    ("/web.config",        "web.config",           "high",   "Configuración IIS / IIS config"),
    ("/server-status",     "Apache Status",        "medium", "Estado del servidor Apache / Apache server status"),
    ("/server-info",       "Apache Info",          "medium", "Información del servidor / Server info"),
]


async def _scan_sensitive_paths_async(base_url: str, client: httpx.AsyncClient, timeout: float = 4.0) -> dict:
    async def check_one(path_tuple: tuple) -> Optional[dict]:
        path, label, severity, description = path_tuple
        url = base_url.rstrip("/") + path
        try:
            resp = await client.get(url, timeout=timeout)
            code = resp.status_code
            if code in (200, 301, 302, 403):
                return {
                    "path": path, "label": label, "severity": severity,
                    "description": description, "status_code": code,
                    "content_type": resp.headers.get("content-type", ""),
                    "size_bytes": len(resp.content),
                    "url": str(resp.url),
                    "accessible": code == 200,
                }
        except Exception:
            pass
        return None

    raw = await asyncio.gather(*[asyncio.create_task(check_one(pt)) for pt in SENSITIVE_PATHS], return_exceptions=True)

    found, not_found, errors = [], 0, 0
    for r in raw:
        if isinstance(r, Exception): errors += 1
        elif r is None:              not_found += 1
        else:                        found.append(r)

    found.sort(key=lambda x: {"high": 0, "medium": 1, "info": 2}.get(x["severity"], 9))

    return {
        "base_url": base_url, "found": found, "not_found": not_found, "errors": errors,
        "high_count":   sum(1 for f in found if f["severity"] == "high"   and f["accessible"]),
        "medium_count": sum(1 for f in found if f["severity"] == "medium" and f["accessible"]),
        "total_found":  len(found),
    }


# ─── Public entry point ────────────────────────────────────────────────────────

async def run_full_audit(target: str, open_ports: list) -> dict:
    async with _make_client() as client:
        base_url, prefetch = await _prefetch(target, open_ports, client)
        headers_result = _audit_headers_from_prefetch(base_url, prefetch)
        tech_result, paths_result = await asyncio.gather(
            _detect_technologies_from_prefetch(base_url, prefetch, client),
            _scan_sensitive_paths_async(base_url, client),
        )

    return {"headers": headers_result, "technologies": tech_result, "paths": paths_result}
