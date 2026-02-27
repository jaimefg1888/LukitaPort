"""
auditor.py — LukitaPort
Módulo de auditoría avanzada:
  - Cabeceras de seguridad HTTP
  - Detección de tecnologías web (Wappalyzer-lite)
  - Rutas sensibles (OSINT pasivo)
"""

import re
import socket
import time
from typing import Optional
import urllib.request
import urllib.error
import ssl


# ─── helpers ──────────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: float = 5.0) -> Optional[tuple[int, dict, str]]:
    """Devuelve (status_code, headers_dict, body) o None en error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (LukitaPort/1.0 Security Audit)"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(16384).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body
    except Exception:
        return None


def _choose_base_url(target: str, open_ports: list) -> Optional[str]:
    """Devuelve la URL base más adecuada según los puertos abiertos."""
    if 443 in open_ports or 8443 in open_ports:
        return f"https://{target}"
    if 80 in open_ports or 8080 in open_ports:
        return f"http://{target}"
    # Intentar https de todos modos
    return f"https://{target}"


# ─── 1. Cabeceras de seguridad HTTP ──────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "label": "HSTS",
        "description_es": "Obliga a usar HTTPS. Previene ataques de downgrade y cookies robadas.",
        "description_en": "Forces HTTPS. Prevents downgrade attacks and cookie theft.",
        "severity": "high",
    },
    "Content-Security-Policy": {
        "label": "CSP",
        "description_es": "Limita las fuentes de scripts y recursos. Mitiga XSS.",
        "description_en": "Restricts script/resource sources. Mitigates XSS.",
        "severity": "high",
    },
    "X-Frame-Options": {
        "label": "X-Frame-Options",
        "description_es": "Previene que la página sea cargada en un iframe (clickjacking).",
        "description_en": "Prevents the page from being loaded in an iframe (clickjacking).",
        "severity": "medium",
    },
    "X-Content-Type-Options": {
        "label": "X-Content-Type-Options",
        "description_es": "Evita que el navegador interprete el contenido con un MIME diferente.",
        "description_en": "Prevents MIME type sniffing.",
        "severity": "medium",
    },
    "Referrer-Policy": {
        "label": "Referrer-Policy",
        "description_es": "Controla qué información del referer se envía en las peticiones.",
        "description_en": "Controls how much referrer info is sent with requests.",
        "severity": "low",
    },
    "Permissions-Policy": {
        "label": "Permissions-Policy",
        "description_es": "Controla el acceso a APIs del navegador (cámara, micrófono, geolocalización).",
        "description_en": "Controls access to browser APIs (camera, mic, geolocation).",
        "severity": "low",
    },
    "X-XSS-Protection": {
        "label": "X-XSS-Protection",
        "description_es": "Filtro XSS del navegador (legacy, pero sigue siendo buena práctica).",
        "description_en": "Browser XSS filter (legacy, but still good practice).",
        "severity": "low",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Revela el software del servidor y versión.",
    "X-Powered-By": "Revela el lenguaje/framework del backend.",
    "X-AspNet-Version": "Revela la versión de ASP.NET.",
    "X-AspNetMvc-Version": "Revela la versión de ASP.NET MVC.",
}


def audit_headers(target: str, open_ports: list) -> dict:
    base_url = _choose_base_url(target, open_ports)
    result = fetch_result = _fetch(base_url)

    # Si falla https, intentar http
    if result is None and base_url.startswith("https://"):
        base_url = f"http://{target}"
        result = _fetch(base_url)

    if result is None:
        return {"error": "Could not connect", "url": base_url, "present": [], "missing": [], "dangerous": [], "score": 0}

    status, headers, _ = result
    # Normalizar claves a title-case para comparación
    headers_norm = {k.title(): v for k, v in headers.items()}

    present = []
    missing = []

    for header, info in SECURITY_HEADERS.items():
        key = header.title()
        if key in headers_norm:
            present.append({
                "header": header,
                "value": headers_norm[key],
                "label": info["label"],
                "description_es": info["description_es"],
                "description_en": info["description_en"],
                "severity": info["severity"],
                "status": "present",
            })
        else:
            missing.append({
                "header": header,
                "label": info["label"],
                "description_es": info["description_es"],
                "description_en": info["description_en"],
                "severity": info["severity"],
                "status": "missing",
            })

    dangerous = []
    for header, desc in DANGEROUS_HEADERS.items():
        key = header.title()
        if key in headers_norm:
            dangerous.append({
                "header": header,
                "value": headers_norm[key],
                "description": desc,
            })

    # Score 0-100
    high_present = sum(1 for h in present if h["severity"] == "high")
    med_present  = sum(1 for h in present if h["severity"] == "medium")
    low_present  = sum(1 for h in present if h["severity"] == "low")
    score = min(100, (high_present * 30) + (med_present * 20) + (low_present * 10) - (len(dangerous) * 5))
    score = max(0, score)

    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"

    return {
        "url": base_url,
        "status_code": status,
        "present": present,
        "missing": missing,
        "dangerous": dangerous,
        "score": score,
        "grade": grade,
    }


# ─── 2. Detección de tecnologías web ─────────────────────────────────────────

TECH_PATTERNS = {
    # ── CMS ──────────────────────────────────────────────────────────────────
    "WordPress": {
        "body": [r"wp-content/", r"wp-includes/", r"/wp-json/", r"wordpress"],
        "headers": {"X-Pingback": r"xmlrpc\.php"},
        "icon": "📝", "category": "CMS",
    },
    "Joomla": {
        "body": [r"/components/com_", r"Joomla!", r"/media/jui/"],
        "icon": "📝", "category": "CMS",
    },
    "Drupal": {
        "body": [r"Drupal\.settings", r"/sites/default/files/", r"drupal\.js"],
        "headers": {"X-Generator": r"Drupal"},
        "icon": "📝", "category": "CMS",
    },
    "Magento": {
        "body": [r"Mage\.Cookies", r"/skin/frontend/", r"magento"],
        "icon": "📝", "category": "CMS",
    },
    "TYPO3": {
        "body": [r"typo3/", r"TYPO3"],
        "icon": "📝", "category": "CMS",
    },
    "Ghost": {
        "body": [r"ghost\.io", r"/ghost/api/"],
        "icon": "📝", "category": "CMS",
    },
    # ── E-commerce ───────────────────────────────────────────────────────────
    "Shopify": {
        "body": [r"cdn\.shopify\.com", r"Shopify\.theme", r"shopify"],
        "icon": "🛒", "category": "E-commerce",
    },
    "WooCommerce": {
        "body": [r"woocommerce", r"wc-api", r"wc_add_to_cart"],
        "icon": "🛒", "category": "E-commerce",
    },
    "PrestaShop": {
        "body": [r"prestashop", r"/modules/ps_"],
        "icon": "🛒", "category": "E-commerce",
    },
    "OpenCart": {
        "body": [r"route=common/home", r"opencart"],
        "icon": "🛒", "category": "E-commerce",
    },
    "BigCommerce": {
        "body": [r"bigcommerce\.com", r"stencil"],
        "icon": "🛒", "category": "E-commerce",
    },
    # ── JavaScript Frameworks ─────────────────────────────────────────────────
    "React": {
        "body": [r"react\.development\.js", r"react\.production\.min\.js", r"__react", r"data-reactroot", r"_reactFiber"],
        "icon": "⚛️", "category": "JavaScript Framework",
    },
    "Vue.js": {
        "body": [r"vue\.min\.js", r"vue\.js", r"__vue__", r"data-v-"],
        "icon": "💚", "category": "JavaScript Framework",
    },
    "Angular": {
        "body": [r"ng-version=", r"angular\.min\.js", r"ng-app", r"angular\.js"],
        "icon": "🅰️", "category": "JavaScript Framework",
    },
    "Next.js": {
        "body": [r"__NEXT_DATA__", r"/_next/static/"],
        "icon": "▲", "category": "JavaScript Framework",
    },
    "Nuxt.js": {
        "body": [r"__nuxt", r"/_nuxt/"],
        "icon": "💚", "category": "JavaScript Framework",
    },
    "Svelte": {
        "body": [r"__svelte", r"svelte-"],
        "icon": "🔥", "category": "JavaScript Framework",
    },
    "Ember.js": {
        "body": [r"ember\.min\.js", r"Ember\.VERSION"],
        "icon": "🐹", "category": "JavaScript Framework",
    },
    "Backbone.js": {
        "body": [r"backbone\.js", r"Backbone\.VERSION"],
        "icon": "🦴", "category": "JavaScript Framework",
    },
    # ── JavaScript Libraries ──────────────────────────────────────────────────
    "jQuery": {
        "body": [r"jquery\.min\.js", r"jquery-\d+\.\d+", r"jquery\.js"],
        "icon": "🔨", "category": "JavaScript Library",
    },
    "Lodash": {
        "body": [r"lodash\.min\.js", r"lodash\.js"],
        "icon": "🔨", "category": "JavaScript Library",
    },
    "Moment.js": {
        "body": [r"moment\.min\.js", r"moment\.js"],
        "icon": "⏰", "category": "JavaScript Library",
    },
    "Alpine.js": {
        "body": [r"x-data=", r"alpine\.js"],
        "icon": "🏔️", "category": "JavaScript Library",
    },
    "HTMX": {
        "body": [r"hx-get=", r"htmx\.min\.js", r"htmx\.org"],
        "icon": "⚡", "category": "JavaScript Library",
    },
    # ── CSS Frameworks ────────────────────────────────────────────────────────
    "Bootstrap": {
        "body": [r"bootstrap\.min\.css", r"bootstrap\.min\.js", r"bootstrap/\d"],
        "icon": "🎨", "category": "CSS Framework",
    },
    "Tailwind CSS": {
        "body": [r"tailwindcss", r"tailwind\.config", r"class=\".*\b(px-|py-|mx-|flex |grid |text-|bg-)"],
        "icon": "🎨", "category": "CSS Framework",
    },
    "Bulma": {
        "body": [r"bulma\.min\.css", r"bulma\.css"],
        "icon": "🎨", "category": "CSS Framework",
    },
    "Foundation": {
        "body": [r"foundation\.min\.css", r"foundation\.js"],
        "icon": "🎨", "category": "CSS Framework",
    },
    "Material UI": {
        "body": [r"MuiButton", r"makeStyles", r"@material-ui"],
        "icon": "🎨", "category": "CSS Framework",
    },
    # ── Web Servers ───────────────────────────────────────────────────────────
    "nginx": {
        "headers": {"Server": r"nginx"},
        "icon": "🔧", "category": "Web Server",
    },
    "Apache": {
        "headers": {"Server": r"Apache"},
        "icon": "🔧", "category": "Web Server",
    },
    "IIS": {
        "headers": {"Server": r"IIS|Microsoft-IIS"},
        "icon": "🔧", "category": "Web Server",
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"},
        "icon": "⚡", "category": "Web Server",
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
        "icon": "🔧", "category": "Web Server",
    },
    "Gunicorn": {
        "headers": {"Server": r"gunicorn"},
        "icon": "🦄", "category": "Web Server",
    },
    "Netlify": {
        "headers": {"X-Netlify-Cache-Tag": r".+", "Server": r"Netlify"},
        "icon": "☁️", "category": "Hosting",
    },
    "Vercel": {
        "headers": {"X-Vercel-Id": r".+", "Server": r"Vercel"},
        "icon": "▲", "category": "Hosting",
    },
    # ── CDN / Proxy ───────────────────────────────────────────────────────────
    "Cloudflare": {
        "headers": {"Server": r"cloudflare", "CF-RAY": r".+"},
        "icon": "☁️", "category": "CDN / Proxy",
    },
    "Fastly": {
        "headers": {"X-Served-By": r"cache-.+fastly", "X-Cache": r".+"},
        "icon": "☁️", "category": "CDN / Proxy",
    },
    "Akamai": {
        "headers": {"X-Check-Cacheable": r".+", "Server": r"AkamaiGHost"},
        "icon": "☁️", "category": "CDN / Proxy",
    },
    "AWS CloudFront": {
        "headers": {"X-Amz-Cf-Id": r".+", "Via": r"CloudFront"},
        "icon": "☁️", "category": "CDN / Proxy",
    },
    # ── Backend Languages ─────────────────────────────────────────────────────
    "PHP": {
        "headers": {"X-Powered-By": r"PHP"},
        "body": [r"\.php"],
        "icon": "🐘", "category": "Backend",
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".+"},
        "icon": "🔵", "category": "Backend",
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger"},
        "body": [r"csrf-token", r"rails"],
        "icon": "💎", "category": "Backend",
    },
    "Django": {
        "body": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
        "icon": "🐍", "category": "Backend",
    },
    "Laravel": {
        "body": [r"laravel_session", r"XSRF-TOKEN"],
        "headers": {"X-Powered-By": r"Laravel"},
        "icon": "🔴", "category": "Backend",
    },
    "Express.js": {
        "headers": {"X-Powered-By": r"Express"},
        "icon": "🟢", "category": "Backend",
    },
    "FastAPI": {
        "body": [r"FastAPI", r"openapi\.json"],
        "icon": "⚡", "category": "Backend",
    },
    "Spring": {
        "headers": {"X-Application-Context": r".+"},
        "body": [r"spring", r"Spring Framework"],
        "icon": "🍃", "category": "Backend",
    },
    # ── Analytics / Marketing ─────────────────────────────────────────────────
    "Google Analytics": {
        "body": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d{6,}-\d", r"G-[A-Z0-9]{8,}"],
        "icon": "📊", "category": "Analytics",
    },
    "Google Tag Manager": {
        "body": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
        "icon": "📊", "category": "Analytics",
    },
    "Matomo": {
        "body": [r"matomo\.js", r"piwik\.js"],
        "icon": "📊", "category": "Analytics",
    },
    "Hotjar": {
        "body": [r"hotjar\.com", r"hjid"],
        "icon": "🔥", "category": "Analytics",
    },
    "Plausible": {
        "body": [r"plausible\.io"],
        "icon": "📊", "category": "Analytics",
    },
    # ── Security / Auth ───────────────────────────────────────────────────────
    "Cloudflare Turnstile": {
        "body": [r"challenges\.cloudflare\.com/turnstile"],
        "icon": "🛡️", "category": "Security",
    },
    "reCAPTCHA": {
        "body": [r"recaptcha\.net", r"google\.com/recaptcha"],
        "icon": "🛡️", "category": "Security",
    },
    "hCaptcha": {
        "body": [r"hcaptcha\.com"],
        "icon": "🛡️", "category": "Security",
    },
    "Auth0": {
        "body": [r"auth0\.com", r"auth0\.js"],
        "icon": "🔐", "category": "Auth",
    },
    "Okta": {
        "body": [r"okta\.com", r"okta-signin"],
        "icon": "🔐", "category": "Auth",
    },
    # ── Fonts / UI ───────────────────────────────────────────────────────────
    "Font Awesome": {
        "body": [r"fontawesome", r"fa-solid", r"fa-brands"],
        "icon": "🔤", "category": "UI Library",
    },
    "Google Fonts": {
        "body": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"],
        "icon": "🔤", "category": "UI Library",
    },
    # ── Chat / Support ────────────────────────────────────────────────────────
    "Intercom": {
        "body": [r"intercomcdn\.com", r"intercom\.io"],
        "icon": "💬", "category": "Chat",
    },
    "Zendesk": {
        "body": [r"zopim\.com", r"zendesk\.com", r"zd-"],
        "icon": "💬", "category": "Chat",
    },
    "Tawk.to": {
        "body": [r"tawk\.to"],
        "icon": "💬", "category": "Chat",
    },
    "HubSpot": {
        "body": [r"hubspot\.com", r"hs-scripts\.com"],
        "icon": "🟠", "category": "Marketing",
    },
}


def detect_technologies(target: str, open_ports: list) -> dict:
    base_url = _choose_base_url(target, open_ports)
    fetch = _fetch(base_url)

    if fetch is None and base_url.startswith("https://"):
        base_url = f"http://{target}"
        fetch = _fetch(base_url)

    if fetch is None:
        return {"error": "Could not connect", "url": base_url, "technologies": []}

    status, headers, body = fetch
    headers_norm = {k.lower(): v for k, v in headers.items()}
    body_lower = body.lower()

    detected = []
    for tech_name, patterns in TECH_PATTERNS.items():
        found = False

        # Check body patterns
        for pat in patterns.get("body", []):
            if re.search(pat, body, re.IGNORECASE):
                found = True
                break

        # Check header patterns
        if not found:
            for header_key, pat in patterns.get("headers", {}).items():
                header_val = headers_norm.get(header_key.lower(), "")
                if header_val and re.search(pat, header_val, re.IGNORECASE):
                    found = True
                    break

        if found:
            detected.append({
                "name": tech_name,
                "icon": patterns.get("icon", "⚙️"),
                "category": patterns.get("category", "Other"),
            })

    # Group by category
    categories = {}
    for tech in detected:
        cat = tech["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tech)

    return {
        "url": base_url,
        "status_code": status,
        "technologies": detected,
        "by_category": categories,
        "count": len(detected),
    }


# ─── 3. Rutas sensibles ───────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    # Config / info disclosure
    ("/robots.txt",              "Robots.txt",          "info",   "Puede revelar rutas ocultas / Can reveal hidden paths"),
    ("/sitemap.xml",             "Sitemap",             "info",   "Mapa del sitio / Site structure map"),
    ("/.git/HEAD",               ".git expuesto",       "high",   "Repositorio Git accesible públicamente / Git repo exposed"),
    ("/.env",                    ".env expuesto",       "high",   "Variables de entorno expuestas / Env vars exposed"),
    ("/config.php",              "config.php",          "high",   "Fichero de configuración / Config file"),
    ("/configuration.php",       "configuration.php",   "high",   "Configuración Joomla / Joomla config"),
    ("/wp-config.php",           "wp-config.php",       "high",   "Configuración WordPress / WordPress config"),
    ("/phpinfo.php",             "phpinfo()",           "high",   "Información del servidor PHP / PHP server info"),
    ("/info.php",                "info.php",            "high",   "Información del servidor / Server info"),
    # Admin panels
    ("/wp-admin/",               "WordPress Admin",     "medium", "Panel de administración WordPress / WordPress admin panel"),
    ("/admin/",                  "Admin Panel",         "medium", "Panel de administración genérico / Generic admin panel"),
    ("/administrator/",          "Joomla Admin",        "medium", "Panel de administración Joomla / Joomla admin panel"),
    ("/login",                   "Login",               "info",   "Página de inicio de sesión / Login page"),
    ("/dashboard",               "Dashboard",           "info",   "Dashboard / Dashboard"),
    ("/phpmyadmin/",             "phpMyAdmin",          "high",   "Interfaz de base de datos expuesta / DB interface exposed"),
    ("/pma/",                    "phpMyAdmin (pma)",    "high",   "Interfaz phpMyAdmin alternativa / Alt phpMyAdmin"),
    # API / debug
    ("/api/",                    "API Root",            "info",   "Raíz de API / API root endpoint"),
    ("/swagger-ui.html",         "Swagger UI",          "medium", "Documentación de API expuesta / API docs exposed"),
    ("/swagger/",                "Swagger",             "medium", "Documentación de API / API documentation"),
    ("/api/docs",                "API Docs",            "medium", "Documentación de API / API documentation"),
    ("/graphql",                 "GraphQL",             "medium", "Endpoint GraphQL expuesto / GraphQL endpoint"),
    ("/debug",                   "Debug endpoint",      "high",   "Endpoint de debug / Debug endpoint"),
    ("/console",                 "Console",             "high",   "Consola de administración / Admin console"),
    # Backups / logs
    ("/backup/",                 "Backup dir",          "high",   "Directorio de backups / Backup directory"),
    ("/logs/",                   "Logs dir",            "high",   "Directorio de logs / Logs directory"),
    ("/error_log",               "Error log",           "medium", "Registro de errores / Error log"),
    ("/.htaccess",               ".htaccess",           "medium", "Configuración Apache / Apache config"),
    ("/web.config",              "web.config",          "high",   "Configuración IIS / IIS config"),
    # Common services
    ("/server-status",           "Apache Status",       "medium", "Estado del servidor Apache / Apache server status"),
    ("/server-info",             "Apache Info",         "medium", "Información del servidor / Server info"),
]


def scan_sensitive_paths(target: str, open_ports: list, timeout: float = 4.0) -> dict:
    base_url = _choose_base_url(target, open_ports)

    found = []
    not_found = 0
    errors = 0

    for path, label, severity, description in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            result = _fetch(url, timeout=timeout)
            if result is None:
                errors += 1
                continue
            status, hdrs, body = result
            if status in (200, 301, 302, 403):
                content_type = hdrs.get("Content-Type", hdrs.get("content-type", ""))
                size = len(body)
                found.append({
                    "path": path,
                    "label": label,
                    "severity": severity,
                    "description": description,
                    "status_code": status,
                    "content_type": content_type,
                    "size_bytes": size,
                    "url": url,
                    "accessible": status == 200,
                })
            else:
                not_found += 1
        except Exception:
            errors += 1

    # Sort by severity
    order = {"high": 0, "medium": 1, "info": 2}
    found.sort(key=lambda x: order.get(x["severity"], 9))

    high_count   = sum(1 for f in found if f["severity"] == "high" and f["accessible"])
    medium_count = sum(1 for f in found if f["severity"] == "medium" and f["accessible"])

    return {
        "base_url": base_url,
        "found": found,
        "not_found": not_found,
        "errors": errors,
        "high_count": high_count,
        "medium_count": medium_count,
        "total_found": len(found),
    }
