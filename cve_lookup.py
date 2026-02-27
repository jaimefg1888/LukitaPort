import asyncio
import time
from typing import Optional
import httpx


NVD_API_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT  = 12.0
RESULTS_PER_PAGE = 5
NVD_REQUEST_DELAY = 6.2  # 5 requests per 30s free tier limit

SEVERITY_COLORS = {
    "CRITICAL": "#ff0033",
    "HIGH":     "#ff4444",
    "MEDIUM":   "#ffaa00",
    "LOW":      "#00cc66",
    "NONE":     "#555555",
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


class _TTLCache:
    def __init__(self, ttl_seconds: int = 600):
        self._store: dict[str, tuple[dict, float]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Optional[dict]:
        entry = self._store.get(key)
        if entry and (time.monotonic() - entry[1]) < self._ttl:
            return entry[0]
        if entry:
            del self._store[key]
        return None

    def set(self, key: str, value: dict) -> None:
        self._store[key] = (value, time.monotonic())

    def clear(self) -> None:
        self._store.clear()

    @property
    def size(self) -> int:
        return len(self._store)


_cache = _TTLCache(ttl_seconds=600)
_nvd_lock = asyncio.Lock()
_last_request_time: float = 0.0


async def _nvd_request(keyword: str, results_per_page: int = RESULTS_PER_PAGE) -> Optional[dict]:
    global _last_request_time

    async with _nvd_lock:
        elapsed = time.monotonic() - _last_request_time
        if elapsed < NVD_REQUEST_DELAY:
            await asyncio.sleep(NVD_REQUEST_DELAY - elapsed)

        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                resp = await client.get(
                    NVD_API_BASE,
                    params={"keywordSearch": keyword, "resultsPerPage": results_per_page, "startIndex": 0},
                    headers={"User-Agent": "LukitaPort Security Audit", "Accept": "application/json"},
                )
                _last_request_time = time.monotonic()

                if resp.status_code == 404:
                    return {"totalResults": 0, "vulnerabilities": []}
                if resp.status_code == 429:
                    return {"_error": "rate_limited", "totalResults": 0, "vulnerabilities": []}
                resp.raise_for_status()
                return resp.json()

        except httpx.HTTPStatusError as e:
            _last_request_time = time.monotonic()
            if e.response.status_code == 429:
                return {"_error": "rate_limited", "totalResults": 0, "vulnerabilities": []}
            return None
        except Exception:
            _last_request_time = time.monotonic()
            return None


def _parse_cve(vuln: dict) -> dict:
    cve  = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    description  = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )

    cvss_score, severity = None, "NONE"
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            m = metrics[key]
            if isinstance(m, list) and m:
                cvss_data  = m[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity   = (m[0].get("baseSeverity") or cvss_data.get("baseSeverity") or "NONE").upper()
                break

    return {
        "id":          cve_id,
        "description": description[:300] + ("..." if len(description) > 300 else ""),
        "cvss_score":  cvss_score,
        "severity":    severity,
        "severity_color": SEVERITY_COLORS.get(severity, "#555"),
        "published":   cve.get("published", "")[:10],
        "references":  [r.get("url", "") for r in cve.get("references", [])[:3] if r.get("url")],
        "nvd_url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


async def lookup_cves(service: str, version: str = "", max_results: int = 5) -> dict:
    keyword = f"{service} {version}".strip() if version else service.strip()
    if not keyword:
        return {"cves": [], "total": 0, "error": "No keyword provided", "keyword_used": ""}

    cache_key = keyword.lower()
    cached = _cache.get(cache_key)
    if cached is not None:
        return {**cached, "cached": True}

    data = await _nvd_request(keyword, max_results)

    if data is None:
        return {"cves": [], "total": 0, "error": "NVD API unavailable", "keyword_used": keyword}
    if data.get("_error") == "rate_limited":
        return {"cves": [], "total": 0, "error": "NVD rate limit exceeded — retry in 30s.", "keyword_used": keyword}

    cves = sorted(
        [_parse_cve(v) for v in data.get("vulnerabilities", [])[:max_results]],
        key=lambda c: SEV_ORDER.get(c["severity"], 9),
    )
    result = {"cves": cves, "total": data.get("totalResults", 0), "error": None, "keyword_used": keyword, "cached": False}
    _cache.set(cache_key, result)
    return result


async def lookup_cves_for_ports(versions: dict) -> dict:
    results = {}
    for port_str, info in versions.items():
        port    = int(port_str) if isinstance(port_str, str) else port_str
        service = info.get("name") or info.get("product") or ""
        version = info.get("version") or ""
        if not service:
            continue
        result = await lookup_cves(service, version)
        if result.get("cves") or result.get("error"):
            results[port] = result
    return results


def get_cache_stats() -> dict:
    return {"entries": _cache.size, "ttl_seconds": _cache._ttl}
