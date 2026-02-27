import json
import re
import asyncio
import shutil
import sys
import ipaddress
from fastapi import FastAPI, Query, Request, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Annotated

import httpx

from config import PORT_RISK
from resolver import resolve_target
from scanner import scan_ports_stream, get_port_range, PROFILES
from auditor import run_full_audit
from ssl_analyzer import analyze_ssl_for_ports
from cve_lookup import lookup_cves, lookup_cves_for_ports

app = FastAPI(title="LukitaPort")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")

_screenshots: dict[str, dict] = {}

# ─── Input Validation ─────────────────────────────────────────────────────────

_HOSTNAME_RE = re.compile(
    r'^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)'
    r'(?:\.(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?))*$'
)

_DOMAIN_LABEL_RE = re.compile(r'^[A-Za-z0-9\-]{1,63}$')


def _validate_target(target: str) -> str:
    t = target.strip()
    if not t or len(t) > 253:
        raise HTTPException(status_code=400, detail="Invalid target: empty or exceeds 253 characters")
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    if _HOSTNAME_RE.match(t) and "." in t:
        return t
    raise HTTPException(
        status_code=400,
        detail=f"Invalid target: '{t}' must be a valid IPv4, IPv6, or RFC 1123 hostname",
    )


def _validate_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {e}")


def _validate_domain(domain: str) -> str:
    d = domain.strip().lstrip("*.").lower()
    if not d or len(d) > 253 or "." not in d:
        raise HTTPException(status_code=400, detail="Invalid domain: must contain at least one dot")
    labels = d.split(".")
    if not all(_DOMAIN_LABEL_RE.match(lbl) for lbl in labels):
        raise HTTPException(status_code=400, detail=f"Invalid domain: '{d}' contains invalid characters")
    return d


def _validate_open_ports(ports_str: str) -> list[int]:
    ports = []
    for p in ports_str.split(","):
        p = p.strip()
        if not p.isdigit():
            raise HTTPException(status_code=400, detail=f"Invalid port value: '{p}'")
        pint = int(p)
        if not (1 <= pint <= 65535):
            raise HTTPException(status_code=400, detail=f"Port {pint} is out of range (1–65535)")
        ports.append(pint)
    return ports


# ─── Config ───────────────────────────────────────────────────────────────────

@app.get("/api/config", include_in_schema=False)
def get_config():
    return {"portRisk": {str(k): v for k, v in PORT_RISK.items()}}


# ─── Root ─────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root():
    return FileResponse("frontend/index.html")


# ─── Resolve ─────────────────────────────────────────────────────────────────

@app.get("/api/resolve")
async def resolve(target: str = Query(...)):
    safe = _validate_target(target)
    return resolve_target(safe)


# ─── GeoIP / ASN ─────────────────────────────────────────────────────────────

async def _geoip(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,regionName,city,isp,as,org,query"},
            )
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country":      data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region":       data.get("regionName", ""),
                    "city":         data.get("city", ""),
                    "isp":          data.get("isp", ""),
                    "asn":          data.get("as", ""),
                    "org":          data.get("org", ""),
                }
    except Exception:
        pass
    return {}


@app.get("/api/geoip")
async def geoip(target: str = Query(...)):
    safe = _validate_target(target)
    resolution = resolve_target(safe)
    if resolution["error"] or not resolution["ip"]:
        return {"error": f"Could not resolve: {resolution['error']}"}
    geo = await _geoip(resolution["ip"])
    return {"ip": resolution["ip"], **geo}


# ─── Scan ────────────────────────────────────────────────────────────────────

@app.get("/api/scan")
async def scan(
    request:    Request,
    target:     str   = Query(...),
    mode:       str   = Query("quick",  regex="^(quick|full|custom)$"),
    profile:    str   = Query("normal", regex="^(stealth|normal|aggressive)$"),
    port_start: int   = Query(1,    ge=1, le=65535),
    port_end:   int   = Query(1024, ge=1, le=65535),
    timeout:    float = Query(1.0,  ge=0.1, le=5.0),
):
    safe = _validate_target(target)
    resolution = resolve_target(safe)

    if resolution["error"] or not resolution["ip"]:
        err_msg = resolution["error"]
        async def error_stream():
            yield 'data: ' + json.dumps({'error': f'Could not resolve target: {err_msg}'}) + '\n\n'

        return StreamingResponse(error_stream(), media_type="text/event-stream")

    ip    = resolution["ip"]
    ports = get_port_range(mode, port_start, port_end)
    prof  = PROFILES.get(profile, PROFILES["normal"])

    geo_task = asyncio.create_task(_geoip(ip))

    async def event_stream():
        try:
            geo = await asyncio.wait_for(geo_task, timeout=3.0)
        except Exception:
            geo = {}

        meta = {
            "type":        "meta",
            "ip":          ip,
            "hostname":    resolution["hostname"],
            "resolved":    resolution["resolved"],
            "total_ports": len(ports),
            "mode":        mode,
            "profile":     profile,
            "input":       target,
            "geo":         geo,
        }
        yield f"data: {json.dumps(meta)}\n\n"

        open_count = 0

        async for result in scan_ports_stream(
            ip, ports, timeout,
            max_concurrent=prof["max_concurrent"],
            inter_delay=prof["inter_delay"],
        ):
            if await request.is_disconnected():
                yield f"data: {json.dumps({'type': 'cancelled'})}\n\n"
                return

            if result["state"] == "open":
                open_count += 1
            result["type"] = "port"
            yield f"data: {json.dumps(result)}\n\n"

        yield f"data: {json.dumps({'type': 'done', 'open_ports': open_count, 'total_scanned': len(ports)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ─── Network Discovery ────────────────────────────────────────────────────────

_NMAP_TIMEOUT_BASE       = 20
_NMAP_TIMEOUT_PER_PORT   = 4

@app.get("/api/discover")
async def discover(
    cidr:      str = Query(..., description="CIDR range, e.g. 192.168.1.0/24"),
    max_hosts: int = Query(254, ge=1, le=1024),
):
    network = _validate_cidr(cidr)
    hosts   = list(network.hosts())[:max_hosts]
    if not hosts:
        return {"error": "No hosts in range", "alive": []}

    is_windows = sys.platform == "win32"

    async def ping_host(ip_obj) -> Optional[dict]:
        ip_str = str(ip_obj)
        # ip_str is guaranteed to be a valid IP from ipaddress library
        args = (
            ["ping", "-n", "1", "-w", "800", ip_str]
            if is_windows
            else ["ping", "-c", "1", "-W", "1", ip_str]
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return None

            if proc.returncode == 0:
                output = stdout.decode("utf-8", errors="replace")
                rtt = None
                for pattern in (r"time[<=](\d+\.?\d*)\s*ms", r"Average\s*=\s*(\d+)ms"):
                    m = re.search(pattern, output, re.IGNORECASE)
                    if m:
                        rtt = float(m.group(1))
                        break
                return {"ip": ip_str, "alive": True, "rtt_ms": rtt}
        except Exception:
            pass
        return None

    sem = asyncio.Semaphore(64)

    async def ping_with_sem(ip_obj):
        async with sem:
            return await ping_host(ip_obj)

    tasks   = [asyncio.create_task(ping_with_sem(h)) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    alive   = [r for r in results if isinstance(r, dict) and r and r.get("alive")]
    alive.sort(key=lambda x: list(map(int, x["ip"].split("."))))

    return {
        "cidr":        cidr,
        "total_hosts": len(hosts),
        "alive_count": len(alive),
        "alive":       alive,
    }


# ─── Subdomains ───────────────────────────────────────────────────────────────

@app.get("/api/subdomains")
async def subdomains(domain: str = Query(...)):
    import socket
    safe = _validate_domain(domain)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{safe}", "output": "json"},
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return {"error": f"crt.sh returned {resp.status_code}", "subdomains": []}
            data = resp.json()
    except Exception as e:
        return {"error": f"crt.sh unreachable: {e}", "subdomains": []}

    seen: set[str] = set()
    results = []

    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.").lower()
            if not name or name in seen:
                continue
            if not (name == safe or name.endswith(f".{safe}")):
                continue
            if "*" in name:
                continue
            seen.add(name)
            results.append({
                "subdomain":  name,
                "issuer":     entry.get("issuer_name", ""),
                "not_before": entry.get("not_before", "")[:10],
                "not_after":  entry.get("not_after", "")[:10],
            })

    results.sort(key=lambda x: x["subdomain"])

    async def resolve_sub(item: dict) -> dict:
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, item["subdomain"])
            return {**item, "ip": ip, "resolves": True}
        except Exception:
            return {**item, "ip": None, "resolves": False}

    top  = results[:50]
    rest = results[50:]
    resolved_top = await asyncio.gather(*[asyncio.create_task(resolve_sub(r)) for r in top], return_exceptions=True)
    resolved_top = [r for r in resolved_top if isinstance(r, dict)]
    for item in rest:
        resolved_top.append({**item, "ip": None, "resolves": None})

    return {
        "domain":     safe,
        "total":      len(results),
        "subdomains": resolved_top,
    }


# ─── Nmap helpers ─────────────────────────────────────────────────────────────

def _find_nmap() -> Optional[str]:
    path = shutil.which("nmap")
    if path:
        return path
    if sys.platform == "win32":
        import os
        for candidate in (
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\nmap\nmap.exe",
        ):
            if os.path.isfile(candidate):
                return candidate
    return None


async def _run_nmap_async(ip: str, ports_str: str, timeout_seconds: int) -> dict:
    nmap_bin = _find_nmap()
    if not nmap_bin:
        return {"_error": "nmap_not_installed"}

    args = [
        nmap_bin,
        "-sV", "--version-intensity", "5",
        "-T4",
        "--host-timeout", f"{timeout_seconds}s",
        "-p", ports_str,
        "-oX", "-",
        ip,
    ]

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds + 10)
    except asyncio.TimeoutError:
        try:
            proc.terminate()
            await asyncio.sleep(1)
            proc.kill()
        except ProcessLookupError:
            pass
        return {"_error": "nmap_timeout"}
    except asyncio.CancelledError:
        try:
            proc.terminate()
            await asyncio.sleep(0.5)
            proc.kill()
        except ProcessLookupError:
            pass
        raise

    if proc.returncode != 0 and not stdout:
        err = stderr.decode("utf-8", errors="replace")[:200]
        if "nmap" in err.lower() or "command not found" in err.lower():
            return {"_error": "nmap_not_installed"}
        return {"_error": err or "nmap error"}

    return _parse_nmap_xml(stdout.decode("utf-8", errors="replace"))


def _parse_nmap_xml(xml: str) -> dict:
    import xml.etree.ElementTree as ET
    results = {}
    try:
        root = ET.fromstring(xml)
        for host in root.findall("host"):
            for ports_el in host.findall("ports"):
                for port_el in ports_el.findall("port"):
                    portid    = int(port_el.get("portid", 0))
                    state_el  = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    svc = port_el.find("service") or {}
                    results[portid] = {
                        "product":   svc.get("product", "")   if hasattr(svc, "get") else "",
                        "version":   svc.get("version", "")   if hasattr(svc, "get") else "",
                        "extrainfo": svc.get("extrainfo", "") if hasattr(svc, "get") else "",
                        "cpe":       (svc.find("cpe").text if svc.find("cpe") is not None else "") if hasattr(svc, "find") else "",
                        "name":      svc.get("name", "")      if hasattr(svc, "get") else "",
                    }
    except Exception as e:
        results["_error"] = f"xml_parse_error: {e}"
    return results


# ─── Fingerprint ─────────────────────────────────────────────────────────────

@app.get("/api/fingerprint")
async def fingerprint(
    request: Request,
    target:  str = Query(...),
    ports:   str = Query(...),
):
    safe       = _validate_target(target)
    resolution = resolve_target(safe)
    if resolution["error"] or not resolution["ip"]:
        return {"error": f"Could not resolve: {resolution['error']}", "results": {}}

    port_list = _validate_open_ports(ports)
    if not port_list:
        return {"error": "No valid ports provided", "results": {}}

    ports_str   = ",".join(str(p) for p in port_list)
    timeout_sec = _NMAP_TIMEOUT_BASE + _NMAP_TIMEOUT_PER_PORT * len(port_list)

    results = await _run_nmap_async(resolution["ip"], ports_str, timeout_sec)
    return {
        "ip":          resolution["ip"],
        "timeout_sec": timeout_sec,
        "results":     results,
    }


# ─── Screenshot ──────────────────────────────────────────────────────────────

async def _take_screenshot_bg(target: str, port: int):
    import time
    scheme = "https" if port in (443, 8443) else "http"
    url    = f"{scheme}://{target}:{port}" if port not in (80, 443) else f"{scheme}://{target}"
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            page = await browser.new_page(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
            )
            try:
                await asyncio.wait_for(page.goto(url, wait_until="domcontentloaded"), timeout=8.0)
                png = await page.screenshot(full_page=False)
                _screenshots[target] = {"png": png, "url": url, "ts": time.time()}
            except Exception:
                pass
            finally:
                await browser.close()
    except (ImportError, Exception):
        pass


@app.get("/api/screenshot")
async def get_screenshot(target: str = Query(...)):
    data = _screenshots.get(target)
    if not data:
        return Response(status_code=204)
    return Response(
        content=data["png"],
        media_type="image/png",
        headers={"X-Screenshot-Url": data.get("url", "")},
    )


@app.post("/api/screenshot/capture")
async def capture_screenshot(
    background_tasks: BackgroundTasks,
    target: str = Query(...),
    port:   int = Query(80),
):
    safe       = _validate_target(target)
    resolution = resolve_target(safe)
    if resolution["error"] or not resolution["ip"]:
        return {"error": f"Could not resolve: {resolution['error']}"}
    hostname = resolution["hostname"] or target
    background_tasks.add_task(_take_screenshot_bg, hostname, port)
    return {"status": "capturing", "target": hostname, "port": port}


# ─── Audit ───────────────────────────────────────────────────────────────────

@app.get("/api/audit")
async def audit(
    target:     str = Query(...),
    open_ports: str = Query("80,443"),
):
    safe       = _validate_target(target)
    resolution = resolve_target(safe)
    if resolution["error"] or not resolution["ip"]:
        return {"error": f"Could not resolve: {resolution['error']}"}

    ports    = _validate_open_ports(open_ports)
    hostname = resolution["hostname"] or target
    result   = await run_full_audit(hostname, ports)
    return {"target": target, "ip": resolution["ip"], **result}


# ─── SSL ─────────────────────────────────────────────────────────────────────

@app.get("/api/ssl")
async def ssl_analysis(
    target:     str   = Query(...),
    open_ports: str   = Query("443"),
    timeout:    float = Query(8.0, ge=1.0, le=30.0),
):
    safe       = _validate_target(target)
    resolution = resolve_target(safe)
    if resolution["error"] or not resolution["ip"]:
        return {"error": f"Could not resolve: {resolution['error']}"}

    ports    = _validate_open_ports(open_ports)
    hostname = resolution["hostname"] or target
    loop     = asyncio.get_event_loop()
    result   = await loop.run_in_executor(None, analyze_ssl_for_ports, hostname, ports, timeout)
    return {"target": target, "ip": resolution["ip"], **result}


# ─── CVE ─────────────────────────────────────────────────────────────────────

@app.get("/api/cve")
async def cve_lookup_endpoint(
    service:     str = Query(...),
    version:     str = Query(""),
    max_results: int = Query(5, ge=1, le=10),
):
    return await lookup_cves(service, version, max_results)


@app.post("/api/cve/batch")
async def cve_batch(versions: dict):
    results = await lookup_cves_for_ports(versions)
    return {"results": results}


@app.get("/api/cve/cache-stats", include_in_schema=False)
async def cve_cache_stats():
    from cve_lookup import get_cache_stats
    return get_cache_stats()


# ─── Markdown Export ─────────────────────────────────────────────────────────

class ScanData(BaseModel):
    meta:    dict
    results: list
    summary: dict


class ExportRequest(BaseModel):
    scan:              ScanData
    audit:             Optional[dict] = None
    screenshot_target: Optional[str]  = None


@app.post("/api/export/md")
async def export_markdown(payload: ExportRequest):
    from datetime import datetime

    meta    = payload.scan.meta
    results = payload.scan.results
    summary = payload.scan.summary
    audit   = payload.audit
    ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_info = meta.get("target", {}) or {}

    lines = []
    lines.append("# LukitaPort — Port Scan Report")
    lines.append("")
    lines.append(f"> Generated: {ts}  ")
    lines.append(f"> **Target:** `{target_info.get('input', '—')}`  ")
    lines.append(f"> **IP:** `{target_info.get('ip', '—')}`  ")
    if target_info.get("hostname"):
        lines.append(f"> **Hostname:** `{target_info['hostname']}`  ")
    lines.append(f"> **Mode:** {target_info.get('mode', '—')}  ")
    lines.append(f"> **Profile:** {target_info.get('profile', 'normal')}  ")

    geo = target_info.get("geo") or {}
    if geo:
        lines.append(f"> **Location:** {geo.get('city', '')} {geo.get('country', '')} · {geo.get('isp', '')} · {geo.get('asn', '')}  ")
    lines.append("> **For educational use only.**")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Open | Closed | Filtered | Total Scanned |")
    lines.append("|------|--------|----------|---------------|")
    lines.append(f"| {summary.get('open', 0)} | {summary.get('closed', 0)} | {summary.get('filtered', 0)} | {summary.get('total', 0)} |")
    lines.append("")

    open_ports = [r for r in results if r.get("state") == "open"]
    if open_ports:
        lines.append("## Open Ports")
        lines.append("")
        lines.append("| Port | Service | Risk | Response (ms) | Version / Banner |")
        lines.append("|------|---------|------|---------------|------------------|")
        for r in open_ports:
            port    = r.get("port", "")
            service = r.get("service", "")
            risk    = PORT_RISK.get(port, "info").upper()
            resp    = r.get("response_time_ms", "—")
            version = r.get("version") or r.get("banner") or ""
            lines.append(f"| {port} | {service} | {risk} | {resp} | {str(version)[:60]} |")
        lines.append("")

    high_n = sum(1 for r in open_ports if PORT_RISK.get(r.get("port"), "info") == "high")
    med_n  = sum(1 for r in open_ports if PORT_RISK.get(r.get("port"), "info") == "medium")
    if high_n or med_n:
        lines.append("## Risk Assessment")
        lines.append("")
        if high_n:
            lines.append(f"- 🔴 **{high_n} high-risk port(s)** — FTP, Telnet, RDP, exposed databases…")
        if med_n:
            lines.append(f"- 🟡 **{med_n} medium-risk port(s)** — SSH, DNS, IMAP, alternative proxies")
        lines.append("")

    lines.append("## All Results")
    lines.append("")
    lines.append("| Port | State | Service | Risk | Response (ms) |")
    lines.append("|------|-------|---------|------|---------------|")
    for r in results:
        port  = r.get("port", "")
        state = r.get("state", "")
        svc   = r.get("service", "")
        risk  = PORT_RISK.get(port, "info").upper() if state == "open" else "—"
        resp  = r.get("response_time_ms", "—")
        icon  = "🟢" if state == "open" else "🟡" if state == "filtered" else "🔴"
        lines.append(f"| {port} | {icon} {state.capitalize()} | {svc} | {risk} | {resp} |")
    lines.append("")

    if audit:
        lines.append("---")
        lines.append("")
        lines.append("## Advanced Audit")
        lines.append("")
        hd = audit.get("headers")
        if hd and not hd.get("error"):
            lines.append(f"### HTTP Security Headers — Grade: {hd.get('grade','?')} ({hd.get('score',0)}/100)")
            lines.append("")
            for h in hd.get("missing", []):
                lines.append(f"- `{h['header']}` (**{h['severity'].upper()}**) — {h.get('description_en','')}")
            lines.append("")
        td = audit.get("technologies")
        if td and not td.get("error") and td.get("technologies"):
            lines.append(f"### Detected Technologies ({td['count']})")
            lines.append("")
            for tech in td["technologies"]:
                lines.append(f"- {tech['icon']} **{tech['name']}** ({tech['category']})")
            lines.append("")
        pd = audit.get("paths")
        if pd and pd.get("found"):
            lines.append(f"### Sensitive Paths ({pd['total_found']} found)")
            lines.append("")
            lines.append("| Path | Label | Severity | Status |")
            lines.append("|------|-------|----------|--------|")
            for f in pd["found"]:
                accessible = "✅ Accessible" if f["accessible"] else f"⚠️ {f['status_code']}"
                lines.append(f"| `{f['path']}` | {f['label']} | **{f['severity'].upper()}** | {accessible} |")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*LukitaPort · jaimefg1888 · For educational use only*")

    return Response(
        content="\n".join(lines),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=lukitaport_report.md"},
    )


# ─── PDF Export ───────────────────────────────────────────────────────────────

@app.post("/api/export/pdf")
async def export_pdf(payload: ExportRequest):
    try:
        from pdf_generator import generate_pdf

        screenshot_png: Optional[bytes] = None
        if payload.screenshot_target:
            sc = _screenshots.get(payload.screenshot_target)
            if sc:
                screenshot_png = sc.get("png")

        loop      = asyncio.get_event_loop()
        pdf_bytes = await loop.run_in_executor(
            None,
            generate_pdf,
            {
                "meta":    payload.scan.meta,
                "results": payload.scan.results,
                "summary": payload.scan.summary,
            },
            payload.audit,
            screenshot_png,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=lukitaport_report.pdf"},
        )
    except ImportError:
        return Response(
            content=json.dumps({"error": "reportlab not installed."}),
            media_type="application/json",
            status_code=500,
        )
    except Exception as e:
        return Response(
            content=json.dumps({"error": str(e)}),
            media_type="application/json",
            status_code=500,
        )
