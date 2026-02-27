import json
from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from resolver import resolve_target
from scanner import scan_ports_stream, get_port_range, fingerprint_ports
from auditor import audit_headers, detect_technologies, scan_sensitive_paths

app = FastAPI(title="LukitaPort", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/", include_in_schema=False)
def root():
    return FileResponse("frontend/index.html")


@app.get("/api/resolve")
def resolve(target: str = Query(...)):
    return resolve_target(target)


@app.get("/api/scan")
def scan(
    target: str = Query(...),
    mode: str = Query("quick", regex="^(quick|full|custom)$"),
    port_start: int = Query(1, ge=1, le=65535),
    port_end: int = Query(1024, ge=1, le=65535),
    timeout: float = Query(1.0, ge=0.1, le=5.0),
):
    resolution = resolve_target(target)

    if resolution["error"] or not resolution["ip"]:
        def error_stream():
            err_msg = resolution["error"]
            yield f"data: {json.dumps({'error': f'Could not resolve target: {err_msg}'})}\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")

    ip = resolution["ip"]
    ports = get_port_range(mode, port_start, port_end)

    def event_stream():
        meta = {
            "type": "meta",
            "ip": ip,
            "hostname": resolution["hostname"],
            "resolved": resolution["resolved"],
            "total_ports": len(ports),
            "mode": mode,
            "input": target,
        }
        yield f"data: {json.dumps(meta)}\n\n"

        open_count = 0
        for result in scan_ports_stream(ip, ports, timeout):
            if result["state"] == "open":
                open_count += 1
            result["type"] = "port"
            yield f"data: {json.dumps(result)}\n\n"

        yield f"data: {json.dumps({'type': 'done', 'open_ports': open_count, 'total_scanned': len(ports)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/fingerprint")
def fingerprint(
    target: str = Query(...),
    ports: str = Query(...),  # comma-separated: "80,443,22"
    timeout: float = Query(5.0, ge=1.0, le=30.0),
):
    """Detecta versiones de servicio con nmap en los puertos especificados."""
    resolution = resolve_target(target)
    if resolution["error"] or not resolution["ip"]:
        return {"error": f"Could not resolve: {resolution['error']}", "results": {}}

    port_list = []
    for p in ports.split(","):
        try:
            port_list.append(int(p.strip()))
        except ValueError:
            pass

    if not port_list:
        return {"error": "No valid ports provided", "results": {}}

    results = fingerprint_ports(resolution["ip"], port_list, timeout)
    return {"ip": resolution["ip"], "results": results}


@app.get("/api/audit")
def audit(
    target: str = Query(...),
    open_ports: str = Query("80,443"),  # comma-separated
):
    """Auditoría avanzada: cabeceras HTTP, tecnologías y rutas sensibles."""
    resolution = resolve_target(target)
    if resolution["error"] or not resolution["ip"]:
        return {"error": f"Could not resolve: {resolution['error']}"}

    ports = []
    for p in open_ports.split(","):
        try:
            ports.append(int(p.strip()))
        except ValueError:
            pass

    ip = resolution["ip"]
    hostname = resolution["hostname"] or target

    headers_result = audit_headers(hostname, ports)
    tech_result    = detect_technologies(hostname, ports)
    paths_result   = scan_sensitive_paths(hostname, ports)

    return {
        "target": target,
        "ip": ip,
        "headers": headers_result,
        "technologies": tech_result,
        "paths": paths_result,
    }


# ─── PDF export ───────────────────────────────────────────────────────────────

class ScanData(BaseModel):
    meta: dict
    results: list
    summary: dict


class ExportRequest(BaseModel):
    scan: ScanData
    audit: Optional[dict] = None


@app.post("/api/export/pdf")
def export_pdf(payload: ExportRequest):
    """Genera un informe PDF profesional con los resultados del escaneo."""
    try:
        from pdf_generator import generate_pdf
        pdf_bytes = generate_pdf(
            scan_data={
                "meta":    payload.scan.meta,
                "results": payload.scan.results,
                "summary": payload.scan.summary,
            },
            audit_data=payload.audit,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=lukitaport_report.pdf"},
        )
    except ImportError:
        return Response(
            content=json.dumps({"error": "reportlab not installed. Run: pip install reportlab"}),
            media_type="application/json",
            status_code=500,
        )
    except Exception as e:
        return Response(
            content=json.dumps({"error": str(e)}),
            media_type="application/json",
            status_code=500,
        )
