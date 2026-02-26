"""
main.py — LukitaPort API Server
FastAPI + SSE para escaneo de puertos en tiempo real.
jaimefg1888 | LukitaPort
"""

import json
import asyncio
from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from resolver import resolve_target
from scanner import scan_ports_stream, get_port_range

app = FastAPI(
    title="LukitaPort",
    description="Port scanner API — solo para uso educativo y en entornos propios.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/", include_in_schema=False)
def root():
    return FileResponse("frontend/index.html")


@app.get("/api/resolve")
def resolve(target: str = Query(..., description="IP o dominio a resolver")):
    return resolve_target(target)


@app.get("/api/scan")
def scan(
    target: str = Query(...),
    mode: str = Query("quick", regex="^(quick|full|custom)$"),
    port_start: int = Query(1, ge=1, le=65535),
    port_end: int = Query(1024, ge=1, le=65535),
    timeout: float = Query(1.0, ge=0.1, le=5.0),
):
    """
    Stream de SSE con resultados de escaneo en tiempo real.
    Cada evento es un JSON con el resultado del puerto escaneado.
    """
    resolution = resolve_target(target)

    if resolution["error"] or not resolution["ip"]:
        error_msg = f"No se pudo resolver el objetivo: {resolution['error']}"
        def error_stream():
            yield f"data: {json.dumps({'error': error_msg})}\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")

    ip = resolution["ip"]
    ports = get_port_range(mode, port_start, port_end)

    def event_stream():
        # Primer evento: metadata de la sesión
        meta = {
            "type": "meta",
            "ip": ip,
            "hostname": resolution["hostname"],
            "resolved": resolution["resolved"],
            "total_ports": len(ports),
            "mode": mode,
        }
        yield f"data: {json.dumps(meta)}\n\n"

        open_count = 0
        for result in scan_ports_stream(ip, ports, timeout):
            if result["state"] == "open":
                open_count += 1
            result["type"] = "port"
            yield f"data: {json.dumps(result)}\n\n"

        # Evento final con resumen
        summary = {
            "type": "done",
            "open_ports": open_count,
            "total_scanned": len(ports),
        }
        yield f"data: {json.dumps(summary)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
