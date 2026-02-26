import json
from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from resolver import resolve_target
from scanner import scan_ports_stream, get_port_range

app = FastAPI(title="LukitaPort", version="1.0.0")

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
            yield f"data: {json.dumps({'error': f'Could not resolve target: {resolution[\"error\"]}'})}\n\n"
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
