# -*- coding: utf-8 -*-
import os, asyncio, csv, io, time
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from cekirdek.motor import Motor
from cekirdek.db import db_init, db_rapor, db_yaz
from cekirdek.ws import ws_manager
from cekirdek.kayit import MODULLER

app = FastAPI(title="Zafiyet Tarayici")

@app.on_event("startup")
async def startup(): db_init()

@app.post("/api/scan")
async def api_scan(hedefler: list[str] | None = None):
    asyncio.create_task(Motor().calistir(hedefler))
    return {"durum": "baslatildi"}

@app.post("/api/scan/iptal")
async def api_iptal():
    Motor.iptal_et(); return {"durum": "iptal_edildi"}

@app.get("/api/report")
async def api_report(): return JSONResponse(db_rapor())

@app.get("/api/report/csv")
async def api_report_csv():
    rows = db_rapor()
    out = io.StringIO()
    if rows:
        w = csv.DictWriter(out, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition":"attachment; filename=rapor.csv"})

@app.get("/api/moduller")
async def api_moduller(): return {"moduller": list(MODULLER.keys())}

@app.get("/api/audit")
async def api_audit(): return JSONResponse(db_audit())

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.bagla(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: ws_manager.ayir(ws)

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("arayuz/index.html", "r", encoding="utf-8") as f: return f.read()

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
