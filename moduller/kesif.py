# -*- coding: utf-8 -*-
import aiohttp
import re
import urllib.parse

MODUL_ADI = "kesif"
KATEGORI = "kesif"

# Açık siteleri bulmak için DuckDuckGo HTML arama sorguları
ARAMA_SORGULARI = [
    "inurl:admin.php",
    "inurl:.env",
    "inurl:wp-content",
    "inurl:backup.sql"
]

async def osint_hedef_listesi():
    hedefler = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    async with aiohttp.ClientSession(headers=headers) as session:
        for sorgu in ARAMA_SORGULARI:
            url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(sorgu)}"
            try:
                async with session.get(url, timeout=10) as r:
                    if r.status == 200:
                        html = await r.text()
                        # DuckDuckGo sonuç linklerini ayıkla
                        linkler = re.findall(r'class="result__url" href="([^"]+)"', html)
                        for link in linkler:
                            # DuckDuckGo yönlendirme linklerini temizle
                            if "uddg=" in link:
                                link = urllib.parse.unquote(link.split("uddg=")[1].split("&")[0])
                            
                            if link.startswith("http"):
                                # Sadece ana domaini al (alt dizinleri temizle)
                                parsed = urllib.parse.urlparse(link)
                                domain_url = f"{parsed.scheme}://{parsed.netloc}"
                                hedefler.add(domain_url)
            except Exception as e:
                print(f"[KESIF HATASI] {sorgu}: {e}")

    # Eğer hiç sonuç bulunamazsa test listesine dön
    if not hedefler:
        return ["http://testphp.vulnweb.com", "http://example.com"]
        
    return list(hedefler)[:5]  # Test için ilk 5 siteyi döndür

async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    db_yaz(hedef, MODUL_ADI, KATEGORI, "Hedef listeye alindi", "", "bilgi")
    await ws.yayinla({"tip": "bulgu", "hedef": hedef, "modul": MODUL_ADI, "bulgu": "Hedef listeye eklendi"})
