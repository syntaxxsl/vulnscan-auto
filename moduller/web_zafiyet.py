# -*- coding: utf-8 -*-
MODUL_ADI = "web_zafiyet"; KATEGORI = "web"
LFI = ["/index.php?page=../../../../etc/passwd","/?file=../../../../etc/passwd"]
XSS = ["/?q=<script>alert(1)</script>"]
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    for p in LFI:
        try:
            async with session.get(hedef.rstrip("/")+p, timeout=5) as r:
                t = await r.text()
                if "root:x:0:0" in t:
                    db_yaz(hedef, MODUL_ADI, KATEGORI, "LFI tespit", p, "kritik")
                    await ws.yayinla({"tip":"bulgu","hedef":hedef,"modul":MODUL_ADI,"bulgu":"LFI"})
        except: pass
    for p in XSS:
        try:
            async with session.get(hedef.rstrip("/")+p, timeout=5) as r:
                t = await r.text()
                if "<script>alert(1)</script>" in t:
                    db_yaz(hedef, MODUL_ADI, KATEGORI, "XSS tespit", p, "yuksek")
                    await ws.yayinla({"tip":"bulgu","hedef":hedef,"modul":MODUL_ADI,"bulgu":"XSS"})
        except: pass
