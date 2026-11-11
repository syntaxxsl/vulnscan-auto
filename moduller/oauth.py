# -*- coding: utf-8 -*-
MODUL_ADI = "oauth"; KATEGORI = "kimlik"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    test_url = hedef.rstrip("/") + "/oauth/authorize?redirect_uri=https://evil.com"
    try:
        async with session.get(test_url, timeout=5, allow_redirects=False) as r:
            if r.status in (301,302) and "evil.com" in r.headers.get("Location",""):
                db_yaz(hedef, MODUL_ADI, KATEGORI, "OAuth redirect_uri manipulasyonu", test_url, "kritik")
                await ws.yayinla({"tip":"bulgu","hedef":hedef,"modul":MODUL_ADI,"bulgu":"OAuth"})
    except: pass
