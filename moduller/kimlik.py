# -*- coding: utf-8 -*-
MODUL_ADI = "kimlik"; KATEGORI = "web"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, timeout=5) as r:
            cookies = r.cookies
            for c in cookies:
                if not c.get("httponly"):
                    db_yaz(hedef, MODUL_ADI, KATEGORI, f"Cerez HttpOnly eksik: {c.key}", "", "orta")
    except: pass
