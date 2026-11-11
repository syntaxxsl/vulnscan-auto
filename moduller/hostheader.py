# -*- coding: utf-8 -*-
MODUL_ADI = "hostheader"; KATEGORI = "web"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, headers={"Host":"evil.com"}, timeout=5) as r:
            if "evil.com" in await r.text():
                db_yaz(hedef, MODUL_ADI, KATEGORI, "Host header injection", "", "yuksek")
    except: pass
