# -*- coding: utf-8 -*-
import re
MODUL_ADI = "crawler"; KATEGORI = "web"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, timeout=5) as r:
            html = await r.text()
            for l in list(set(re.findall(r'href="([^"]+)"', html)))[:20]:
                db_yaz(hedef, MODUL_ADI, KATEGORI, f"Link: {l}", "", "bilgi")
            for f in list(set(re.findall(r'<form[^>]*action="([^"]*)"', html))):
                db_yaz(hedef, MODUL_ADI, KATEGORI, f"Form: {f}", "", "bilgi")
    except: pass
