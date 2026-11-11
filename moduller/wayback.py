# -*- coding: utf-8 -*-
MODUL_ADI = "wayback"; KATEGORI = "kesif"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    domain = hedef.replace("http://","").replace("https://","").split("/")[0]
    try:
        async with session.get(f"http://archive.org/wayback/available?url={domain}", timeout=10) as r:
            d = await r.json()
            if d.get("archived_snapshots"):
                db_yaz(hedef, MODUL_ADI, KATEGORI, f"Arsiv: {d['archived_snapshots']}", "", "bilgi")
    except: pass
