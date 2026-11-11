# -*- coding: utf-8 -*-
MODUL_ADI = "dns"; KATEGORI = "ag"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    domain = hedef.replace("http://","").replace("https://","").split("/")[0]
    try:
        async with session.get(f"https://dns.google/resolve?name={domain}&type=AXFR", timeout=5) as r:
            if r.status == 200:
                d = await r.json()
                if d.get("Answer"):
                    db_yaz(hedef, MODUL_ADI, KATEGORI, "DNS zone transfer acik olabilir", str(d["Answer"]), "yuksek")
    except: pass
