# -*- coding: utf-8 -*-
MODUL_ADI = "cve"; KATEGORI = "ag"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, timeout=5) as r:
            srv = r.headers.get("Server","")
            if "Apache/2.4.49" in srv or "Apache/2.4.50" in srv:
                db_yaz(hedef, MODUL_ADI, KATEGORI, "CVE-2021-41773 Path Traversal", srv, "kritik")
                await ws.yayinla({"tip":"bulgu","hedef":hedef,"modul":MODUL_ADI,"bulgu":"CVE-2021-41773"})
    except: pass
