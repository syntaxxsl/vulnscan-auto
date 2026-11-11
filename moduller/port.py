# -*- coding: utf-8 -*-
import asyncio
MODUL_ADI = "port"; KATEGORI = "ag"; PORTLAR = [21,22,80,443,3306,8080]
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    host = hedef.replace("http://","").replace("https://","").split("/")[0]
    for p in PORTLAR:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=3)
            db_yaz(hedef, MODUL_ADI, KATEGORI, f"Acik port: {p}", "", "orta")
            await ws.yayinla({"tip": "bulgu", "hedef": hedef, "modul": MODUL_ADI, "bulgu": f"port {p}"})
            w.close(); await w.wait_closed()
        except: pass
