# -*- coding: utf-8 -*-
MODUL_ADI = "dizin"; KATEGORI = "web"
YOLLAR = ["/.env","/backup.sql","/.git/config","/admin","/wp-admin","/phpmyadmin"]
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    for yol in YOLLAR:
        url = hedef.rstrip("/") + yol
        try:
            async with session.get(url, timeout=5) as r:
                if r.status in (200,301,302,403):
                    db_yaz(hedef, MODUL_ADI, KATEGORI, f"Bulundu: {yol}", f"HTTP {r.status}", "yuksek")
                    await ws.yayinla({"tip":"bulgu","hedef":hedef,"modul":MODUL_ADI,"bulgu":yol,"durum":r.status})
        except: pass
