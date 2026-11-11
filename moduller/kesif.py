# -*- coding: utf-8 -*-
MODUL_ADI = "kesif"; KATEGORI = "kesif"
async def osint_hedef_listesi():
    return ["http://example.com", "http://testphp.vulnweb.com"]
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    db_yaz(hedef, MODUL_ADI, KATEGORI, "Hedef listeye alindi", "", "bilgi")
    await ws.yayinla({"tip": "bulgu", "hedef": hedef, "modul": MODUL_ADI, "bulgu": "listeye alindi"})
