# -*- coding: utf-8 -*-
MODUL_ADI = "dlp"; KATEGORI = "analiz"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, timeout=5) as r:
            t = await r.text()
            if "BEGIN RSA PRIVATE KEY" in t:
                db_yaz(hedef, MODUL_ADI, KATEGORI, "Ozel anahtar sizintisi", "", "kritik")
            if "AIza" in t and len(t) < 500000:
                db_yaz(hedef, MODUL_ADI, KATEGORI, "Google API anahtari olabilir", "", "orta")
    except: pass
