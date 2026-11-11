# -*- coding: utf-8 -*-
import re
MODUL_ADI = "yara"; KATEGORI = "analiz"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, timeout=5) as r:
            t = await r.text()
            if re.search(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', t):
                db_yaz(hedef, MODUL_ADI, KATEGORI, "Kredi karti sizintisi (regex)", "", "yuksek")
            if re.search(r'\b\d{11}\b', t):
                db_yaz(hedef, MODUL_ADI, KATEGORI, "TCKN sizintisi (regex)", "", "yuksek")
    except: pass
