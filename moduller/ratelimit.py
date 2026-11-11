# -*- coding: utf-8 -*-
import asyncio
MODUL_ADI = "ratelimit"; KATEGORI = "web"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    kodlar = []
    for _ in range(10):
        try:
            async with session.get(hedef, timeout=3) as r:
                kodlar.append(r.status)
        except: kodlar.append(0)
    if 429 not in kodlar:
        db_yaz(hedef, MODUL_ADI, KATEGORI, "Rate limit yok (10 istek engellenmedi)", str(kodlar), "orta")
