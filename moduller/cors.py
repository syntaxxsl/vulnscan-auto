# -*- coding: utf-8 -*-
MODUL_ADI = "cors"; KATEGORI = "web"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, headers={"Origin":"https://evil.com"}, timeout=5) as r:
            acao = r.headers.get("Access-Control-Allow-Origin","")
            if acao == "*" or "evil.com" in acao:
                db_yaz(hedef, MODUL_ADI, KATEGORI, "CORS yanlis yapilandirmasi", acao, "yuksek")
    except: pass
