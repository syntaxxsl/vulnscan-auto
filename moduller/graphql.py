# -*- coding: utf-8 -*-
MODUL_ADI = "graphql"; KATEGORI = "web"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    url = hedef.rstrip("/") + "/graphql"
    try:
        async with session.post(url, json={"query":"{__schema{types{name}}}"}, timeout=5) as r:
            t = await r.text()
            if "__schema" in t:
                db_yaz(hedef, MODUL_ADI, KATEGORI, "GraphQL introspection acik", url, "orta")
    except: pass
