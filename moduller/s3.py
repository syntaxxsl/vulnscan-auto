# -*- coding: utf-8 -*-
MODUL_ADI = "s3"; KATEGORI = "bulut"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    host = hedef.replace("http://","").replace("https://","").split("/")[0].replace(".", "-")
    url = f"https://{host}.s3.amazonaws.com/"
    try:
        async with session.get(url, timeout=5) as r:
            if r.status in (200, 403) and "ListBucketResult" in await r.text():
                db_yaz(hedef, MODUL_ADI, KATEGORI, f"Acik S3 Bucket: {url}", "", "kritik")
                await ws.yayinla({"tip":"bulgu","hedef":hedef,"modul":MODUL_ADI,"bulgu":"S3"})
    except: pass
