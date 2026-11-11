# -*- coding: utf-8 -*-
MODUL_ADI = "hibp"; KATEGORI = "kesif"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    domain = hedef.replace("http://","").replace("https://","").split("/")[0]
    try:
        async with session.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{domain}",
            headers={"User-Agent":"Tarayici"}, timeout=10) as r:
            if r.status == 200:
                db_yaz(hedef, MODUL_ADI, KATEGORI, f"Email sizintisi: {domain}", "", "yuksek")
    except: pass
