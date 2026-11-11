# -*- coding: utf-8 -*-
MODUL_ADI = "waf"; KATEGORI = "web"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, timeout=5) as r:
            h = {k.lower():v for k,v in r.headers.items()}
            if "server" in h and any(x in h["server"].lower() for x in ["cloudflare","akamai","modsecurity"]):
                db_yaz(hedef, MODUL_ADI, KATEGORI, f"WAF tespit: {h['server']}", "", "bilgi")
                await ws.yayinla({"tip":"bulgu","hedef":hedef,"modul":MODUL_ADI,"bulgu":"WAF"})
    except: pass
