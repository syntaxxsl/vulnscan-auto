# -*- coding: utf-8 -*-
import asyncio
MODUL_ADI = "konteyner"; KATEGORI = "bulut"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    host = hedef.replace("http://","").replace("https://","").split("/")[0]
    for p, ad in [(2375,"Docker API"),(6443,"K8s API"),(10250,"Kubelet")]:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=3)
            db_yaz(hedef, MODUL_ADI, KATEGORI, f"Acik {ad} portu: {p}", "", "kritik")
            await ws.yayinla({"tip":"bulgu","hedef":hedef,"modul":MODUL_ADI,"bulgu":ad})
            w.close(); await w.wait_closed()
        except: pass
