# -*- coding: utf-8 -*-
import ssl, socket
MODUL_ADI = "tls"; KATEGORI = "ag"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    if not hedef.startswith("https"): return
    host = hedef.replace("https://","").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                db_yaz(hedef, MODUL_ADI, KATEGORI, f"Sertifika gecerli: {cert.get('subject')}", "", "bilgi")
    except Exception as e:
        db_yaz(hedef, MODUL_ADI, KATEGORI, f"TLS hatasi: {e}", "", "orta")
