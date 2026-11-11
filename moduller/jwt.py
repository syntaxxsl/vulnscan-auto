# -*- coding: utf-8 -*-
import base64, json
MODUL_ADI = "jwt"; KATEGORI = "kimlik"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    try:
        async with session.get(hedef, timeout=5) as r:
            for c in r.cookies:
                if c.value.count(".") == 2:
                    p = c.value.split(".")[1]; p += "=" * (-len(p) % 4)
                    try:
                        data = json.loads(base64.urlsafe_b64decode(p))
                        if data.get("alg") == "none":
                            db_yaz(hedef, MODUL_ADI, KATEGORI, "JWT none algoritmasi", c.key, "kritik")
                    except: pass
    except: pass
