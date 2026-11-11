# -*- coding: utf-8 -*-
import os
MODUL_ADI = "llm"; KATEGORI = "ai"
async def calistir(hedef, session, ws):
    from cekirdek.db import db_yaz
    key = os.environ.get("OPENAI_KEY","")
    if not key: return
    try:
        async with session.post("https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={"model":"gpt-4o-mini","messages":[{"role":"user","content":f"{hedef} icin 2 adet XSS payload oner"}]},
            timeout=15) as r:
            d = await r.json()
            db_yaz(hedef, MODUL_ADI, KATEGORI, "AI payload onerisi", d["choices"][0]["message"]["content"], "bilgi")
    except: pass
