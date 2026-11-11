# -*- coding: utf-8 -*-
import os
MODUL_ADI = "bildirim"; KATEGORI = "operasyon"

async def calistir(hedef, session, ws):
    token = os.environ.get("TG_TOKEN", "")
    kisisel = os.environ.get("TG_CHAT", "")
    grup = os.environ.get("TG_GROUP_CHAT", "")
    
    hedefler = [c for c in [kisisel, grup] if c]
    if not token or not hedefler:
        return
        
    metin = f"Tarama tamamlandi: {hedef}"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    for chat_id in hedefler:
        try:
            await session.post(url, json={"chat_id": chat_id, "text": metin}, timeout=5)
        except:
            pass
