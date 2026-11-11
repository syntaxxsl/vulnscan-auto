# -*- coding: utf-8 -*-
import asyncio, aiohttp, random, os
from cekirdek.kayit import MODULLER
from cekirdek.ws import ws_manager
from cekirdek.db import db_audit_yaz
from moduller.kesif import osint_hedef_listesi
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (X11; Linux x86_64)"]
class Motor:
    _iptal = False
    @classmethod
    def iptal_et(cls): cls._iptal = True
    async def calistir(self, hedefler=None):
        Motor._iptal = False
        if not hedefler: hedefler = await osint_hedef_listesi()
        sem = asyncio.Semaphore(20)
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        proxy = os.environ.get("TOR_PROXY") or (os.environ.get("PROXY","").split(",")[0] if os.environ.get("PROXY") else None)
        async with aiohttp.ClientSession(headers=headers) as session:
            for hedef in hedefler:
                if Motor._iptal: break
                db_audit_yaz("tarama_baslat", hedef)
                await ws_manager.yayinla({"tip": "log", "mesaj": f"Taranıyor: {hedef}"})
                gorevler = [self._modul_calistir(m, hedef, session, sem) for m in MODULLER.values()]
                await asyncio.gather(*gorevler, return_exceptions=True)
                db_audit_yaz("tarama_bitti", hedef)
                await ws_manager.yayinla({"tip": "tamam", "hedef": hedef})
    async def _modul_calistir(self, modul, hedef, session, sem):
        async with sem:
            try:
                await asyncio.wait_for(modul.calistir(hedef, session, ws_manager), timeout=30)
            except asyncio.TimeoutError:
                await ws_manager.yayinla({"tip": "log", "mesaj": f"Zaman aşımı: {modul.MODUL_ADI} -> {hedef}"})
            except Exception as e:
                await ws_manager.yayinla({"tip": "log", "mesaj": f"Hata: {modul.MODUL_ADI} -> {e}"})
