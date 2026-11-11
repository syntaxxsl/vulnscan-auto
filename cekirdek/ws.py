# -*- coding: utf-8 -*-
from typing import List
from fastapi import WebSocket
class WSManager:
    def __init__(self): self.baglantilar: List[WebSocket] = []
    async def bagla(self, ws: WebSocket):
        await ws.accept(); self.baglantilar.append(ws)
    def ayir(self, ws: WebSocket):
        if ws in self.baglantilar: self.baglantilar.remove(ws)
    async def yayinla(self, mesaj: dict):
        for ws in list(self.baglantilar):
            try: await ws.send_json(mesaj)
            except: self.ayir(ws)
ws_manager = WSManager()
