# -*- coding: utf-8 -*-
import importlib, pkgutil
MODULLER = {}
def modulleri_yukle():
    import moduller
    for _, ad, _ in pkgutil.iter_modules(moduller.__path__):
        try:
            m = importlib.import_module(f"moduller.{ad}")
            if hasattr(m, "calistir") and hasattr(m, "MODUL_ADI"):
                MODULLER[m.MODUL_ADI] = m
        except Exception as e:
            print(f"[KAYIT HATASI] {ad}: {e}")
modulleri_yukle()
