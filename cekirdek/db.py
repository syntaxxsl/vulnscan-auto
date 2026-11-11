# -*- coding: utf-8 -*-
import sqlite3, time, os
DB = os.environ.get("DB_PATH", "tarama.db")
def db_init():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS sonuclar(
        id INTEGER PRIMARY KEY AUTOINCREMENT, hedef TEXT, modul TEXT, kategori TEXT,
        bulgu TEXT, kanit TEXT, onem TEXT, zaman TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, islem TEXT, detay TEXT, zaman TEXT)""")
    con.commit(); con.close()
def db_yaz(hedef, modul, kategori, bulgu, kanit="", onem="orta"):
    con = sqlite3.connect(DB)
    con.execute("INSERT INTO sonuclar(hedef,modul,kategori,bulgu,kanit,onem,zaman) VALUES(?,?,?,?,?,?,?)",
                (hedef, modul, kategori, bulgu, kanit, onem, time.strftime("%Y-%m-%d %H:%M:%S")))
    con.commit(); con.close()
def db_audit_yaz(islem, detay):
    con = sqlite3.connect(DB)
    con.execute("INSERT INTO audit(islem,detay,zaman) VALUES(?,?,?)", (islem, detay, time.strftime("%Y-%m-%d %H:%M:%S")))
    con.commit(); con.close()
def db_rapor():
    con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM sonuclar ORDER BY id DESC").fetchall()
    con.close(); return [dict(r) for r in rows]
def db_audit():
    con = sqlite3.connect(DB); con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM audit ORDER BY id DESC").fetchall()
    con.close(); return [dict(r) for r in rows]
