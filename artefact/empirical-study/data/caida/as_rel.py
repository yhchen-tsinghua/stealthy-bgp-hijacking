#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from pathlib import Path
import requests
import bz2

SCRIPT_DIR = Path(__file__).resolve().parent

SERIAL_1_DIR = SCRIPT_DIR / "serial-1"
SERIAL_1_DIR.mkdir(exist_ok=True, parents=True)
SERIAL_2_DIR = SCRIPT_DIR / "serial-2"
SERIAL_2_DIR.mkdir(exist_ok=True, parents=True)

def get(serial, time):
    if serial == "1":
        fname = f"{time}.as-rel.txt.bz2"
        url = f"https://publicdata.caida.org/datasets/as-relationships/serial-1/{fname}"
        out_txt = SERIAL_1_DIR / fname[:-4]
    elif serial == "2":
        fname = f"{time}.as-rel2.txt.bz2"
        url = f"https://publicdata.caida.org/datasets/as-relationships/serial-2/{fname}"
        out_txt = SERIAL_2_DIR / fname[:-4]
    else:
        raise RuntimeError("bad argument")
    if out_txt.with_suffix("").exists():
        return out_txt
    response = requests.get(url)
    response.raise_for_status()
    decompressed_data = bz2.decompress(response.content)
    out_txt.write_bytes(decompressed_data)
    return out_txt
