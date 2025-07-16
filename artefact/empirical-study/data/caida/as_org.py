#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from pathlib import Path
import requests
import gzip

OUTPUT_DIR = Path(__file__).resolve().parent / "orgs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def get(time):
    fname = f"{time}.as-org2info.txt.gz"
    url = f"https://publicdata.caida.org/datasets/as-organizations/{fname}"
    out_txt = OUTPUT_DIR / fname[:-3]
    if out_txt.exists():
        return out_txt
    response = requests.get(url)
    response.raise_for_status()
    decompressed_data = gzip.decompress(response.content)
    out_txt.write_bytes(decompressed_data)
    return out_txt

def load(time):
    fname = f"{time}.as-org2info.txt"
    lines = open(OUTPUT_DIR/fname, "r").readlines()
    field1 = "aut|changed|aut_name|org_id|opaque_id|source".split("|")
    field2 = "org_id|changed|name|country|source".split("|")
    as_info = {}
    org_info = {}
    for l in lines:
        if l[0] == "#": continue
        values = l.strip().split("|")
        if len(values) == len(field1):
            assert values[0] not in as_info, values[0]
            as_info[values[0]] = dict(zip(field1[1:], values[1:]))
        if len(values) == len(field2):
            assert values[0] not in org_info, values[0]
            org_info[values[0]] = dict(zip(field2[1:], values[1:]))
    return as_info, org_info
