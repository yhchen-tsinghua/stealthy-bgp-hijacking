#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from pathlib import Path
from urllib.parse import urljoin, urlparse
from functools import cache
import shutil
import numpy as np
import requests
import subprocess
import bz2
import re

SCRIPT_DIR = Path(__file__).resolve().parent

@cache
def get_all_collectors(url_index="http://routeviews.org/"):
    response = requests.get(url_index)
    response.raise_for_status()
    res = re.sub(r"\s\s+", " ", response.text.replace("\n", " "))
    collectors2url = {}
    for a, b in re.findall(r'\<A HREF="(.+?)"\>.+?\([\w\s]+, from (.+?)\)', res):
        collector_name = b.split(".")[-3]
        if collector_name in collectors2url:
            idx = 2
            while f"{collector_name}{idx}" in collectors2url:
                idx += 1
            collector_name = f"{collector_name}{idx}"
        if a[-7:] != "bgpdata":
            collectors2url[collector_name] = urljoin(url_index, f"{a}/bgpdata") + "/"
        else:
            collectors2url[collector_name] = urljoin(url_index, a) + "/"

    return collectors2url

def get_recent_archive(collector, collectors2url, year, month, day, hour, minute):
    assert collector in collectors2url

    def pull_list():
        target_url = urljoin(collectors2url[collector], f"{ym}{subdir}") + "/"
        response = requests.get(target_url)
        response.raise_for_status()
        archive_list = re.findall(
            r'\<a href="(.+?(\d{4}).??(\d{2}).??(\d{2}).??(\d{4}).*?\.bz2)"\>', response.text)
        return target_url, archive_list

    ym = f"{year}.{month:02d}"
    subdir = "/RIBS"
    target_url, archive_list = pull_list()

    if not archive_list:
        subdir = ""
        target_url, archive_list = pull_list()
    assert archive_list
    
    time_list = ["".join(i[1:]) for i in archive_list]
    t = f"{year}{month:02d}{day:02d}{hour:02d}{minute:02d}"
    idx = np.searchsorted(time_list, t)

    if idx == 0:
        ym = f"{year}.{int(month)-1:02d}" if month > 1 else f"{int(year)-1}.12"
        target_url, archive_list = pull_list()
        assert archive_list
        archive = urljoin(target_url, archive_list[-1][0])
        stime = list(map(int, [*archive_list[-1][1:-1],
                archive_list[-1][-1][:2], archive_list[-1][-1][2:]]))
        return archive, stime

    archive = urljoin(target_url, archive_list[idx-1][0])
    stime = list(map(int, [*archive_list[idx-1][1:-1],
            archive_list[idx-1][-1][:2], archive_list[idx-1][-1][2:]]))
    return archive, stime

def download_data(url, collector):
    fpath = Path(urlparse(url).path)
    assert fpath.name.endswith(".bz2")
    outpath = SCRIPT_DIR / "ribs" / collector / fpath.stem
    if outpath.exists():
        return outpath
    outpath.parent.mkdir(exist_ok=True, parents=True)
    with requests.get(url, stream=True) as response:
        response.raise_for_status()
        with bz2.open(response.raw, "rb") as bz2_file:
            with open(outpath, "wb") as out_file:
                shutil.copyfileobj(bz2_file, out_file)
    print(f"get ribs for {collector} {outpath.name}")
    return outpath

@cache
def field_selector(fields):
    fmt = "type|timestamp|A/W|peer-ip|peer-asn|prefix|as-path|origin-protocol|next-hop|"\
          "local-pref|MED|community|atomic-agg|aggregator|unknown-field-1|unknown-field-2"
    fmt = fmt.split("|")
    field2idx = dict(zip(fmt, range(len(fmt))))
    indices = [field2idx[f] for f in fields]
    def select(values):
        return [values[i] for i in indices]
    return select

def rib_loader(fpath, fields):
    select = field_selector(fields)
    def line_generator():
        process = subprocess.Popen(
            ["bgpdump", "-q", "-m", "-u", str(fpath)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,  # Automatically decode bytes to str
            bufsize=1   # Line-buffered (only usable if text=True)
        )
        idx = 0
        try:
            for line in process.stdout:
                yield idx, select(line.strip("\n").split("|"))
                idx += 1
        finally:
            process.stdout.close()
            process.terminate()
            process.wait()
    return line_generator
