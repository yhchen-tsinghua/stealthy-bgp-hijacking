#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import requests
import pandas as pd
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib 

date = datetime.now().strftime("%Y%m%d")
script_dir = Path(__file__).resolve().parent
list_dir = script_dir/f"rov_list_{date}"
list_dir.mkdir(parents=True, exist_ok=True)

def rovista(outpath):
    r = requests.get("https://api.rovista.netsecurelab.org/rovista/api/overview?offset=0&count=100000&sortBy=rank&sortOrder=asc", timeout=60)

    if r.status_code != 200:
        print(f"Failed to fetch RoVista: status code {r.status_code}")
        return

    r = r.json()
    data = r["data"]
    df = pd.DataFrame.from_records(data)
    df.to_csv(outpath, index=False)
    print(df)
    return outpath

def cloudflare(outpath):
    r = requests.get("https://raw.githubusercontent.com/cloudflare/isbgpsafeyet.com/master/data/operators.csv", timeout=60)

    if r.status_code != 200:
        print(f"Failed to fetch Cloudflare: status code {r.status_code}")
        return

    open(outpath, "w").write(r.text)
    return outpath

def apnic(outpath):
    # https://blog.apnic.net/2020/06/22/a-new-way-to-measure-route-origin-validation/
    # https://blog.apnic.net/2021/03/24/measuring-roas-and-rov/
    r = requests.get("https://stats.labs.apnic.net/rpki", timeout=60)

    if r.status_code != 200:
        print(f"Failed to fetch APNIC: status code {r.status_code}")
        return

    def get_country_code(line):
        match = re.search(r"<a href=.*?>(.*?)</a>", line)
        if match:
            return match[1]

    text = r.text
    match = re.search(r"\['CC',\s?'Country',\s?'I-RoV Filtering',\s?'Samples',\s?'Weight',\s?'Weighted Samples'\]", text)
    start_idx = match.span()[0]
    lines = [i.strip() for i in text[start_idx:].split("\n") if i and i[0] == "[" and (i[-1] == "," or i[-1] == "]")]
    CCs = list(filter(lambda x:x, map(get_country_code, lines)))

    def get_country_ASes(cc):
        r = requests.get(f"https://stats.labs.apnic.net/rpki/{cc}", timeout=60)

        if r.status_code != 200:
            print(f"Failed to fetch {cc}: status code {r.status_code}")
            return []

        text = r.text
        start_idx = text.find("['ASN', 'AS Name', 'RPKI Validates', 'Samples']")

        results = []
        for line in text[start_idx:].split("\n"):
            if ";" in line: break
            pattern = r"""\["<a href=.*>AS(?P<asn>\d+?)</a>","(?P<as_name>.*?)",(?P<ratio>.*?),(?P<samples>\d+?)\]"""
            match = re.search(pattern, line)
            if match:
                if match.group("ratio") == '""':
                    ratio = 0.
                else:
                    ratio = float(re.search(r"\{v: (.*?), f:'.*?'\}",
                                match.group("ratio"))[1])
                samples = int(match.group("samples"))
                results.append([cc, match.group("asn"),
                        match.group("as_name"), ratio, samples])
        return results

    with ThreadPoolExecutor(max_workers=48) as executor:
        result = [j for i in executor.map(get_country_ASes, CCs) for j in i]

    df = pd.DataFrame(result, columns=["cc", "asn", "as_name", "rov_filtering_ratio", "samples"])
    print(df)
    df.to_csv(outpath, index=False)
    return outpath

if __name__ == "__main__":
    p1 = rovista(list_dir/"rovista.csv")
    p2 = cloudflare(list_dir/"cloudflare.csv")
    p3 = apnic(list_dir/"apnic.csv")

    h = hashlib.md5()
    for fn in [p1, p2, p3]:
        h.update(fn.read_bytes())
    digest = h.hexdigest()
    print(digest)
    open(list_dir/"checksum.md5", "w").write(digest+"\n")
