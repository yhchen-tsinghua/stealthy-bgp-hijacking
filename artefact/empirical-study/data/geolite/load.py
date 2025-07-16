#!/usr/bin/env python
#-*- coding: utf-8 -*-

import pandas as pd
import numpy as np
from pathlib import Path
import pickle

script_dir = Path(__file__).resolve().parent
cache_dir = script_dir/"cache"
cache_dir.mkdir(parents=True, exist_ok=True)

def _load_asn2geoloc_(date):
    ip2geoloc = {}

    def update_ip2geoloc(df):
        for ip, lat, lon in df[["network", "latitude", "longitude"]].values:
            if ip not in ip2geoloc:
                ip2geoloc[ip] = [(lat, lon)]
            else:
                ip2geoloc[ip].append((lat, lon))

    update_ip2geoloc(pd.read_csv(script_dir/f"GeoLite2-City-CSV_{date}"/"GeoLite2-City-Blocks-IPv4.csv",
                                dtype={"network": str, "latitude": np.float64, "longitude": np.float64},
                                low_memory=False))
    update_ip2geoloc(pd.read_csv(script_dir/f"GeoLite2-City-CSV_{date}"/"GeoLite2-City-Blocks-IPv6.csv",
                                dtype={"network": str, "latitude": np.float64, "longitude": np.float64},
                                low_memory=False))

    asn2geoloc = {}

    def update_asn2geoloc(df):
        for ip, asn in df[["network", "autonomous_system_number"]].values:
            if ip not in ip2geoloc:
                continue
            if asn not in asn2geoloc:
                asn2geoloc[asn] = ip2geoloc[ip]
            else:
                asn2geoloc[asn] += ip2geoloc[ip]

    update_asn2geoloc(pd.read_csv(script_dir/f"GeoLite2-ASN-CSV_{date}"/"GeoLite2-ASN-Blocks-IPv4.csv",
                                dtype={"network": str, "autonomous_system_number": str}))
    update_asn2geoloc(pd.read_csv(script_dir/f"GeoLite2-ASN-CSV_{date}"/"GeoLite2-ASN-Blocks-IPv6.csv",
                                dtype={"network": str, "autonomous_system_number": str}))

    return asn2geoloc

def load_asn2geoloc(date):
    cache_file = cache_dir/f"asn2geoloc.{date}.cache"
    if cache_file.exists():
        ret = pickle.load(open(cache_file, "rb"))
    else:
        ret = _load_asn2geoloc_(date)
        pickle.dump(ret, open(cache_file, "wb"))
    return ret
