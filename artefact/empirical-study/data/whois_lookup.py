#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import subprocess
from datetime import datetime
from pathlib import Path
from functools import lru_cache

script_dir = Path(__file__).resolve().parent
cache_dir = script_dir/"whois_cache"
cache_dir.mkdir(parents=True, exist_ok=True)

@lru_cache(maxsize=128)
def whois_lookup(target, cache_date=datetime.now().strftime("%Y-%m-%d")):
    cache_file = cache_dir/f"{target.replace('/', '_')}.{cache_date}.txt"
    if cache_file.exists():
        with cache_file.open("r", encoding="utf-8") as f:
            content = f.read()
    else:
        try:
            result = subprocess.run(["whois", target],
                        text=True, capture_output=True, check=True)
            content = result.stdout
            with cache_file.open("w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            content = ""
    return content
