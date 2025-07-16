#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from pathlib import Path
from ipaddress import ip_network
from collections import UserDict, Counter
from itertools import product, count
from functools import lru_cache
from rapidfuzz import fuzz
from datetime import datetime
import pandas as pd
import numpy as np
import re
import click
import json
import pickle
import lz4.frame

from data.routeviews.get_ribs import get_all_collectors, get_recent_archive, download_data, rib_loader
from data.caida.as_org import get as _get_orgs, load as _load_orgs
from data.caida.as_rel import get as _get_rels

from data.rpki_validator import RPKI
from data.irr_validator import RADB
from data.whois_lookup import whois_lookup

script_dir = Path(__file__).resolve().parent
result_dir = script_dir/"result"
result_dir.mkdir(exist_ok=True, parents=True)
cache_dir = script_dir/".cache"
cache_dir.mkdir(exist_ok=True, parents=True)

g_disk_cache = False

# use after pre-loading
g_collector2rib = dict()
g_as_info = dict()
g_org_info = dict()
g_ngbr_info = dict()

g_rpki = None
g_radb = None

g_routine_sig = None
g_time_sig = None
g_collector_sig = None

g_initial_incident_id = 0

g_analyzer = None

class RecursiveDict(UserDict):
    def __getitem__(self, key):
        if "/" in key:
            first, rest = key.split("/", 1)
            return self.data.setdefault(first, RecursiveDict())[rest]
        return self.data[key]

    def __setitem__(self, key, value):
        if "/" in key:
            first, rest = key.split("/", 1)
            self.data.setdefault(first, RecursiveDict())[rest] = value
        else:
            self.data[key] = value

    def __contains__(self, key):
        if "/" in key:
            first, rest = key.split("/", 1)
            return first in self.data and rest in self.data[first]
        return key in self.data

    def to_dict(self):
        """Convert RecursiveDict to a native dictionary."""
        def convert(value):
            if isinstance(value, RecursiveDict):
                return value.to_dict()
            return value
        return {key: convert(val) for key, val in self.data.items()}

    @classmethod
    def from_dict(cls, d):
        """Create a RecursiveDict from a native dictionary."""
        def convert(value):
            if isinstance(value, dict):
                return cls.from_dict(value)
            return value
        rd = cls()
        for key, val in d.items():
            rd[key] = convert(val)
        return rd

    # Example usage
    # D = RecursiveDict()
    # D["A/B/C"] = 42
    # print(D["A/B/C"])  # Output: 42
    # print(D["A"]["B"]["C"])  # Output: 42
    # print("A/B/C" in D)  # Output: True
    # print("A/B" in D)    # Output: True
    # print("A/D" in D)    # Output: False

def lz4load(fpath):
    return pickle.load(lz4.frame.open(fpath, "rb"))

def lz4dump(obj, fpath):
    pickle.dump(obj, lz4.frame.open(fpath, "wb"), protocol=4)

non_critical_snippets = [r'tele(com|communication|service)?s?', r'communications?', r'networks?', r'systems?', r'solutions?', r'technolog(y|ies)', r'digitals?', r'internet', r'online', r'media', r'data', r'services?', r'clouds?', r'corp(oration)?', r'inc(orporated)?', r'llc', r'l(td|imited)?', r'pvt', r'joint stock', r'bank', r'university', r'department', r'ministry', r'board', r'company', r'co', r'center', r'institutes?', r'groups?', r'organizations?', r'cooperative', r'councils?', r'academy', r'college', r'government', r'associations?', r'department', r'laboratory', r'sa', r'ag', r'nv', r'gmbh', r'ltee', r'bv', r'sia']

def clean_org_name(org_name):
    clean_name = re.sub(r'[^\w\s]', '', org_name.lower())
    for snippet in non_critical_snippets:
        clean_name = re.sub(rf'\b{snippet}\b', '', clean_name)
    clean_name = re.sub(r'\s+', ' ', clean_name).strip()
    return clean_name

def pre_loading(collectors, year, month, day, hour, initial_incident_id):
    global g_time_sig, g_collector_sig, g_routine_sig

    g_time_sig = f"{year:04d}{month:02d}{day:02d}.{hour:02d}00"
    g_collector_sig = "_".join(sorted(collectors))
    g_routine_sig = f"{g_time_sig}.{g_collector_sig}"

    print(f"Pre-loading {g_routine_sig}")

    # RIBs
    for collector in collectors:
        data, _ = get_recent_archive(collector, get_all_collectors(),
                                            year, month, day, hour, minute=1)
        fpath = download_data(data, collector)
        assert f"rib.{g_time_sig}" == fpath.name, f"{g_time_sig} {fpath}"
        g_collector2rib[collector] = rib_loader(fpath, fields=("prefix", "as-path"))
    print("RIB loader initialized")

    # AS Organizations
    try:
        _year, _month = year, month
        _get_orgs(f"{_year:04d}{_month:02d}01")
    except:
        _year = year+(month-2)//12
        _month = (month-2)%12+1
        _get_orgs(f"{_year:04d}{_month:02d}01")

    _as_info, _org_info = _load_orgs(f"{_year:04d}{_month:02d}01")
    g_as_info.update(_as_info)
    g_org_info.update(_org_info)
    print("Orgs loaded")

    # AS Relationships
    try:
        _year, _month = year, month
        as_rel_fpath = _get_rels(serial="2", time=f"{_year:04d}{_month:02d}01")
    except:
        _year = year+(month-2)//12
        _month = (month-2)%12+1
        as_rel_fpath = _get_rels(serial="2", time=f"{_year:04d}{_month:02d}01")

    for l in open(as_rel_fpath, "r").readlines():
        if l[0] == "#": continue
        a, b, rel = l.strip().split("|")[:3]
        if a not in g_ngbr_info: g_ngbr_info[a] = {-1:set(), 0:set(), 1:set()}
        if b not in g_ngbr_info: g_ngbr_info[b] = {-1:set(), 0:set(), 1:set()}
        g_ngbr_info[a][+int(rel)].add(b)
        g_ngbr_info[b][-int(rel)].add(a)
    print("Rels loaded")

    # RPKI
    global g_rpki
    g_rpki = RPKI().load_data(year, month, day)
    print("RPKI loaded")

    # RADB
    global g_radb
    g_radb = RADB().load_data(year, month, day)
    print("RADB loaded")

    # initial incident ID
    global g_initial_incident_id
    g_initial_incident_id = initial_incident_id

class PrefixOriginView:
    class PrefixNode:
        def __init__(self):
            self.left       = None
            self.right      = None
            self.view       = dict()
            self.refs       = dict()

        def get_left(self):
            if self.left is None:
                self.left = PrefixOriginView.PrefixNode()
            return self.left

        def get_right(self):
            if self.right is None:
                self.right = PrefixOriginView.PrefixNode()
            return self.right

        def add_view(self, origin, vp, ref):
            # In {vp}'s view, the current prefix
            # is originated from the AS {origin}
            # according to the {ref} announcement
            if origin in self.view:
                self.view[origin].add(vp)
            else: self.view[origin] = {vp}

            if (origin, vp) in self.refs:
                self.refs[origin, vp].append(ref)
            else: self.refs[origin, vp] = [ref] 

    def __init__(self):
        self.root = PrefixOriginView.PrefixNode()

    @staticmethod
    def prefix_to_dirs(prefix_str):
        prefix = ip_network(prefix_str)
        if prefix.version == 6: return None
        prefixlen = prefix.prefixlen
        prefix = int(prefix[0]) >> (32-prefixlen)
        directions = [(prefix>>shift)&1
                        for shift in range(prefixlen-1, -1, -1)]
        return directions

    @staticmethod
    def dirs_to_prefix(directions):
        prefix = 0
        superlen = 32-len(directions)
        for left in directions:
            prefix = (prefix<<1)|int(left)
        prefix = ip_network(prefix<<superlen).supernet(superlen)
        return prefix

    def create_node(self, directions):
        n = self.root
        for left in directions:
            if left: n = n.get_left()
            else: n = n.get_right()
        return n

    def find_node(self, directions):
        n = self.root
        for left in directions:
            if n is None: break
            if left: n = n.get_left()
            else: n = n.get_right()
        return n

    def update_view(self, directions, vp, origin, ref):
        if not directions: return
        self.create_node(directions).add_view(origin, vp, ref)

    def get_view(self, prefix_str):
        directions = self.prefix_to_dirs(prefix_str)
        if not directions: return
        n = self.find_node(directions)
        if n is None: return
        return n.view

    def iter_subtree(self, directions):
        n = self.find_node(directions)
        if n is None: return
        queue = [[directions, n]]
        while queue:
            dirs, node = queue.pop(0)
            if node.view:
                yield dirs, node
            if node.left:
                queue.append([dirs+[True], node.left])
            if node.right:
                queue.append([dirs+[False], node.right])

class Analyzer:
    def __init__(self):
        self.as_views = dict()

    def update_route(self, prefix_str, aspath_str, ref):
        if prefix_str[-2:] == "/0": return

        directions = PrefixOriginView.prefix_to_dirs(prefix_str)

        if not directions: return

        aspath_lst = aspath_str.split(" ")
        vp, origin = aspath_lst[0], aspath_lst[-1]

        for i, asn in enumerate(aspath_lst):
            if i > 0 and asn == aspath_lst[i-1]: # skip prepended AS
                continue
            if asn not in self.as_views:
                self.as_views[asn] = PrefixOriginView()
            # {asn} should forward traffic to {origin}, thinks {vp}
            self.as_views[asn].update_view(directions, vp, origin, ref)

    def update_rib(self, collector):
        for i, (prefix_str, aspath_str) in g_collector2rib[collector]():
            self.update_route(prefix_str, aspath_str, ref=f"{collector}.{i}")
        return self

    def check_route(self, prefix_str, aspath_str, ref):
        if prefix_str[-2:] == "/0": return

        directions = PrefixOriginView.prefix_to_dirs(prefix_str)

        if not directions: return

        aspath_lst = aspath_str.split(" ")
        vp, origin = aspath_lst[0], aspath_lst[-1]

        # any origin outside {set_expected} indicates a potential collision
        # {set_expected} includes all origins of {vp} and the ASes on the path
        set_expected = set([o for _, n in self.as_views[vp].iter_subtree(directions)
                                for o in n.view.keys()] + aspath_lst)

        for start_idx, asn in enumerate(aspath_lst):
            if asn != vp: break
        for end_idx, asn in zip(range(len(aspath_lst)-1, -1, -1), aspath_lst[::-1]):
            if asn != origin: break

        # find a risk-critical AS
        for i, asn in enumerate(aspath_lst[start_idx:end_idx+1], start=start_idx):
            if asn == aspath_lst[i-1]: # skip prepended AS
                continue
            for dirs, node in self.as_views[asn].iter_subtree(directions):
                for other_origin in node.view:
                    if other_origin not in set_expected:
                        colli_vp = sorted(node.view[other_origin])
                        colli_ref = ["|".join(node.refs[other_origin, cvp])
                                        for cvp in colli_vp]
                        colli_prefix = str(PrefixOriginView.dirs_to_prefix(dirs))
                        return {
                            "prefix": prefix_str,
                            "aspath": aspath_str,
                            "ref" : ref,
                            "colli_prefix": colli_prefix,
                            "colli_origin": other_origin,
                            "colli_as": asn,
                            "colli_vp": ";".join(colli_vp),
                            "colli_ref": ";".join(colli_ref),
                        } # This follows the loose heuristics, meaning that
                          # we just saw {prefix} with {aspath} according to
                          # route {ref}. Yet {colli_prefix}, be it exactly
                          # {prefix} or a sub-prefix, has been seen in many
                          # routes, i.e., {colli_ref}, that indicate it is
                          # originated by an origin AS that has never been
                          # seen as an origin of {perfix} or any sub-perfix
                          # by the current VP, i.e., {aspaht[0]}, and these
                          # routes are forwarded by {colli_as} until reach-
                          # ing {colli_vp}

    def check_rib(self, collector):
        for i, (prefix_str, aspath_str) in g_collector2rib[collector]():
            risk = self.check_route(prefix_str, aspath_str, ref=f"{collector}.{i}")
            if risk is not None:
                yield risk

def discover_risk_instances():
    global g_analyzer

    def construct_views(cache_path):
        print("start constructing views")
        analyzer = Analyzer()

        for collector in g_collector2rib:
            analyzer.update_rib(collector)
            print(f"{collector} finished")

        if g_disk_cache: lz4dump(analyzer, cache_path)
        return analyzer

    views_cache = cache_dir/f"{g_routine_sig}.as_views.lz4"
    if views_cache.exists():
        g_analyzer = lz4load(views_cache)
    else:
        g_analyzer = construct_views(views_cache)

    print("start discovering risks")
    for collector in g_collector2rib:
        for risk in g_analyzer.check_rib(collector):
            yield risk
        print(f"{collector} finished")

def risk_analysis(risk_iter):
    def is_same_org(asn0, asn1):
        asn0 = asn0.strip("{}").split(",")[0]
        asn1 = asn1.strip("{}").split(",")[0]
        if asn0 in g_as_info and asn1 in g_as_info:
            id_key = "opaque_id" if g_as_info[asn0]["opaque_id"] else "org_id"
            if g_as_info[asn0][id_key] == g_as_info[asn1][id_key]:
                return f"{id_key}:{g_as_info[asn1][id_key]}"
        return None

    def find_same_org(target, aspath_lst):
        same_orgs = []
        same_org_id = None
        for i, asn in enumerate(aspath_lst):
            if i > 0 and asn == aspath_lst[i-1]:
                continue
            org_id = is_same_org(asn, target)
            if org_id is not None:
                same_orgs.append(asn)
                same_org_id = org_id
        return same_orgs, same_org_id

    def find_as_rel(asn0, asn1):
        if asn0 in g_ngbr_info:
            for rel, ngbrs in g_ngbr_info[asn0].items():
                if asn1 in ngbrs: return rel
        return None
                
    for risk in risk_iter:
        prefix = risk["prefix"]
        aspath = risk["aspath"].split(" ")
        vp, origin = aspath[0], aspath[-1]

        colli_prefix = risk["colli_prefix"]
        colli_origin = risk["colli_origin"]

        # a1: what's the RPKI status of {prefix}-{origin}?
        risk["a1"] = g_rpki.validate(prefix, origin)

        # a2: what's the RPKI status of {colli_prefix}-{colli_origin}?
        risk["a2"] = g_rpki.validate(colli_prefix, colli_origin)

        # a3: what's the IRR status of {prefix}-{origin}?
        risk["a3"] = g_radb.validate(prefix, origin)

        # a4: what's the IRR status of {colli_prefix}-{colli_origin}?
        risk["a4"] = g_radb.validate(colli_prefix, colli_origin)

        same_orgs, same_org_id = find_same_org(colli_origin, aspath)
        # a5: which ASes in {aspath} are of the same org as {colli_origin}?
        risk["a5"] = ";".join(same_orgs) if same_orgs else "None"

        # a6: what the same org are they belong to?
        risk["a6"] = "None" if same_org_id is None else same_org_id

        # a7: what relationship is between {origin} and {colli_origin}?
        rel = find_as_rel(origin, colli_origin)
        risk["a7"] = "None" if rel is None else str(rel)

        yield risk

def post_processing(risk_iter):
    global g_analyzer

    def search_org_info(asn):
        info = []
        if asn in g_as_info:
            info.append(g_as_info[asn]["aut_name"])
            org_id = g_as_info[asn]["org_id"]
            if org_id in g_org_info:
                for k in ["name", "country", "source", "changed"]:
                    info.append(g_org_info[org_id][k])
        return info

    risks = []
    for risk in risk_iter:
        if risk["a1"] != "Valid": continue
        if risk["a2"] != "Invalid": continue
        if risk["a3"] != "Valid": continue
        if risk["a4"] != "Invalid": continue
        if risk["a5"] != "None": continue
        if risk["a6"] != "None": continue
        if risk["a7"] != "None": continue
        risks.append(risk)

    del g_analyzer
    risk_df = pd.DataFrame.from_records(risks)
    del risks

    # recover reference routes
    def recover_ref_routes():
        print("start recovering reference routes")
        collector2refs = dict()
        for colli_ref in risk_df["colli_ref"]:
            for ref_list in colli_ref.split(";"):
                for ref in ref_list.split("|"):
                    collector, idx = ref.split(".")
                    collector2refs.setdefault(collector, set()).add(int(idx))
        ref2route = dict()
        for collector, indices in collector2refs.items():
            loader = g_collector2rib[collector]()
            for target_idx in sorted(indices):
                for idx, route in loader:
                    if idx == target_idx:
                        ref2route[f"{collector}.{idx}"] = route
                        break
            print(f"{collector} finished")
        return ref2route
    ref2route = recover_ref_routes()

    print("start grouping and tagging events")
    alarms = []
    for (colli_ref), grp in risk_df.groupby("colli_ref"):
        alarm = RecursiveDict()

        # alarm triggers
        # alarm["alarm_trigger/name"] = "Alarm triggers"
        # alarm["alarm_trigger/info"] = "This field locates the entries of alarm-triggering announcements within the original RouteViews data. Each key represents the name of a RouteViews collector, and its corresponding value is a set of indexes pointing to the specific entries in the collector's RIB data at the time of detection.\n"

        key_set = set()
        for refs in colli_ref.split(";"):
            for ref in refs.split("|"):
                collector, idx = ref.split(".")
                key = f"alarm_trigger/{collector}"
                if key in alarm:
                    alarm[key].add(int(idx))
                else:
                    alarm[key] = {int(idx)}
                key_set.add(key)
        for key in key_set: alarm[key] = sorted(alarm[key])

        alarm_trigger = alarm["alarm_trigger"]
        for collector, indexes in alarm_trigger.items():
            alarm_trigger[collector] = sorted(indexes)

        # risk-critical ASes (aka colli_signature)
        # alarm["risk_critical/name"] = "Risk-critical ASes"
        # alarm["risk_critical/info"] = "This field lists the set of on-path ASes responsible for forwarding traffic to unexpected origins, as identified by the control-plane observations from at least one vantage points. These ASes are deemed critical to the risk highlighted by the alarm.\n"

        colli_ases = set(map(str, grp.colli_as.unique()))
        alarm["risk_critical"] = sorted({asn for colli_as in colli_ases
                                        for asn in colli_as.strip("{}").split(",")})

        # risk-observing VPs (aka unexpec_vp_signature)
        # alarm["risk_observing/name"] = "Risk-observing VPs"
        # alarm["risk_observing/info"] = "This field lists the set of vantage points that observed the unexpected routes in their routing tables.\n"

        colli_vps = {vp for vps_str in grp.colli_vp.astype(str)
                            for vp in vps_str.split(";")}
        alarm["risk_observing"] = sorted({asn for colli_vp in colli_vps
                                        for asn in colli_vp.strip("{}").split(",")})

        # risk-ignorant VPs (aka expec_vp_signature)
        # alarm["risk_ignorant/name"] = "Risk-ignorant VPs"
        # alarm["risk_ignorant/info"] = "This field lists the set of vantage points that observed only the expected routes and did not observe any unexpected routes in their routing tables.\n"

        alarm["risk_ignorant"] = sorted({asn for aspath in grp.aspath.values
                        for asn in aspath.split(" ", 1)[0].strip("{}").split(",")})

        # affected prefixes (aka prefixes1_signature)
        # alarm["affected_prefixes/name"] = "Affected prefixes"
        # alarm["affected_prefixes/info"] = "This field lists the set of prefixes in risk of hijacking.\n"

        alarm["affected_prefixes"] = sorted(grp.prefix.unique())

        # mis-announced prefixes (aka prefixes2_signature)
        # alarm["mis_announced_prefixes/name"] = "Mis-announced prefixes"
        # alarm["mis_announced_prefixes/info"] = "This field lists the set of prefixes that were announced by illegitimate origins, presumably resulting in hijacking.\n"

        alarm["mis_announced_prefixes"] = sorted(grp.colli_prefix.unique())

        # print(f"{','.join(alarm['affected_prefixes'])}"
        #        " -> "
        #       f"{','.join(alarm['mis_announced_prefixes'])}")

        # expected origins (aka expec_signature)
        # alarm["expected_origins/name"] = "Expected origins"
        # alarm["expected_origins/info"] = "This field lists the legitimate origins that are authorized to announce the the affected prefixes.\n"
        alarm["expected_origins"] = set() # updated later

        # unexpected origins (aka unexpec_signature)
        # alarm["unexpected_origins/name"] = "Unexpected origins"
        # alarm["unexpected_origins/info"] = "This field lists the illegitimate origins that mis-announced prefixes, presumably resulting in hijacking.\n"
        alarm["unexpected_origins"] = set() # updated later

        # expected routes
        # print("Expected:")
        # alarm["expected_routes/name"] = "Expected routes"
        # alarm["expected_routes/info"] = "This field lists the routes destined for the affected prefixes that were announced by legitimate origins. These routes themselves show no signs of hijacking, and are thus considered the expected routes.\n"

        alarm["expected_routes"] = set()
        for prefix, aspath, ref in grp[["prefix", "aspath", "ref"]].values:
            aspath = aspath.split(" ")
            alarm["expected_origins"].update(aspath[-1].strip("{}").split(","))
            for i in range(len(aspath)):
                if aspath[i] in colli_ases:
                    aspath[i] = f"<{aspath[i]}>"
            aspath = " ".join(aspath)
            alarm["expected_routes"].add((prefix, aspath, ref))
            # print(f"  {prefix}: {aspath}")

        alarm["expected_origins"] = sorted(alarm["expected_origins"])
        alarm["expected_routes"] = sorted(alarm["expected_routes"])

        # unexpected routes
        # print("Unexpected:")
        # alarm["unexpected_routes/name"] = "Unexpected routes"
        # alarm["unexpected_routes/info"] = "This field lists the routes destined for the prefixes that were mis-announced by illegitimate origins. These routes indicate actual hijacking of the affected prefixes, and are thus considered the unexpected routes.\n"

        alarm["unexpected_routes"] = set()
        for ref_list in colli_ref.split(";"):
            for ref in ref_list.split("|"):
                prefix, aspath = ref2route[ref]
                aspath = aspath.split(" ")
                alarm["unexpected_origins"].update(aspath[-1].strip("{}").split(","))
                for i in range(len(aspath)):
                    if aspath[i] in colli_ases:
                        aspath[i] = f"<{aspath[i]}>"
                aspath = " ".join(aspath)
                alarm["unexpected_routes"].add((prefix, aspath, ref))
                # print(f"  {prefix}: {aspath}")

        alarm["unexpected_origins"] = sorted(alarm["unexpected_origins"])
        alarm["unexpected_routes"] = sorted(alarm["unexpected_routes"])

        # organization
        # print("Organization:")
        # alarm["organizations/name"] = "Related oranizations"
        # alarm["organizations/info"] = "This field provides information about the organizations associated with the relevant ASes.\n"

        for asn in alarm["risk_critical"]:
            org_info = search_org_info(asn)
            alarm[f"organizations/risk_critical/{asn}"] = org_info
            # print(f"  Colli {asn}: {', '.join(org_info)}")

        for asn in alarm["expected_origins"]:
            org_info = search_org_info(asn)
            alarm[f"organizations/expected_origins/{asn}"] = org_info
            # print(f"  Expec {asn}: {', '.join(org_info)}")

        for asn in alarm["unexpected_origins"]:
            org_info = search_org_info(asn)
            alarm[f"organizations/unexpected_origins/{asn}"] = org_info
            # print(f"  Unexp {asn}: {', '.join(org_info)}")

        # tags
        # alarm["tags/name"] = "Tags"
        # alarm["tags/info"] = ("This field tags the alarm under specific identifiable circumstances.\n"
        # "- Origin Relay: the expected origin is also on the unexpected route.\n"
        # "- Private-Use ASN: the unexpected origin is reserved for private use.\n"
        # "- Direct VP View: a vantage point is also a risk-critical AS.\n"
        # "- Origin AS-Set: the unexpected origin is an AS-set.\n"
        # "- Similar Org Name: the expected and unexpected origins share similar organization names at the character level.\n"
        # "- Different Countries: the expected and unexpected origins are from different countries\n"
        # "- WHOIS Recorded: the unexpected origins and their associated organizations are listed in WHOIS records, and these records match the affected prefixes.\n")

        alarm["tags"] = set()

        unexpected_paths = [list(map(lambda x: x.strip("<>"), i.split(" ")))
                                for _,i,_ in alarm["unexpected_routes"]]

        def check_origin_relay():
            # is the expected origin also on the unexpected path?
            for origin, path in product(alarm["expected_origins"],
                                        unexpected_paths):
                if origin in path:
                    return True
            return False

        def check_private_use_asn():
            # is the unexpected origin reserved for private use?
            for asn in alarm["unexpected_origins"]:
                asn = int(asn)
                if asn == 0 or asn == 112 or asn == 23456 \
                    or (asn >= 64496 and asn <= 65551) \
                    or (asn >= 4200000000 and asn <= 4294967295):
                    return True
            return False

        def check_direct_vp_view():
            # is there an unexpected path directly received by a collector?
            for vp in alarm["risk_observing"]:
                if vp in alarm["risk_critical"]:
                    return True
            return False

        def check_route_aggregation():
            # is the unexpected origin enclosed in curly brackets?
            for path in unexpected_paths:
                if path[-1].startswith("{") and path[-1].endswith("}"): 
                    return True
            return False

        def check_common_fuzzy_snippet(str1, str2, min_ratio=90):
            min_len = max(min(len(str1), len(str2))//2+1, 5)
            for i in range(len(str1)):
                for j in range(i + min_len, len(str1) + 1):
                    substring = str1[i:j]
                    if fuzz.partial_ratio(substring, str2) >= min_ratio:
                        return True
            return False
        def check_similar_organization_name():
            # are the organization names similar?
            for asn0, asn1 in product(alarm["expected_origins"],
                                      alarm["unexpected_origins"]):
                info0 = search_org_info(asn0)
                info1 = search_org_info(asn1)
                if len(info0) == 5 and len(info1) == 5:
                    if check_common_fuzzy_snippet(clean_org_name(info0[1]),
                            clean_org_name(info1[1])):
                        return True
            return False

        def check_different_country():
            # are the organization from different countries?
            for asn0, asn1 in product(alarm["expected_origins"],
                                      alarm["unexpected_origins"]):
                info0 = search_org_info(asn0)
                info1 = search_org_info(asn1)
                if len(info0) == 5 and len(info1) == 5:
                    if info0[2] and info1[2] and info0[2] != info1[2]:
                        return True
            return False

        def check_whois_record():
            # are the origins/organizations recorded in whois?
            for colli_prefix in alarm["mis_announced_prefixes"]:
                whois_content = whois_lookup(colli_prefix, g_time_sig[:8])
                whois_values = set()
                for line in whois_content.split("\n"):
                    if not line or line.startswith("%"): continue
                    match = re.match(r'^(\S+):\s+(.*)$', line)
                    if match:
                        _, value = match.groups()
                        whois_values.add(clean_org_name(value))
                for asn in alarm["unexpected_origins"]:
                    for v in whois_values: # check ASN first
                        if f"as{asn}" in v:
                            return True
                    info = search_org_info(asn) # check Org then
                    if len(info) == 5 and info[1]:
                        org_name = clean_org_name(info[1])
                        for v in whois_values:
                            if len(v) < 5: continue
                            if check_common_fuzzy_snippet(org_name, v):
                                return True
            return False

        if check_origin_relay(): alarm["tags"].add("Origin Relay")
        if check_private_use_asn(): alarm["tags"].add("Private-Use ASN")
        if check_direct_vp_view(): alarm["tags"].add("Direct VP View")
        if check_route_aggregation(): alarm["tags"].add("Origin AS-Set")
        if check_similar_organization_name(): alarm["tags"].add("Similar Org Name")
        if check_different_country(): alarm["tags"].add("Different Countries")
        if check_whois_record(): alarm["tags"].add("WHOIS Recorded")
        alarm["tags"] = sorted(alarm["tags"])

        # print(f"Note: {'; '.join(alarm['tags'])}")
        # print()
        alarms.append(alarm.to_dict())

    # merge alarms with intersecting signatures into one incident
    print("start incident merging")
    indices = list(range(len(alarms)))
    sig_names = ("affected_prefixes",
                 "mis_announced_prefixes",
                 "expected_origins")
    virtual_signatures = [
        {sig_name: set(alarm[sig_name]) for sig_name in sig_names}
        for alarm in alarms]

    def check_intersection(i, j):
        vsi = virtual_signatures[i]
        vsj = virtual_signatures[j]
        for sig_name in sig_names:
            if vsi[sig_name] & vsj[sig_name]:
                return True
        return False

    def update_virtual_signatures(i, j):
        vsi = virtual_signatures[i]
        vsj = virtual_signatures[j]
        for sig_name in sig_names:
            vsi[sig_name].update(vsj[sig_name])

    changed = True
    while changed:
        changed = False
        for i in range(len(alarms)):
            for j in range(i+1, len(alarms)):
                if indices[i] != indices[j] and check_intersection(i, j):
                    old_index, new_index = indices[j], indices[i]
                    for k in range(len(alarms)):
                        if indices[k] == old_index:
                            indices[k] = new_index
                    update_virtual_signatures(i, j)
                    changed = True

    def incident_id_mapper():
        counter = count().__next__
        return {idx: counter() for idx in np.unique(indices)}

    mapper = incident_id_mapper()
    alarm_count = Counter()
    incidents = dict()
    for index, alarm in zip(indices, alarms):
        incident_id = mapper[index]
        alarm_id = alarm_count[incident_id]
        alarm_count[incident_id] += 1
        alarm["id"] = f"{g_routine_sig}.I#{incident_id}.A#{alarm_id}"
        incidents.setdefault(incident_id, []).append(alarm)

    time = datetime.strptime(g_time_sig, "%Y%m%d.%H%M").strftime("%Y-%m-%d %H:%M")
    bad_practice_signs = {"Origin Relay", "Private-Use ASN", "Origin AS-Set", "Similar Org Name", "WHOIS Recorded"}
    for incident_id, incident_alarms in incidents.items():
        incident_abstract = dict()
        incident_abstract["id"] = incident_id + g_initial_incident_id
        incident_abstract["time"] = time

        incident_abstract["prefixes"] = set()
        incident_abstract["expected_origins"] = set()
        incident_abstract["unexpected_origins"] = set()
        incident_abstract["tags"] = set()
        incident_abstract["alarm_id"] = list()
        for alarm in incident_alarms:
            incident_abstract["prefixes"].update(alarm["affected_prefixes"])
            incident_abstract["prefixes"].update(alarm["mis_announced_prefixes"])
            for field in ("expected_origins", "unexpected_origins"):
                for asn, org_info in alarm["organizations"][field].items():
                    if len(org_info) == 5:
                        _, org_name, country, _, _ = org_info
                        org_source = ", ".join([org_name, country])
                    else: org_source = ""
                    if org_source:
                        incident_abstract[field].add(f"AS{asn} ({org_source})")
                    else:
                        incident_abstract[field].add(f"AS{asn}")
            incident_abstract["tags"].update(alarm["tags"])
            incident_abstract["alarm_id"].append(alarm["id"])

        if incident_abstract["tags"] & bad_practice_signs:
            incident_abstract["category"] = "Bad Operational Practice"
        else:
            incident_abstract["category"] = "Potential Stealthy Hijacking"

        for field in ("prefixes", "expected_origins", "unexpected_origins", "tags"):
            incident_abstract[field] = sorted(incident_abstract[field])

        incident_abstract["ai_output"] = "Unavailable for this incident."

        incidents[incident_id] = incident_abstract

    incidents = sorted(incidents.values(), key=lambda x: x["id"], reverse=True)
    return alarms, incidents

def routine(collectors, year, month, day, hour, initial_incident_id):
    pre_loading(collectors, year, month, day, hour, initial_incident_id)
    risk_iter = discover_risk_instances()
    risk_iter = risk_analysis(risk_iter)
    alarms, incidents = post_processing(risk_iter)

    json.dump(incidents, (result_dir/f"{g_routine_sig}.incidents.json").open("w"))
    json.dump(alarms, (result_dir/f"{g_routine_sig}.alarms.json").open("w"))

    return incidents, alarms

@click.command()
@click.option('-c', '--collectors', default="wide,amsix,route-views2", show_default=True, help="Comma-separated list of collectors (default: 'wide,amsix,route-views2').", callback=lambda ctx, param, value: value.split(','))
@click.option('-y', '--year', type=int, required=True, help="Year as an integer.")
@click.option('-m', '--month', type=int, required=True, help="Month as an integer.")
@click.option('-d', '--day', type=int, required=True, help="Day as an integer.")
@click.option('-H', '--hour', type=int, required=True, help="Hour as an integer.")
@click.option('-I', '--initial-incident-id', type=int, required=True, help="Incident ID to start with.")
def main(collectors, year, month, day, hour, initial_incident_id):
    """Example:
    python routine.py -c wide,amsix,route-views2 -y 2025 -m 1 -d 1 -H 12 -I 0
    """
    routine(collectors, year, month, day, hour, initial_incident_id)

if __name__ == "__main__":
    main()
