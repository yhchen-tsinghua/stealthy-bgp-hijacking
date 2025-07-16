#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import json
from pathlib import Path
from data.rov_measurement.process import load_cloudflare, load_apnic, load_rovista
from data.caida.as_rel import get as get_rels
from datetime import datetime
from functools import cache, lru_cache
import numpy as np
import pandas as pd

script_dir = Path(__file__).resolve().parent
data_dir = script_dir/"data"
result_dir = script_dir/"result"
result_dir.mkdir(parents=True, exist_ok=True)
cache_dir = script_dir/".cache"

rov_date = 20250310
before = datetime(year=2025, month=3, day=1)
rov_status = None
incidents = None
alarmByID = None

strptime = lambda i: datetime.strptime(i, "%Y-%m-%d %H:%M")

all_asns = None

def load_rov_status():
    global rov_status
    rov_status = dict()

    for asn, status in load_cloudflare(rov_date)[["asn", "status"]].values:
        s = rov_status.setdefault(asn,
                dict(rovista=None, apnic=None, cloudflare=None))
        s["cloudflare"] = status

    for asn, ratio in load_apnic(rov_date)[["asn", "ratio"]].values:
        s = rov_status.setdefault(asn,
                dict(rovista=None, apnic=None, cloudflare=None))
        s["apnic"] = ratio

    for asn, ratio in load_rovista(rov_date)[["asn", "ratio"]].values:
        s = rov_status.setdefault(asn,
                dict(rovista=None, apnic=None, cloudflare=None))
        s["rovista"] = ratio

load_rov_status()

@cache
def get_rov_list(th=0.8):
    set_rov = set()
    
    for asn, status in rov_status.items():
        if status["cloudflare"] == "safe":
            set_rov.add(asn)
            continue
        s1 = 0 if status["apnic"] is None else status["apnic"]
        s2 = 0 if status["rovista"] is None else status["rovista"]
        if max(s1, s2) >= th:
            set_rov.add(asn)

    return set_rov

@cache
def get_rov_list_ablation(apnic=False, rovista=False, cloudflare=False, th=0.8, rnd=0):
    def get_source2set():
        source2set = {}
        source2set["apnic"] = {
            asn for asn, status in rov_status.items()
            if status["apnic"] is not None
            and status["apnic"] >= th
        }
        source2set["rovista"] = {
            asn for asn, status in rov_status.items()
            if status["rovista"] is not None
            and status["rovista"] >= th
        }
        source2set["cloudflare"] = {
            asn for asn, status in rov_status.items()
            if status["cloudflare"] == "safe"
        }
        return source2set

    p_sources, n_sources = [], []

    if apnic: p_sources.append("apnic")
    else: n_sources.append("apnic")

    if rovista: p_sources.append("rovista")
    else: n_sources.append("rovista")

    if cloudflare: p_sources.append("cloudflare")
    else: n_sources.append("cloudflare")

    if len(p_sources) == 0: # random
        np.random.seed(rnd)
        rov_set = set(np.random.choice(all_asns, size=1000, replace=False).tolist())
    else:
        source2set = get_source2set()
        rov_set = set()
        for ps in p_sources:
            rov_set |= source2set[ps]
        for ns in n_sources:
            rov_set -= source2set[ns]

    return rov_set

def get_noise_resistance(th=0.8):
    n, n1, n2 = 0, 0, 0
    for asn, status in rov_status.items():
        s1 = int(status["cloudflare"] == "safe")
        s2 = int(status["apnic"] is not None and status["apnic"] >= th)
        s3 = int(status["rovista"] is not None and status["rovista"] >= th)
        if (s1 + s2 + s3) > 0: n += 1
        if (s1 + s2 + s3) > 1: n1 += 1
        if (s1 + s2 + s3) > 2: n2 += 1

    return n1/n, n2/n

def load_incidents():
    global incidents
    incidents = json.load(open(data_dir/"service"/"all-incidents.json", "r"))[::-1]
    incidents = list(filter(lambda x: strptime(x["time"]) < before, incidents))

load_incidents()

def load_alarms():
    global alarmByID
    alarmByID = {alarm["id"]: alarm for alarm in json.load(open(data_dir/"service"/"all-alarms.json", "r"))}

load_alarms()

@cache
def get_toposim(date, th=None):
    filename = get_rels("2", date)
    if th is None:
        rov_set = set()
    else:
        rov_set = get_rov_list(th)
    return TopoSim(filename, exclude=rov_set)

P2C = -1
P2P =  0
C2P = +1

class TopoSim:
    def __init__(self, filename, break_tie_fn=None, prefer_change=False, exclude=set()):
        self.ngbrs = {}
        n_edge = 0

        for line in open(filename, "r").readlines():
            if line.startswith("#"): continue
            a, b, rel = line.strip().split("|")[:3]
            n_edge += 1

            to_add = (a not in exclude) and (b not in exclude)

            if a not in self.ngbrs:
                self.ngbrs[a] = {C2P:set(),P2P:set(),P2C:set()}
            if to_add:
                self.ngbrs[a][int(rel)].add(b)

            if b not in self.ngbrs:
                self.ngbrs[b] = {C2P:set(),P2P:set(),P2C:set()}
            if to_add:
                self.ngbrs[b][-int(rel)].add(a)

        if break_tie_fn is None:
            self.break_tie_fn = TopoSim.rnd_break_ties
        else:
            self.break_tie_fn = break_tie_fn

        self.prefer_change = prefer_change

        print(f"load: {filename}")
        print(f"nodes: {len(self.ngbrs):,}, edges: {n_edge:,}")

    def get_ngbrs(self, asn, rel=[C2P, P2P, P2C]):
        if type(rel) is list:
            return set().union(*[self.ngbrs[asn][i] for i in rel])
        else:
            return self.ngbrs[asn][rel]

    def get_rel(self, a, b):
        for k, v in self.ngbrs[a].items():
            if b in v: return k
        return None

    @staticmethod
    def equally_best_nexthop(working_rib, best_from_rel=P2C):
        best_length = float("inf")
        ties = []
        for ngbr in working_rib.keys():
            as_path, from_rel = working_rib[ngbr]
            if from_rel == best_from_rel:
                length = len(as_path)
                if length == best_length:
                    ties.append(ngbr)
                elif length < best_length:
                    ties = [ngbr]
                    best_length = length
            elif from_rel > best_from_rel:
                ties = [ngbr]
                best_from_rel = from_rel
                best_length = len(as_path)
        return ties

    @staticmethod
    def rnd_break_ties(ties):
        return np.random.choice(ties)

    @staticmethod
    def states_update(routes, ribs, working_as, as_path, from_rel, break_tie_fn, prefer_change):
        # as_path should not contain working_as
        # from_rel is the rel from as_path[0] to working_as
        ngbr = as_path[0]
        rib = ribs.setdefault(working_as, dict())
        rib[ngbr] = [as_path, from_rel]

        updated = False
        if working_as not in routes:
            routes[working_as] = [as_path, from_rel] # first receive
            updated = True
        else:
            old_as_path, old_from_rel = routes[working_as]
            if old_as_path[0] == ngbr: # from the same ngbr
                if len(as_path) <= len(old_as_path):
                    # new route better than or equal to old one
                    routes[working_as] = [as_path, from_rel]
                    updated = True
                else: # select new route from rib
                    routes[working_as] = rib[break_tie_fn(
                        TopoSim.equally_best_nexthop(rib, best_from_rel=from_rel))]
                    updated = True
            else:
                if (from_rel > old_from_rel
                    or (from_rel == old_from_rel
                        and len(as_path) < len(old_as_path))):
                    # from different ngbrs and better than old one
                    routes[working_as] = [as_path, from_rel]
                    updated = True
                elif (prefer_change 
                    and from_rel == old_from_rel
                        and len(as_path) == len(old_as_path)):
                    # from different ngbrs and equal to old one
                    # and prefer to re-select given `prefer_change`
                    routes[working_as] = rib[break_tie_fn(
                        TopoSim.equally_best_nexthop(rib, best_from_rel=from_rel))]
                    updated = old_as_path != routes[working_as][0]
        return routes[working_as] if updated else None

    @lru_cache(maxsize=1024)
    def sim_all_routes_to(self, origin_as):
        ribs = dict()
        routes = {origin_as: [[], None]}

        init_path = [origin_as]
        queue = [[working_as, init_path, from_rel]
                for from_rel, ngbrs in self.ngbrs[origin_as].items()
                    for working_as in ngbrs]

        while queue:
            _working_as, _as_path, _from_rel = queue.pop(0)
            updated_route = TopoSim.states_update(routes, ribs, _working_as,
                    _as_path, _from_rel, self.break_tie_fn, self.prefer_change)
            if updated_route is not None:
                _as_path, _from_rel = updated_route
                next_path = [_working_as] + _as_path
                queue += [[working_as, next_path, from_rel]
                    for from_rel, ngbrs in self.ngbrs[_working_as].items()
                        if from_rel <= _from_rel and
                            not (from_rel == 0 and _from_rel == 0) # valley-free
                                for working_as in ngbrs
                                    if working_as not in _as_path] # avoid circle

        return routes

def get_all_asns():
    global all_asns
    all_asns = set()
    for d in ["20250101", "20250201"]:
        all_asns = all_asns.union(get_toposim(d).ngbrs.keys())
    all_asns = sorted(all_asns)
get_all_asns()

def check_incident(incident, th, rov_list_gen):
    if "Direct VP View" not in incident["tags"]: # filter low-confidence incidents
        return np.zeros((4, 3), dtype=np.int64)

    if "Similar Org Name" in incident["tags"]: # filter benign incidents
        return np.zeros((4, 3), dtype=np.int64)

    incident_alarms = []
    for i in incident["alarm_id"]:
        alarm = alarmByID[i]
        if "Direct VP View" not in alarm["tags"]: # filter low-confidence alarms
            continue
        incident_alarms.append(alarm)

    rov_set = rov_list_gen(th)

    as_rel_date = strptime(incident["time"]).strftime("%Y%m01")
    toposim_valid = get_toposim(as_rel_date)
    toposim_invalid = get_toposim(as_rel_date, th)

    def check_expected_route_with_rov(aspath):
        for asn in aspath:
            if asn.startswith("<") and asn.endswith(">"): break
            if asn in rov_set: return True
        return False

    def check_unexpected_route_with_rov(aspath):
        for asn in aspath:
            if asn.startswith("<") and asn.endswith(">"):
                asn = asn.strip("<>")
            if asn in rov_set: return False
        return True

    def check_expected_route_with_topo(aspath, invalid_origins):
        valid_origin = None
        for asn in aspath[::-1]:
            asn = asn.strip("<>")
            if asn in toposim_valid.ngbrs:
                valid_origin = asn
                break

        if valid_origin is None:
            return False

        vp = aspath[0].strip("<>")

        if vp not in toposim_valid.ngbrs:
            return False

        seeing_valid = vp in toposim_valid.sim_all_routes_to(valid_origin)

        not_seeing_invalid = False
        for invalid_origin in invalid_origins:
            if vp not in toposim_invalid.sim_all_routes_to(invalid_origin):
                not_seeing_invalid = True
                break

        risk_critical = False
        for asn in aspath:
            if asn.startswith("<") and asn.endswith(">"):
                asn = asn.strip("<>")
                for invalid_origin in invalid_origins:
                    if asn in toposim_invalid.sim_all_routes_to(invalid_origin):
                        risk_critical = True
                        break
                if risk_critical: break

        return (seeing_valid and not_seeing_invalid and risk_critical)

    def check_unexpected_route_with_topo(aspath):
        invalid_origin = None
        for asn in aspath[::-1]:
            asn = asn.strip("<>")
            if asn in toposim_invalid.ngbrs:
                invalid_origin = asn
                break

        if invalid_origin is None:
            return False

        vp = aspath[0].strip("<>")

        if vp not in toposim_invalid.ngbrs:
            return False

        seeing_invalid = vp in toposim_invalid.sim_all_routes_to(invalid_origin)

        return seeing_invalid

    n_expec, n_expec_rov, n_expec_sim = [0]*3 # expected routes level
    n_unexp, n_unexp_rov, n_unexp_sim = [0]*3 # unexpected routes level
    n_alarm, n_alarm_rov, n_alarm_sim = [0]*3 # alarm level
    n_incid, n_incid_rov, n_incid_sim = [0]*3 # incident level

    for alarm in incident_alarms:
        invalid_origins = set() # get the actual origin
        for _, aspath, _ in alarm["unexpected_routes"]:
            invalid_origin = None
            for asn in aspath.split(" ")[::-1]:
                asn = asn.strip("<>")
                if asn in toposim_invalid.ngbrs:
                    invalid_origin = asn
                    break
            if invalid_origin is not None:
                invalid_origins.add(invalid_origin)

        vp_status_rov = dict()
        vp_status_sim = dict()
        for _, aspath, _ in alarm["expected_routes"]:
            aspath = aspath.split(" ")
            vp = aspath[0].strip("<>")

            if vp not in vp_status_rov or not vp_status_rov[vp]:
                vp_status_rov[vp] = check_expected_route_with_rov(aspath)

            if vp not in vp_status_sim or not vp_status_sim[vp]:
                vp_status_sim[vp] = check_expected_route_with_topo(aspath, invalid_origins)
        assert len(vp_status_rov) == len(vp_status_sim)
        n_expec += len(vp_status_sim)
        n_expec_rov += np.count_nonzero(list(vp_status_rov.values()))
        n_expec_sim += np.count_nonzero(list(vp_status_sim.values()))

        vp_status_rov = dict()
        vp_status_sim = dict()
        for _, aspath, _ in alarm["unexpected_routes"]:
            aspath = aspath.split(" ")
            vp = aspath[0].strip("<>")

            if vp not in vp_status_rov or not vp_status_rov[vp]:
                vp_status_rov[vp] = check_unexpected_route_with_rov(aspath)

            if vp not in vp_status_sim or not vp_status_sim[vp]:
                vp_status_sim[vp] = check_unexpected_route_with_topo(aspath)
        assert len(vp_status_rov) == len(vp_status_sim)
        n_unexp += len(vp_status_sim)
        n_unexp_rov += np.count_nonzero(list(vp_status_rov.values()))
        n_unexp_sim += np.count_nonzero(list(vp_status_sim.values()))

        n_alarm += 1
        if n_expec_rov > 0 and n_unexp_rov > 0: # at least one pair passes
            n_alarm_rov += 1
        if n_expec_sim > 0 and n_unexp_sim > 0:
            n_alarm_sim += 1

    n_incid += 1
    if n_alarm_rov > 0: # at least one alarm passes
        n_incid_rov += 1
    if n_alarm_sim > 0:
        n_incid_sim += 1

    return [[n_expec, n_expec_rov, n_expec_sim],
            [n_unexp, n_unexp_rov, n_unexp_sim],
            [n_alarm, n_alarm_rov, n_alarm_sim],
            [n_incid, n_incid_rov, n_incid_sim],]

def overall_accuracy(th=0.8, rov_list_gen=get_rov_list):
    stats_all = np.zeros((4, 3), dtype=np.int64)
    for incident in incidents:
        stats_all[:] += np.array(check_incident(incident, th, rov_list_gen))

    ((acc_expec_rov, acc_unexp_rov, acc_alarm_rov, acc_incid_rov),
     (acc_expec_sim, acc_unexp_sim, acc_alarm_sim, acc_incid_sim)) = stats_all[:, 1:].T/stats_all[:, 0]

    n_route, n_route_rov, n_route_sim = stats_all[0]+stats_all[1]
    acc_route_rov = n_route_rov/n_route
    acc_route_sim = n_route_sim/n_route

    print(f"acc_expec_rov: {acc_expec_rov:.2%}")
    print(f"acc_unexp_rov: {acc_unexp_rov:.2%}")
    print(f"acc_route_rov: {acc_route_rov:.2%}")
    print(f"acc_alarm_rov: {acc_alarm_rov:.2%}")
    print(f"acc_incid_rov: {acc_incid_rov:.2%}")
    print(f"acc_expec_sim: {acc_expec_sim:.2%}")
    print(f"acc_unexp_sim: {acc_unexp_sim:.2%}")
    print(f"acc_route_sim: {acc_route_sim:.2%}")
    print(f"acc_alarm_sim: {acc_alarm_sim:.2%}")
    print(f"acc_incid_sim: {acc_incid_sim:.2%}")
    print(f"#incidents: {stats_all[3, 0]}")
    print(f"#alarms: {stats_all[2, 0]}")
    print(f"#routes: {n_route}")

    return (acc_expec_rov, acc_unexp_rov, acc_route_rov, acc_alarm_rov, acc_incid_rov,
            acc_expec_sim, acc_unexp_sim, acc_route_sim, acc_alarm_sim, acc_incid_sim)

ths = np.arange(0, 1, 0.1).tolist()+[0.95, 0.99]
acc = np.array([overall_accuracy(th, get_rov_list) for th in ths])

# single-source ablation
apnic_gen = lambda th: get_rov_list_ablation(apnic=True, th=th)
rovista_gen = lambda th: get_rov_list_ablation(rovista=True, th=th)
cloudflare_gen = lambda th: get_rov_list_ablation(cloudflare=True, th=th)

acc_a = np.array([overall_accuracy(th, apnic_gen) for th in ths])
acc_r = np.array([overall_accuracy(th, rovista_gen) for th in ths])
acc_c = np.array([overall_accuracy(th, cloudflare_gen) for th in ths])

# two-source ablation
ar_gen = lambda th: get_rov_list_ablation(apnic=True, rovista=True, th=th)
ac_gen = lambda th: get_rov_list_ablation(apnic=True, cloudflare=True, th=th)
rc_gen = lambda th: get_rov_list_ablation(rovista=True, cloudflare=True, th=th)

acc_ar = np.array([overall_accuracy(th, ar_gen) for th in ths])
acc_ac = np.array([overall_accuracy(th, ac_gen) for th in ths])
acc_rc = np.array([overall_accuracy(th, rc_gen) for th in ths])

# random ablation
list_acc_rnd = []
for run in range(3):
    rnd_gen = lambda th: get_rov_list_ablation(rnd=run)
    acc_rnd = np.array(overall_accuracy(rov_list_gen=rnd_gen))
    list_acc_rnd.append(acc_rnd)

def to_df(acc, ths=ths):
    cols = ["acc_expec_rov", "acc_unexp_rov", "acc_route_rov", "acc_alarm_rov", "acc_incid_rov", "acc_expec_sim", "acc_unexp_sim", "acc_route_sim", "acc_alarm_sim", "acc_incid_sim"]
    df_acc = pd.DataFrame(acc, columns=cols)
    df_acc["rov_ratio_th"] = ths
    return df_acc

df_acc = to_df(acc)

df_acc_a = to_df(acc_a)
df_acc_r = to_df(acc_r)
df_acc_c = to_df(acc_c)

df_acc_ar = to_df(acc_ar)
df_acc_ac = to_df(acc_ac)
df_acc_rc = to_df(acc_rc)

df_acc_rnd = to_df(list_acc_rnd, ths=0.8)
df_acc_rnd = df_acc_rnd.groupby("rov_ratio_th")[["acc_expec_sim", "acc_unexp_sim", "acc_route_sim", "acc_alarm_sim", "acc_incid_sim"]].mean().reset_index()

def ablation_table():
    def get_source2set():
        source2set = {}
        source2set["apnic"] = {
            asn for asn, status in rov_status.items()
            if status["apnic"] is not None
            and status["apnic"] >= 0.8
        }
        source2set["rovista"] = {
            asn for asn, status in rov_status.items()
            if status["rovista"] is not None
            and status["rovista"] >= 0.8
        }
        source2set["cloudflare"] = {
            asn for asn, status in rov_status.items()
            if status["cloudflare"] == "safe"
        }
        return source2set
    source2set = get_source2set()

    f = open(result_dir/"ablation-table.tex", "w")
    dfs = [df_acc, df_acc_rc, df_acc_ac, df_acc_ar, df_acc_a, df_acc_r, df_acc_c, df_acc_rnd]
    srcs = ["111", "011", "101", "110", "100", "010", "001", "000"]
    for df,src in zip(dfs, srcs):
        out = []
        rov_set = set()
        for s, n in zip(src, ["apnic", "rovista", "cloudflare"]):
            if s == "1":
                out.append(r"\fullcirc[0.5ex]")
                rov_set |= source2set[n]
            else: out.append(r"\emptycirc[0.5ex]")
        acc = max([tuple(row) for row in df[["acc_incid_sim", "acc_alarm_sim", "acc_route_sim", "acc_expec_sim", "acc_unexp_sim"]].itertuples(index=False)])
        out += [f"{i:.4f}" for i in acc]
        out.append(f"{len(rov_set):,}" if rov_set else "1,000")
        f.write("&".join(out)+r" \\"+"\n")
    f.close()
ablation_table()

import matplotlib.pyplot as plt
import matplotlib as mpl
from matplotlib.ticker import MultipleLocator
from matplotlib.gridspec import GridSpec
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

class MyTransform(mpl.transforms.Transform):
    input_dims = 2
    output_dims = 2
    def __init__(self, base_point, base_transform, offset, *kargs, **kwargs):
        self.base_point = base_point
        self.base_transform = base_transform
        self.offset = offset
        super(mpl.transforms.Transform, self).__init__(*kargs, **kwargs)
    def transform_non_affine(self, values):
        new_base_point = self.base_transform.transform(self.base_point)
        t = mpl.transforms.Affine2D().translate(-new_base_point[0], -new_base_point[1])
        values = t.transform(values)
        x = values[:, 0:1]
        y = values[:, 1:2]
        r = np.sqrt(x**2+y**2)
        new_r = r-self.offset
        new_r[new_r<0] = 0.0
        new_x = new_r/r*x
        new_y = new_r/r*y
        return t.inverted().transform(np.concatenate((new_x, new_y), axis=1))

def acc_plot():
    def custom_plot(ax, x, y, ls, lw, ms, marker, color, label, alpha, offset=3):
        line, = ax.plot(x, y, marker=marker, ms=ms, color=color, alpha=alpha, ls="")
        for i in range(1, len(x)):
            mid_x = (x[i]+x[i-1])/2
            mid_y = (y[i]+y[i-1])/2
            t = ax.transData
            my_t = MyTransform(base_point=(mid_x, mid_y),
                    base_transform=t, offset=offset)
            t_end = t + my_t
            line, = ax.plot([x[i-1], x[i]], [y[i-1], y[i]],
                            ls=ls, lw=lw, color=color)
            line.set_transform(t_end)
        ax.plot([], [], ls=ls, lw=lw, ms=ms,
                marker=marker, color=color, label=label)

    fig = plt.figure(figsize=(4, 1.2))
    gs = GridSpec(1, 2)
    gs.update(wspace=0.06)
    axes = [fig.add_subplot(gs[i]) for i in range(2)]

    dlim = 0.2
    ticklabelsize = 6
    ticklabelpad = 1
    labelpad = 2
    markersize = 2

    # acc_route_sim, acc_alarm_sim, acc_incid_sim
    ax = axes[0]

    markers = ["o", "D", "*"]
    colors = ["#377eb8", "#ff7f00", "#4daf4a"]
    labels = ["route", "alarm", "incident"][::-1]
    keys = ["acc_route_sim", "acc_alarm_sim", "acc_incid_sim"][::-1]
    x = np.arange(df_acc.shape[0])

    for key, label, marker, color in zip(keys, labels, markers, colors):
        y = df_acc[key].values
        custom_plot(ax, x, y, ls="-", lw=1,
                ms=markersize+1 if marker == "*" else markersize,
                marker=marker, color=color, alpha=1, label=label)

    ax.set_xlim((-dlim, len(x)-1+dlim))
    ax.set_xticks(x)
    ax.set_xticklabels([f"{int(th*100)}" for th in df_acc["rov_ratio_th"].values])
    ax.set_xlabel("ROV filtering threshold (%)", fontsize=ticklabelsize+1, labelpad=labelpad)
    ax.set_ylim((-dlim*0.1, 1+dlim*0.1))
    ax.set_yticks(np.arange(11)/10)
    ax.tick_params("both", left=True, bottom=True, length=2,
            labelsize=ticklabelsize-0.5, pad=ticklabelpad)
    ax.set_ylabel("Accuracy", fontsize=ticklabelsize+1, labelpad=labelpad)
    ax.grid(True, ls="--", alpha=0.5)
    ax.legend(ncols=1, fontsize=ticklabelsize-0.5)

    # acc_expec_sim, acc_unexp_sim
    ax = axes[1]

    markers = ["*", "v", "^"]
    colors = ["#4daf4a", "#f781bf", "#BC6999"]
    labels = ["route", "route (valid)", "route (invalid)"]
    keys = ["acc_route_sim", "acc_expec_sim", "acc_unexp_sim"]

    for key, label, marker, color in zip(keys, labels, markers, colors):
        y = df_acc[key].values
        custom_plot(ax, x, y, ls="-", lw=1,
                ms=markersize+1 if marker == "*" else markersize,
                marker=marker, color=color, alpha=1, label=label)

    ax.set_xlim((-dlim, len(x)-1+dlim))
    ax.set_xticks(x)
    ax.set_xticklabels([f"{int(th*100)}" for th in df_acc["rov_ratio_th"].values])
    ax.set_xlabel("ROV filtering threshold (%)", fontsize=ticklabelsize+1, labelpad=labelpad)
    ax.set_ylim((-dlim*0.1, 1+dlim*0.1))
    ax.set_yticks(np.arange(11)/10)
    ax.set_yticklabels([])
    ax.tick_params("both", left=True, bottom=True, length=2,
            labelsize=ticklabelsize-0.5, pad=ticklabelpad)
    ax.grid(True, ls="--", alpha=0.5)
    ax.legend(ncols=1, fontsize=ticklabelsize-0.5)

    fig.savefig(result_dir/f"acc.pdf", bbox_inches="tight")
    plt.close(fig)
acc_plot()

def noise_resistance_plot():
    def custom_plot(ax, x, y, ls, lw, ms, marker, color, offset=3):
        line, = ax.plot(x, y, marker=marker, ms=ms, color=color, ls="")
        for i in range(1, len(x)):
            mid_x = (x[i]+x[i-1])/2
            mid_y = (y[i]+y[i-1])/2
            t = ax.transData
            my_t = MyTransform(base_point=(mid_x, mid_y),
                    base_transform=t, offset=offset)
            t_end = t + my_t
            line, = ax.plot([x[i-1], x[i]], [y[i-1], y[i]],
                            ls=ls, lw=lw, color=color)
            line.set_transform(t_end)
        ax.plot([], [], ls=ls, lw=lw, ms=ms,
                marker=marker, color=color)

    def lim(l, r, ratio):
        d = (r-l)*ratio
        return l-d, r+d

    fig = plt.figure(figsize=(4, 1.2))
    gs = GridSpec(2, 1)
    gs.update(hspace=0.3)
    axes = [fig.add_subplot(gs[i]) for i in range(2)]

    dlim = 0.05
    ticklabelsize = 6
    ticklabelpad = 1
    markersize = 2

    x = np.arange(len(ths))
    y1, y2 = np.array([get_noise_resistance(th) for th in ths]).T

    ax = axes[0]
    custom_plot(ax, x, y1, ls="-", lw=1, ms=markersize, marker="o", color="#377eb8")
    ax.text(0.98, 0.85, "Mislabeled by one source.", fontsize=ticklabelsize, va="top", ha="right", transform=ax.transAxes, bbox=dict(facecolor="white", alpha=0.8, lw=0, pad=1))
    

    ax.set_xlim(lim(0, len(x)-1, dlim))
    ax.set_xticks(x)
    ax.set_xticklabels([])
    ax.set_ylim(lim(0.2, 0.6, dlim))
    ax.set_yticks(np.arange(2, 7)/10)
    ax.set_yticklabels([f"{int(i*10)}" for i in range(2, 7)])
    ax.tick_params("both", left=True, bottom=True, length=2,
            labelsize=ticklabelsize, pad=ticklabelpad)
    ax.grid(True, ls="--", alpha=0.5)

    ax = axes[1]
    custom_plot(ax, x, y2, ls="-", lw=1, ms=markersize, marker="D", color="#377eb8")
    ax.text(0.98, 0.85, "Mislabeled by two sources.", fontsize=ticklabelsize, va="top", ha="right", transform=ax.transAxes, bbox=dict(facecolor="white", alpha=0.8, lw=0, pad=1))

    ax.set_xlim(lim(0, len(x)-1, dlim))
    ax.set_xticks(x)
    ax.set_xticklabels([f"{int(th*100)}" for th in ths])
    ax.set_xlabel("ROV filtering threshold (%)", fontsize=ticklabelsize+1)
    ax.set_ylim(lim(0, 0.02, dlim))
    ax.set_yticks(np.arange(0, 2.5, 0.5)/100)
    ax.set_yticklabels([f"{i:.1f}" for i in np.arange(0, 2.5, 0.5)])
    ax.tick_params("both", left=True, bottom=True, length=2,
            labelsize=ticklabelsize, pad=ticklabelpad)
    ax.grid(True, ls="--", alpha=0.5)

    fig.supylabel("Noise Resistance (%)", x=0.045, y=0.48, fontsize=ticklabelsize+1)
    fig.savefig(result_dir/f"resistance.pdf", bbox_inches="tight")
    plt.close(fig)
noise_resistance_plot()

def runtime_performance():
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator
    from matplotlib.gridspec import GridSpec
    from scipy.stats import sem, t
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(5, 2))
    gs = GridSpec(2, 1)
    gs.update(hspace=0.1)
    axes = [fig.add_subplot(gs[i]) for i in range(2)]

    colors = ['#377eb8', '#ff7f00', '#4daf4a', '#f781bf', '#BC6999']

    dlim = 0.05

    # ours vs baseline
    ax = axes[0]

    df = pd.read_csv(cache_dir/"matrix_bgpsim_1.csv")
    means = df.mean()
    standard_errors = df.apply(sem)
    confidence_intervals = standard_errors * t.ppf((1 + 0.95) / 2, df.shape[0] - 1)

    x_values = means.index.astype(int)
    y_values = means.values
    y_errors = confidence_intervals.values

    ax.plot(x_values, y_values, ls="-", lw=1, color=colors[0], label="Ours (1x)")
    ax.errorbar(x_values, y_values, yerr=y_errors, fmt='.', capsize=3, capthick=1, color=colors[0])

    df = pd.read_csv(cache_dir/"bgpsim.csv")
    means = df.mean()
    standard_errors = df.apply(sem)
    confidence_intervals = standard_errors * t.ppf((1 + 0.95) / 2, df.shape[0] - 1)

    x_values = means.index.astype(int)
    y_values = means.values
    y_errors = confidence_intervals.values

    ax.plot(x_values, y_values, ls="--", lw=1, color=colors[1], label="BGPsim")
    ax.errorbar(x_values, y_values, yerr=y_errors, fmt='.', capsize=3, capthick=1, color=colors[1])

    ax.yaxis.set_major_locator(MultipleLocator(2.5))
    ax.yaxis.set_minor_locator(MultipleLocator(0.5))
    ax.xaxis.set_major_locator(MultipleLocator(10))
    ax.set_xlim((10-90*dlim, 100+90*dlim))
    ax.set_ylim((0-7.5*dlim, 7.5+7.5*dlim))
    ax.set_xticklabels([])
    ax.set_ylabel('Seconds')
    ax.grid(True)
    ax.legend(fontsize=7)

    # ours vs ours
    ax = axes[1]

    df = pd.read_csv(cache_dir/"matrix_bgpsim_1.csv")
    means = df.mean()
    standard_errors = df.apply(sem)
    confidence_intervals = standard_errors * t.ppf((1 + 0.95) / 2, df.shape[0] - 1)

    x_values = means.index.astype(int)
    y_values = means.values
    y_errors = confidence_intervals.values

    ax.plot(x_values, y_values, ls="-", lw=1, color=colors[0], label="Ours (1x)")
    ax.errorbar(x_values, y_values, yerr=y_errors, fmt='.', capsize=3, capthick=1, color=colors[0])

    df = pd.read_csv(cache_dir/"matrix_bgpsim_20.csv")
    means = df.mean()
    standard_errors = df.apply(sem)
    confidence_intervals = standard_errors * t.ppf((1 + 0.95) / 2, df.shape[0] - 1)

    x_values = means.index.astype(int)
    y_values = means.values
    y_errors = confidence_intervals.values

    ax.plot(x_values, y_values, ls="--", lw=1, color=colors[2], label="Ours (20x)")
    ax.errorbar(x_values, y_values, yerr=y_errors, fmt='.', capsize=3, capthick=1, color=colors[2])

    df = pd.read_csv(cache_dir/"matrix_bgpsim_40.csv")
    means = df.mean()
    standard_errors = df.apply(sem)
    confidence_intervals = standard_errors * t.ppf((1 + 0.95) / 2, df.shape[0] - 1)

    x_values = means.index.astype(int)
    y_values = means.values
    y_errors = confidence_intervals.values

    ax.plot(x_values, y_values, ls=":", lw=1, color=colors[3], label="Ours (40x)")
    ax.errorbar(x_values, y_values, yerr=y_errors, fmt='.', capsize=3, capthick=1, color=colors[3])

    df = pd.read_csv(cache_dir/"matrix_bgpsim_gpu.csv")
    means = df.mean()
    standard_errors = df.apply(sem)
    confidence_intervals = standard_errors * t.ppf((1 + 0.95) / 2, df.shape[0] - 1)

    x_values = means.index.astype(int)
    y_values = means.values
    y_errors = confidence_intervals.values

    ax.plot(x_values, y_values, ls="-.", lw=1, color=colors[4], label="Ours (GPU)")
    ax.errorbar(x_values, y_values, yerr=y_errors, fmt='.', capsize=3, capthick=1, color=colors[4])

    ax.yaxis.set_major_locator(MultipleLocator(0.1))
    ax.yaxis.set_minor_locator(MultipleLocator(0.01))
    ax.xaxis.set_major_locator(MultipleLocator(10))
    ax.set_xlim((10-90*dlim, 100+90*dlim))
    ax.set_ylim((0-0.23*dlim, 0.23+0.23*dlim))
    ax.set_xlabel('# of ASes')
    ax.set_ylabel('Seconds')
    ax.grid(True)
    ax.legend(fontsize=7, ncols=2)

    fig.savefig(result_dir/f"runtime_performance.pdf", bbox_inches="tight")
    plt.close(fig)
runtime_performance()
