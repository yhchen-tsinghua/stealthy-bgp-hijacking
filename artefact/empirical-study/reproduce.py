#!/usr/bin/env python
#-*- coding: utf-8 -*-

import json
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
from collections import Counter
from itertools import product
import pickle
from itertools import product

script_dir = Path(__file__).resolve().parent
result_dir = script_dir/"result"
result_dir.mkdir(exist_ok=True, parents=True)
cache_dir = script_dir/".cache"
cache_dir.mkdir(exist_ok=True, parents=True)
data_dir = script_dir/"data"

before = datetime(year=2025, month=3, day=1)
strptime = lambda i: datetime.strptime(i, "%Y-%m-%d %H:%M")

incidents = json.load(open(data_dir/"service"/"all-incidents.json", "r"))[::-1]
incidents = list(filter(lambda x: strptime(x["time"]) < before, incidents))

alarmByID = {alarm["id"]: alarm for alarm in json.load(open(data_dir/"service"/"all-alarms.json", "r"))}

import matplotlib as mpl
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

def vp_plot():
    incident_vp = []
    alarm_vp = []
    for incident in incidents:
        vp_set1, vp_set2 = set(), set()
        for aid in incident["alarm_id"]:
            alarm = alarmByID[aid]
            vps1 = alarm["risk_observing"]
            vps2 = alarm["risk_ignorant"]

            vp_set1.update(vps1)
            vp_set2.update(vps2)

            alarm_vp.append(min(len(vps1), len(vps2)))
        incident_vp.append(min(len(vp_set1), len(vp_set2)))

    _x1, _y1 = np.unique(incident_vp, return_counts=True)
    _x2, _y2 = np.unique(alarm_vp, return_counts=True)

    x = np.arange(max(_x1[-1], _x2[-1]), dtype=int)

    y1 = np.zeros_like(x)
    y1[_x1-1] = _y1

    y2 = np.zeros_like(x)
    y2[_x2-1] = _y2

    import matplotlib.pyplot as plt
    from matplotlib.gridspec import GridSpec
    from matplotlib.patches import Patch
    from matplotlib.colors import to_rgba

    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(8, 1.6))
    gs = GridSpec(1, 2)
    gs.update(wspace=0.17)
    axes = [fig.add_subplot(gs[i]) for i in range(2)]

    def lim(l, r, ratio):
        d = (r-l)*ratio
        return l-d, r+d

    dlim = 0.03
    axis_fontsize = 10
    labelpad = 0.06
    colors = ["#377eb8", "#ff7f00"]
    alpha = 0.8

    ax = axes[0]

    bar1 = ax.bar(x, y1/100, width=0.3, align="edge", alpha=alpha,
            color=colors[0], label="Incidents", zorder=10)
    bar2 = ax.bar(x, y2/100, width=-0.3, align="edge", alpha=alpha,
            color=colors[1], label="Alarms", zorder=10)

    ax.set_xlim(lim(x[0], x[-1], dlim))
    ax.set_xticks(x, minor=True)
    ax.set_xticks([x[0], x[-1]])
    ax.set_xticklabels(["1", str(x[-1]+1)], fontsize=axis_fontsize)
    ax.tick_params("x", which="minor", length=2)
    ax.tick_params("x", which="major", length=4, pad=2)
    ax.text(0.5, -labelpad, "# of vantage points observing", fontsize=axis_fontsize, va="top", ha="center", transform=ax.transAxes)

    ax.set_ylim(lim(0, 12, dlim))
    ax.set_yticks(np.arange(0, 14, 2))
    ax.set_yticklabels(list(map(str, np.arange(0, 14, 2)*100)))
    ax.tick_params("y", which="major", length=3, pad=1, labelsize=axis_fontsize-3)
    ax.set_ylabel("Count", fontsize=axis_fontsize, labelpad=0)
    ax.yaxis.set_label_coords(-0.095, 0.5)
    ax.grid(True, axis="y", ls="--", alpha=0.4, zorder=0)

    ax.annotate(f"More than 40% observed by only one VP.",
        xy=(0, 9.5), xycoords=ax.transData,
        xytext=(1.2, 11), textcoords=ax.transData,
        arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=0.1",
            relpos=(0, 0.6), facecolor="black", edgecolor=None),
        fontsize=axis_fontsize-2, color="black", ha="left", va="center")

    ax.legend(loc="center", fontsize=axis_fontsize-1, framealpha=0.9)

    def get_matrix():
        incident_vp_1 = []
        incident_vp_2 = []
        alarm_vp_1 = []
        alarm_vp_2 = []
        all_vps = set()
        for incident in incidents:
            vp_set1, vp_set2 = set(), set()
            for aid in incident["alarm_id"]:
                alarm = alarmByID[aid]

                alarm_vp_1.append(alarm["risk_observing"])
                alarm_vp_2.append(alarm["risk_ignorant"])

                vp_set1.update(alarm["risk_observing"])
                vp_set2.update(alarm["risk_ignorant"])

            incident_vp_1.append(list(vp_set1))
            incident_vp_2.append(list(vp_set2))
            all_vps.update(vp_set1)
            all_vps.update(vp_set2)

        vp2index = {vp: idx for idx, vp in enumerate(all_vps)}

        def gen_matrix(event_vp):
            mat = np.zeros((len(event_vp), len(vp2index)), dtype=bool)
            for i, vps in enumerate(event_vp):
                for vp in vps: mat[i, vp2index[vp]] = True
            return mat

        imat1 = gen_matrix(incident_vp_1)
        imat2 = gen_matrix(incident_vp_2)
        amat1 = gen_matrix(alarm_vp_1)
        amat2 = gen_matrix(alarm_vp_2)

        return imat1, imat2, amat1, amat2

    matrix_cache = cache_dir/"event-vp.cache"
    if matrix_cache.exists():
        imat1, imat2, amat1, amat2 = pickle.load(matrix_cache.open("rb"))
    else:
        imat1, imat2, amat1, amat2 = get_matrix()
        pickle.dump([imat1, imat2, amat1, amat2], matrix_cache.open("wb"))

    def visibility(mat1, mat2, n_remove=0):
        n_event, n_vp = mat1.shape

        remain = np.ones(n_vp, dtype=bool)
        remain[np.random.choice(n_vp, size=n_remove, replace=False)] = False

        vis = np.count_nonzero(
            np.any(mat1[:, remain], axis=1) & np.any(mat2[:, remain], axis=1)
        )/n_event

        return vis

    def all_visibility():
        ret = []
        np.random.seed(0)
        for n, _ in product(range(1, 21), range(5000)):
            ret.append({
                "type": "incident",
                "n_removed_vp": n,
                "vis": visibility(imat1, imat2, n_remove=n)
            })
            ret.append({
                "type": "alarm",
                "n_removed_vp": n,
                "vis": visibility(amat1, amat2, n_remove=n)
            })
        df = pd.DataFrame.from_records(ret)
        return df

    cache_vis = cache_dir/"vis.csv"
    if cache_vis.exists():
        df = pd.read_csv(cache_vis)
    else:
        df = all_visibility()
        df.to_csv(cache_vis, index=False)

    def ci_95(group):
        n = len(group)
        mean, std = group.mean(), group.std()
        ci = 1.96 * (std / np.sqrt(n))  # 1.96 is the z-score for 95% CI
        return ci

    def custom_plot(ax, x, y, ls, lw, ms, marker, color, alpha, label, offset=3):
        line, = ax.plot(x, y, marker=marker, mew=0, ms=ms, color=color, alpha=alpha, ls="")
        for i in range(1, len(x)):
            mid_x = (x[i]+x[i-1])/2
            mid_y = (y[i]+y[i-1])/2
            t = ax.transData
            my_t = MyTransform(base_point=(mid_x, mid_y),
                    base_transform=t, offset=offset)
            t_end = t + my_t
            line, = ax.plot([x[i-1], x[i]], [y[i-1], y[i]],
                            ls=ls, lw=lw, color=color, alpha=alpha)
            line.set_transform(t_end)
        ax.plot([], [], ls=ls, lw=lw, mew=0, ms=ms, alpha=alpha,
                marker=marker, color=color, label=label)

    ax = axes[1]

    labels = ["Average", "Worst-case"]
    stats = ["mean", "min"]
    markers = ["o", "D"]
    linesyltes = ["-", "-"]
    for stat, label, ls, color, marker in zip(stats, labels, linesyltes, colors, markers):
        result = (df.loc[df["type"] == "alarm"]).groupby(
                "n_removed_vp")["vis"].agg([stat]).reset_index()
        x = result["n_removed_vp"].values.astype(int) 
        y = result[stat].values

        custom_plot(ax, x, y, ls=ls, lw=1, ms=3.5, marker=marker,
                color=color, alpha=alpha, label=label)

    ax.set_xlim(lim(x[0], x[-1], dlim))
    ax.set_xticks(x, minor=True)
    ax.set_xticks([x[0], x[-1]])
    ax.set_xticklabels([str(x[0]), str(x[-1])], fontsize=axis_fontsize)
    ax.tick_params("x", which="minor", length=2)
    ax.tick_params("x", which="major", length=4, pad=2)
    ax.text(0.5, -labelpad, "# of vantage points removed", fontsize=axis_fontsize, va="top", ha="center", transform=ax.transAxes)

    ax.set_ylim(lim(0.4, 1.0, dlim))
    ax.set_yticks(np.linspace(0.4, 1, 7))
    # ax.set_yticks(np.arange(40, 101)/100, minor=True)
    ax.set_yticklabels([f"{i}" for i in np.linspace(40, 100, 7, dtype=int)])
    ax.tick_params("y", which="major", length=3, pad=1, labelsize=axis_fontsize-3)
    ax.set_ylabel("Visibility (%)", fontsize=axis_fontsize, labelpad=0)
    ax.yaxis.set_label_coords(-0.08, 0.5)
    ax.grid(True, axis="y", ls="--", alpha=0.4, zorder=0)

    ax.text(0.985, 0.94, "5,000 random trials each.", fontsize=axis_fontsize-2, va="top", ha="right", fontstyle="italic", fontstretch="condensed", transform=ax.transAxes)

    ax.legend(fontsize=axis_fontsize-1, framealpha=0.9)

    fig.savefig(result_dir/f"vp-distribution.pdf", bbox_inches="tight")
    plt.close(fig)
vp_plot()

def time_series_plot():
    df_inci = pd.DataFrame.from_records(incidents)
    n_daily = []
    n_daily_new = []
    sigs = Counter()

    sigs_benign = set()
    
    for _, df in tuple(df_inci.groupby("time")):
        n_daily.append(df.shape[0])

        n_new = 0
        for p, eo, uo, cat in df[["prefixes", "expected_origins", "unexpected_origins", "category"]].itertuples(index=False):
            sig = (*p, *eo, *uo)
            if sig not in sigs:
                n_new += 1
            sigs[sig] += 1

            if cat == "Bad Operational Practice":
                sigs_benign.add(sig)

        n_daily_new.append(n_new)

    n_daily = np.array(n_daily)
    n_daily_new = np.array(n_daily_new)

    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator
    from matplotlib.gridspec import GridSpec
    from matplotlib.patches import Patch

    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(8, 1.6))
    gs = GridSpec(1, 2)
    gs.update(wspace=0.12)
    axes = [fig.add_subplot(gs[i]) for i in range(2)]

    dlim = 0.03
    axis_fontsize = 10
    labelpad = 0.06

    ax = axes[0]

    x = np.arange(len(n_daily))
    v1 = ax.vlines(x, 0, n_daily_new, ls="-", lw=2)
    v2 = ax.vlines(x, n_daily_new, n_daily, ls="-", lw=2, alpha=0.2)

    def lim(l, r, ratio):
        d = (r-l)*ratio
        return l-d, r+d

    ax.set_xlim(lim(0, len(x)-1, dlim))
    ax.set_xticks(x, minor=True)
    ax.set_xticks([0, len(x)-1])
    ax.set_xticklabels(["1", str(len(x))], fontsize=axis_fontsize)
    ax.tick_params("x", which="minor", length=2)
    ax.tick_params("x", which="major", length=4, pad=2)
    ax.text(0.5, -labelpad, "$n$-th day of the studied window", fontsize=axis_fontsize, va="top", ha="center", transform=ax.transAxes)

    ax.set_ylim(lim(0, 30, dlim))
    ax.set_yticks(np.arange(0, 35, 5))
    ax.set_yticks(np.arange(0, 31), minor=True)
    ax.tick_params("y", which="minor", length=2)
    ax.tick_params("y", which="major", length=4, pad=2, labelsize=axis_fontsize)
    ax.set_ylabel("Incident Count", fontsize=axis_fontsize)
    ax.grid(True, axis="y", ls="--", alpha=0.4)

    legend_handles = [
        Patch(facecolor=v1.get_colors()[0],
              alpha=v1.get_alpha(),
              label="First Observed"),
        Patch(facecolor=v2.get_colors()[0],
              alpha=v2.get_alpha(),
              label="Total Count"),
    ]

    ax.legend(handles=legend_handles, fontsize=axis_fontsize-1, loc="center", framealpha=0.9)

    ax = axes[1]

    _x0, _y0 = np.unique([v for k,v in sigs.items() if k in sigs_benign], return_counts=True)
    y0 = np.zeros_like(x, dtype=int)
    y0[_x0-1] = _y0

    _x1, _y1 = np.unique(list(sigs.values()), return_counts=True)
    y1 = np.zeros_like(x, dtype=int)
    y1[_x1-1] = _y1

    def calculate_stats(values, frequencies):
        total = np.sum(frequencies)
        mean = np.sum(values * frequencies) / total
        variance = np.sum(frequencies * (values - mean)**2) / total
        std = np.sqrt(variance)
        sorted_indices = np.argsort(values)
        sorted_values = values[sorted_indices]
        sorted_freq = frequencies[sorted_indices]
        cumsum = np.cumsum(sorted_freq)
        median_pos = total / 2
        median_index = np.searchsorted(cumsum, median_pos, side='right')
        if total % 2 == 1:
            median = sorted_values[median_index]
        else:
            if median_pos == cumsum[median_index - 1]:
                median = (sorted_values[median_index - 1] + sorted_values[median_index]) / 2
            else:
                median = sorted_values[median_index]
        return mean, std, median
    # print(calculate_stats(x+1, y1-y0))
    # print(calculate_stats(x+1, y0))

    ax.bar(x, y1-y0, width=0.5, align="edge", alpha=0.5,
            fc="firebrick", label="Risky Incidents", zorder=10)
    ax.bar(x, y0, width=-0.5, align="edge", alpha=0.5,
            fc="teal", label="Bad Practices", zorder=10)

    ax.set_xlim(lim(0, len(x)-1, dlim))
    ax.set_xticks(x, minor=True)
    ax.set_xticks([0, len(x)-1])
    ax.set_xticklabels(["1", str(len(x))], fontsize=axis_fontsize)
    ax.tick_params("x", which="minor", length=2)
    ax.tick_params("x", which="major", length=4, pad=2)
    ax.text(0.5, -labelpad, "Days observing the incident", fontsize=axis_fontsize, va="top", ha="center", transform=ax.transAxes)

    ax.set_ylim(lim(0, 30, dlim))
    ax.set_yticks(np.arange(0, 35, 5))
    ax.set_yticks(np.arange(0, 31), minor=True)
    ax.tick_params("y", which="minor", length=2)
    ax.tick_params("y", which="major", length=4, pad=2, labelsize=axis_fontsize)
    ax.grid(True, axis="y", ls="--", alpha=0.4, zorder=0)

    ax.legend(fontsize=axis_fontsize-1, loc="center", framealpha=0.9)

    # def cdf(y):
    #     y_cumsum = np.cumsum(y)
    #     return y_cumsum / y_cumsum[-1]

    # ax_ = ax.twinx()
    # ax_.set_xlim(lim(0, len(x)-1, dlim))
    # ax_.set_ylim(lim(0, 1, dlim))
    # ax_.scatter(x, cdf(y1), s=8, c=v1.get_colors()[0], alpha=0.2, edgecolor="none", marker="d", zorder=15)
    y1_cumsum = np.cumsum(y1)
    # print(y1_cumsum[:7])
    # print(y1_cumsum[:7]/y1_cumsum[-1])

    y1_cumsum = np.cumsum(y1[::-1])
    y0_cumsum = np.cumsum(y0[::-1])
    # print(y1_cumsum[:30])
    # print(y1_cumsum[:30]/y1_cumsum[-1])
    # print(y0_cumsum[:30])
    # print(y0_cumsum[:30]/y1_cumsum[-1])

    fig.savefig(result_dir/f"daily-incidents.pdf", bbox_inches="tight")
    plt.close(fig)
time_series_plot()

def breakdown_plot():
    df = pd.DataFrame.from_records(incidents)
    individual = {}

    # countries, prefixes, origins, routes, vps
    set1 = [set(), set(), set(), set(), set()] # for risky incidents
    set2 = [set(), set(), set(), set(), set()] # for bad practices

    for p, eo, uo, cat, tags, alarm_id in df[["prefixes", "expected_origins", "unexpected_origins", "category", "tags", "alarm_id"]].itertuples(index=False):
        sig = (*p, *eo, *uo)

        stats = individual.setdefault(sig, [False, False, False])

        if cat == "Bad Operational Practice":
            stats[0] = True # True if there is any sign of route engineering
            sets = set2
        else:
            sets = set1

        for i in alarm_id:
            alarm = alarmByID[i]
            if alarm["affected_prefixes"] != alarm["mis_announced_prefixes"]:
                stats[1] = True # True if it is sub-prefix hijacking

            sets[0].update([i
                    for _, _, i, _, _ in
                    alarm["organizations"]["expected_origins"].values()
                    if i]) # contries
            sets[1].update(alarm["affected_prefixes"]) # prefixes
            sets[2].update(alarm["expected_origins"]) # origins
            sets[3].update([(p,r)
                    for p,r,_ in alarm["expected_routes"]]) # routes
            sets[4].update(alarm["risk_ignorant"]) # vps

        if "Direct VP View" in tags:
            stats[2] = True # True if it is observed directly from VPs

    set_total = [a|b for a,b in zip(set1, set2)]

    # def print_stat(sets):
    #     print(f"#countries: {len(sets[0])}")
    #     print(f"#prefixes: {len(sets[1])}")
    #     print(f"#origins: {len(sets[2])}")
    #     print(f"#routes: {len(sets[3])}")
    #     print(f"#vps: {len(sets[4])}")

    # print("Potential hijacking"); print_stat(set1)
    # print("Bad practices"); print_stat(set2)
    # print("Total"); print_stat(set_total)

    def get_stat(sets):
        return {
            "#Countries": len(sets[0]),
            "#Prefixes":  len(sets[1]),
            "#Origins":   len(sets[2]),
            "#Routes":    len(sets[3]),
            "#VPs":       len(sets[4]),
        }
    json.dump({
        "Risky incidents": get_stat(set1),
        "Bad practices": get_stat(set2),
        "Total": get_stat(set_total),
    }, open(result_dir/"overall_impact.json", "w"), indent=2)

    s1, s2, s3 = np.array(list(individual.values())).T
    s1 = ~s1 # True if there is no sign of any route engineering

    # for k,v in individual.items():
    #     if not v[0] and not v[1] and v[2]: print(k)
    #     if v[0] and not v[1] and v[2]: print(k)

    def show(s):
        n = np.count_nonzero(s)
        print(n, len(s) - n)

    # show(s1)
    # show(s2)
    # show(s3)

    current_set = [True]
    set_tree = []
    for s in (s1, s2, s3):
        current_set = list(map(lambda x: x[0]&x[1], product([s, ~s], current_set)))
        set_tree.append(list(map(np.count_nonzero, current_set)))
    # print(set_tree)

    offset = 3 # NOTE
    line_set = []
    for line_len in set_tree:
        start = 0
        lines = []
        for idx, l in enumerate(line_len):
            lines.append((start, start+l))
            start += l
            if idx+1 == len(line_len)/2:
                start += offset
        line_set.append(lines)

    height = 5
    segs = []
    max_x = 0
    for level, lines in enumerate(line_set):
        mid = len(lines)//2
        y = -level*height
        segs.append([(lines[0][0], y), (lines[mid-1][1], y)]) # first half
        segs.append([(lines[mid][0], y), (lines[-1][1], y)]) # second half
        max_x = max(max_x, lines[-1][1])

    areas = []
    for level, (upper_lines, lower_lines) in enumerate(zip(line_set[:-1], line_set[1:])):
        y = -level*height
        lower_indices = np.arange(len(lower_lines)).astype(int)
        for idx, (upper_l, upper_r) in enumerate(upper_lines):
            idx0, idx1 = lower_indices[lower_indices%len(upper_lines) == idx]
            lower0_l, lower0_r = lower_lines[idx0]
            lower1_l, lower1_r = lower_lines[idx1]
            lower0_len = lower0_r - lower0_l
            lower1_len = lower1_r - lower1_l
            assert upper_r-upper_l == lower0_len+lower1_len
            half = idx%2
            if lower0_len > 0:
                areas.append(dict(
                    polygon=[
                        (upper_l, y),
                        (upper_l+lower0_len, y),
                        (lower0_r, y-height),
                        (lower0_l, y-height)
                    ], half=half))
            if lower1_len > 0:
                areas.append(dict(
                    polygon=[
                        (upper_r-lower1_len, y),
                        (upper_r, y),
                        (lower1_r, y-height),
                        (lower1_l, y-height),
                    ], half=half))

    import matplotlib.pyplot as plt
    from matplotlib.patches import Polygon, FancyArrowPatch
    from matplotlib.collections import PatchCollection, LineCollection
    import matplotlib.patheffects as path_effects
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(3,1.5))
    ax = fig.add_subplot(111)

    def padding(l, r, ratio=0.01):
        d = (r-l)*ratio
        return l-d, r+d

    ax.set_ylim(*padding(-height*(len(set_tree)-1), 0))
    ax.set_xlim(*padding(0, max_x))
    ax.axis("off")

    patches0 = []
    patches1 = []
    for area in areas:
        polygon = Polygon(area["polygon"], closed=True)
        # print(area["polygon"])
        if area["half"] == 0:
            patches0.append(polygon)
        else:
            patches1.append(polygon)
    ax.add_collection(PatchCollection(patches0, lw=0, fc="firebrick", alpha=0.35))
    ax.add_collection(PatchCollection(patches1, lw=0, ec="teal", fc="teal", alpha=0.35))

    def update_length(lw, segs): # to reduce the extra length caused by "round" capstyle
        data_coords = ax.transData.inverted().transform(
            ax.transAxes.transform((0, lw / 72))  # 72 points per inch
        )
        dx = data_coords[1] - ax.transData.inverted().transform(ax.transAxes.transform((0, 0)))[1]
        new_segs = []
        for (x0, y0), (x1, y1) in segs:
            new_segs.append([(x0+dx/2, y0), (x1-dx/2, y1)])
        return new_segs

    segs_lw = 0.8
    ax.add_collection(LineCollection(update_length(segs_lw, segs), colors="black", lw=segs_lw, path_effects=[path_effects.Stroke(capstyle="round")]))
    # print(segs)

    titles = ["Any sign of route engineering?", "Subprefix redirected?", "Directly observed from VPs?"]
    labels = ["No (risky incidents)", "Yes (bad practices)", "Yes (more impactful)", "No", "Yes", "No (less confident)"]

    title_xoffset = max_x*0.002
    text_xoffset = max_x*0.0025
    title_yoffset = height*0.175
    label_yoffset = height*0.04
    tick_size = height*0.03
    tick_width = 0.5
    for i, seg in enumerate(segs):
        (x0, y0), (x1, y1) = seg
        # title
        if i%2 == 0:
            ax.text(x0+title_xoffset, y0+title_yoffset, titles[i//2], ha="left", va="bottom", fontsize=5.5, fontweight="normal", fontstretch="normal")
        # label
        ax.text(x0+text_xoffset, y0+label_yoffset, labels[i], ha="left", va="bottom", fontsize=4, fontweight="normal", fontstretch="normal")
        # ticks
        if i//2 < 2:
            ax.add_collection(LineCollection([[(x, y0), (x, y0-tick_size)] for x in np.arange(x0+1, x1, 1)], colors="black", lw=tick_width, path_effects=[path_effects.Stroke(capstyle="round")]))
        if i//2 == 2:
            ax.add_collection(LineCollection([[(x, y0), (x, y0+tick_size)] for x in np.arange(x0+1, x1, 1)], colors="black", lw=tick_width, path_effects=[path_effects.Stroke(capstyle="round")]))

    ann_yoffset = height*0.45
    enclose_bar_size = height*0.08
    annotation_yoffset = height*0.03
    for seg in segs[:2]:
        x0 = seg[0][0]
        x1 = seg[1][0]
        y = ann_yoffset
        l = enclose_bar_size
        arrow = FancyArrowPatch((x0, y), (x1, y), arrowstyle="<|-|>", shrinkA=0, shrinkB=0, color='black', linewidth=0.5, mutation_scale=4, clip_on=False)
        ax.add_patch(arrow)
        ax.plot([x0, x0], [y-l/2, y+l/2], color='black', lw=0.5, clip_on=False)
        ax.plot([x1, x1], [y-l/2, y+l/2], color='black', lw=0.5, clip_on=False)

        n_inst = int(x1-x0)
        ax.text((x0+x1)/2, y+annotation_yoffset, f"{n_inst} incidents", ha="center", va="bottom", fontsize=4, fontweight="normal", fontstretch="normal")


    fig.tight_layout()
    fig.savefig(result_dir/"incidents-breakdown.pdf", bbox_inches="tight")
    plt.close(fig)
breakdown_plot()
