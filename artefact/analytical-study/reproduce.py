#!/usr/bin/env python
#-*- coding: utf-8 -*-
from matrix_bgpsim import RMatrix
from pathlib import Path
import numpy as np
import pandas as pd
import pickle
import json
import lz4.frame

from data.caida.as_rel import get as get_rels

script_dir = Path(__file__).resolve().parent
data_dir = script_dir/"data"
result_dir = script_dir/"result"
result_dir.mkdir(parents=True, exist_ok=True)
cache_dir = script_dir/".cache"
cache_dir.mkdir(parents=True, exist_ok=True)

as_rel_date = "20250301"
rov_date = "20250310"
as_rel_fpath = get_rels("2", as_rel_date)
matrix_dir = data_dir/"matrices"/f"as_rel_{as_rel_date}_rov_{rov_date}"

RMatrix.init_class(as_rel_fpath)

def lz4load(fpath):
    return pickle.load(lz4.frame.open(fpath, "rb"))

rm0 = RMatrix.load(matrix_dir/"normal.rm.lz4")
rm1 = RMatrix.load(matrix_dir/"rov_block.rm.lz4")

def route_set_size():
    s0 = (rm0.__state__ > 0b00111111).astype(np.float64)
    w0 = rm0.gateway_weights()
    n0 = int(np.sum(s0*w0*w0[:,None]))
    print(f"benign route set size: {n0:,}")

    s1 = (rm1.__state__ > 0b00111111).astype(np.float64)
    w1 = rm1.gateway_weights()
    n1 = int(np.sum(s1*w1*w1[:,None]))
    print(f"malicious route set size: {n1:,}")

    json.dump(dict(n_benign_route=n0, n_malicious_route=n1),
                open(result_dir/"route_number.json", "w"), indent=2)
route_set_size()

def stealthy_hijacking_instances():
    outfile = result_dir/"tab-risk-dissection.tex"
    if outfile.exists():
        outfile.unlink()

    f = outfile.open("a")
    def output_line(string):
        f.write(string+"\n")
        print(string)

    s = len(RMatrix.__idx2asn__)

    def delta(old, new):
        if new <= old:
            ret = "\\textcolor{blue}{\\scriptstyle\\blacktriangledown \\mathbf{"+f"{old-new:.3f}"+"}}"
        else:
            ret = "\\textcolor{BrickRed}{\\scriptstyle\\blacktriangle \\mathbf{"+f"{new-old:.3f}"+"}}"
        ret = ret.replace("%", "\\%")
        return ret

    def abs_str(v):
        return f"{v:.3f}"

    stats = [0, 25, 50, 75, 100]
    stats_name = ["min", "25th", "50th", "75th", "max"]
    firsts = [
        "\\textbf{$\\mathcal{P}$(*,T,H)}",
        "\\textbf{$\\mathcal{P}$(V,*,H)}",
        "\\textbf{$\\mathcal{P}$(V,T,*)}",
        "\\textbf{$\\mathcal{P}$(*,*,H)}",
        "\\textbf{$\\mathcal{P}$(*,T,*)}",
        "\\textbf{$\\mathcal{P}$(V,*,*)}",
        "\\textbf{$\\mathcal{P}$(*,*,*)}",
    ]

    results = []

    def st_sub():
        hijk_target = lz4load(matrix_dir/"mat_hijk_target_num.lz4")
        hijk_vict = lz4load(matrix_dir/"mat_hijk_vict_num.lz4")
        vict_target = lz4load(matrix_dir/"mat_vict_target_num.lz4")

        abs_result = []
        delta_result = []

        # (*, T, H)
        l = np.percentile(hijk_target/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (V, *, H)
        l = np.percentile(hijk_vict/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (V, T, *)
        l = np.percentile(vict_target/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (*, *, H)
        l = np.percentile(np.sum(hijk_target, axis=1)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (*, T, *)
        l = np.percentile(np.sum(hijk_target, axis=0)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (V, *, *)
        l = np.percentile(np.sum(vict_target, axis=1)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (*, *, *)
        l = np.sum(hijk_target)/s**3
        abs_result.append(abs_str(l))
        delta_result.append(delta(0, l))

        return [f"${i}_{{{j}}}$" for i,j in zip(abs_result, delta_result)]
    results.append(st_sub())

    def di_sub():
        s0 = rm0.__state__
        r0 = (s0 > 0b00111111).astype(np.float64)

        s1 = rm1.__state__
        r1 = (s1 > 0b00111111).astype(np.float64)

        abs_result = []
        delta_result = []

        # (*, T, H)
        l = np.percentile(np.sum(r1, axis=0)/s, stats)
        m = np.percentile(np.sum(r0, axis=0)/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (V, *, H)
        l = np.percentile(r1, stats)
        m = np.percentile(r0, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (V, T, *)
        l = np.percentile(np.sum(r1, axis=1)/s, stats)
        m = np.percentile(np.sum(r0, axis=1)/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (*, *, H)
        l = np.percentile(np.sum(r1, axis=0)/s, stats)
        m = np.percentile(np.sum(r0, axis=0)/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (*, T, *)
        l = np.sum(r1)/s**2
        m = np.sum(r0)/s**2
        abs_result += [abs_str(l)]*len(stats)
        delta_result += [delta(m, l)]*len(stats)

        # (V, *, *)
        l = np.percentile(np.sum(r1, axis=1)/s, stats)
        m = np.percentile(np.sum(r0, axis=1)/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (*, *, *)
        l = np.sum(r1)/s**2
        m = np.sum(r0)/s**2
        abs_result.append(abs_str(l))
        delta_result.append(delta(m, l))

        return [f"${i}_{{{j}}}$" for i,j in zip(abs_result, delta_result)]
    results.append(di_sub())

    def st_ex():
        hijk_target = lz4load(matrix_dir/"mat_hijk_target_num_ex.lz4")
        hijk_vict = lz4load(matrix_dir/"mat_hijk_vict_num_ex.lz4")
        vict_target = lz4load(matrix_dir/"mat_vict_target_num_ex.lz4")

        abs_result = []
        delta_result = []

        # (*, T, H)
        l = np.percentile(hijk_target/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (V, *, H)
        l = np.percentile(hijk_vict/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (V, T, *)
        l = np.percentile(vict_target/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (*, *, H)
        l = np.percentile(np.sum(hijk_target, axis=1)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (*, T, *)
        l = np.percentile(np.sum(hijk_target, axis=0)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (V, *, *)
        l = np.percentile(np.sum(vict_target, axis=1)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(0, i) for i in l]

        # (*, *, *)
        l = np.sum(hijk_target)/s**3
        abs_result.append(abs_str(l))
        delta_result.append(delta(0, l))

        return [f"${i}_{{{j}}}$" for i,j in zip(abs_result, delta_result)]
    results.append(st_ex())

    def di_ex():
        hijk_target = lz4load(matrix_dir/"mat_tgt_hijk_num_ex_direct.lz4").T
        hijk_vict = lz4load(matrix_dir/"mat_vict_hijk_num_ex_direct.lz4").T
        vict_target = lz4load(matrix_dir/"mat_vict_tgt_num_ex_direct.lz4")

        hijk_target_no_rov = lz4load(matrix_dir/"mat_tgt_hijk_num_ex_direct_without_ROV.lz4").T
        hijk_vict_no_rov = lz4load(matrix_dir/"mat_vict_hijk_num_ex_direct_without_ROV.lz4").T
        vict_target_no_rov = lz4load(matrix_dir/"mat_vict_tgt_num_ex_direct_without_ROV.lz4")

        abs_result = []
        delta_result = []

        # (*, T, H)
        l = np.percentile(hijk_target/s, stats)
        m = np.percentile(hijk_target_no_rov/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (V, *, H)
        l = np.percentile(hijk_vict/s, stats)
        m = np.percentile(hijk_vict_no_rov/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (V, T, *)
        l = np.percentile(vict_target/s, stats)
        m = np.percentile(vict_target_no_rov/s, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (*, *, H)
        l = np.percentile(np.sum(hijk_target, axis=1)/s**2, stats)
        m = np.percentile(np.sum(hijk_target_no_rov, axis=1)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (*, T, *)
        l = np.percentile(np.sum(hijk_target, axis=0)/s**2, stats)
        m = np.percentile(np.sum(hijk_target_no_rov, axis=0)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (V, *, *)
        l = np.percentile(np.sum(vict_target, axis=1)/s**2, stats)
        m = np.percentile(np.sum(vict_target_no_rov, axis=1)/s**2, stats)
        abs_result += [abs_str(i) for i in l]
        delta_result += [delta(j, i) for i,j in zip(l,m)]

        # (*, *, *)
        l = np.sum(hijk_target)/s**3
        m = np.sum(hijk_target_no_rov)/s**3
        abs_result.append(abs_str(l))
        delta_result.append(delta(m, l))

        return [f"${i}_{{{j}}}$" for i,j in zip(abs_result, delta_result)]
    results.append(di_ex())

    for i, line in enumerate(zip(*results)):
        last = i == len(stats)*(len(firsts)-1)

        if i % len(stats) == 0:
            if last:
                first = firsts[i//len(stats)]
            else:
                first = "\\multirow{"+f"{len(stats)}"+"}{*}{"+firsts[i//len(stats)]+"}"
        else:
            first = ""

        second = "---" if last else "$\mathit{"+stats_name[i % len(stats)]+"}$"

        output_line("&".join([first, second, *line])+"\\\\")

        if i % len(stats) == len(stats) - 1:
            output_line("\\hline")
stealthy_hijacking_instances()

def aggregated_risk_level():
    save_dir = result_dir
    cache_file = cache_dir/"aggregated_risk_level.cache"

    def ecdf(a, max_sample=100000):
        a = a.ravel()
        if len(a) > max_sample:
            a = np.random.choice(a, size=max_sample, replace=True)
        a = np.sort(a)
        ecdf_values = np.arange(1, len(a)+1)/len(a)
        return a, ecdf_values

    def st_sub():
        hijk_target = lz4load(matrix_dir/"mat_hijk_target_num.lz4")
        hijk_vict = lz4load(matrix_dir/"mat_hijk_vict_num.lz4")
        vict_target = lz4load(matrix_dir/"mat_vict_target_num.lz4")

        s = hijk_target.shape[0]

        TH0 = ecdf(hijk_target/s) # (*, T, H)
        VH0 = ecdf(hijk_vict/s) # (V, *, H)
        VT0 = ecdf(vict_target/s) # (V, T, *)
        H0 = ecdf(np.sum(hijk_target, axis=1)/s**2) # (*, *, H)
        T0 = ecdf(np.sum(hijk_target, axis=0)/s**2) # (*, T, *)
        V0 = ecdf(np.sum(vict_target, axis=1)/s**2) # (V, *, *)
        return TH0, VH0, VT0, H0, T0, V0

    def di_sub():
        s = len(RMatrix.__idx2asn__)

        s0 = rm0.__state__
        r0 = (s0 > 0b00111111).astype(np.float64)

        s1 = rm1.__state__
        r1 = (s1 > 0b00111111).astype(np.float64)

        TH1 = ecdf(np.sum(r1, axis=0)/s) # (*, T, H)
        VH1 = ecdf(r1) # (V, *, H)
        VT1 = ecdf(np.sum(r1, axis=1)/s) # (V, T, *)
        H1 = ecdf(np.sum(r1, axis=0)/s)# (*, *, H)
        T1 = ecdf(np.full(s, np.sum(r1)/s**2)) # (*, T, *)
        V1 = ecdf(np.sum(r1, axis=1)/s) # (V, *, *)
        return TH1, VH1, VT1, H1, T1, V1

    def st_ex():
        hijk_target = lz4load(matrix_dir/"mat_hijk_target_num_ex.lz4")
        hijk_vict = lz4load(matrix_dir/"mat_hijk_vict_num_ex.lz4")
        vict_target = lz4load(matrix_dir/"mat_vict_target_num_ex.lz4")

        s = hijk_target.shape[0]

        TH2 = ecdf(hijk_target/s) # (*, T, H)
        VH2 = ecdf(hijk_vict/s) # (V, *, H)
        VT2 = ecdf(vict_target/s) # (V, T, *)
        H2 = ecdf(np.sum(hijk_target, axis=1)/s**2) # (*, *, H)
        T2 = ecdf(np.sum(hijk_target, axis=0)/s**2) # (*, T, *)
        V2 = ecdf(np.sum(vict_target, axis=1)/s**2) # (V, *, *)
        return TH2, VH2, VT2, H2, T2, V2

    def di_ex():
        hijk_target = lz4load(matrix_dir/"mat_tgt_hijk_num_ex_direct.lz4").T
        hijk_vict = lz4load(matrix_dir/"mat_vict_hijk_num_ex_direct.lz4").T
        vict_target = lz4load(matrix_dir/"mat_vict_tgt_num_ex_direct.lz4")

        s = hijk_target.shape[0]

        TH3 = ecdf(hijk_target/s) # (*, T, H)
        VH3 = ecdf(hijk_vict/s) # (V, *, H)
        VT3 = ecdf(vict_target/s) # (V, T, *)
        H3 = ecdf(np.sum(hijk_target, axis=1)/s**2) # (*, *, H)
        T3 = ecdf(np.sum(hijk_target, axis=0)/s**2) # (*, T, *)
        V3 = ecdf(np.sum(vict_target, axis=1)/s**2) # (V, *, *)
        return TH3, VH3, VT3, H3, T3, V3

    if cache_file.exists():
        TH0, VH0, VT0, H0, T0, V0, \
        TH1, VH1, VT1, H1, T1, V1, \
        TH2, VH2, VT2, H2, T2, V2, \
        TH3, VH3, VT3, H3, T3, V3 = pickle.load(open(cache_file, "rb"))
    else:
        TH0, VH0, VT0, H0, T0, V0 = st_sub()
        TH1, VH1, VT1, H1, T1, V1 = di_sub()
        TH2, VH2, VT2, H2, T2, V2 = st_ex()
        TH3, VH3, VT3, H3, T3, V3 = di_ex()
        pickle.dump([
            TH0, VH0, VT0, H0, T0, V0,
            TH1, VH1, VT1, H1, T1, V1,
            TH2, VH2, VT2, H2, T2, V2,
            TH3, VH3, VT3, H3, T3, V3,
        ], open(cache_file, "wb"))

    def insert_lim(xy_tuple):
        x, y = xy_tuple
        x = np.insert(x, 0, 0.)
        y = np.insert(y, 0, 0.)
        x = np.append(x, 1.)
        y = np.append(y, 1.)
        return x, y

    TH0 = insert_lim(TH0); VH0 = insert_lim(VH0); VT0 = insert_lim(VT0); H0 = insert_lim(H0); T0 = insert_lim(T0); V0 = insert_lim(V0); TH1 = insert_lim(TH1); VH1 = insert_lim(VH1); VT1 = insert_lim(VT1); H1 = insert_lim(H1); T1 = insert_lim(T1); V1 = insert_lim(V1); TH2 = insert_lim(TH2); VH2 = insert_lim(VH2); VT2 = insert_lim(VT2); H2 = insert_lim(H2); T2 = insert_lim(T2); V2 = insert_lim(V2); TH3 = insert_lim(TH3); VH3 = insert_lim(VH3); VT3 = insert_lim(VT3); H3 = insert_lim(H3); T3 = insert_lim(T3); V3 = insert_lim(V3)

    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    from matplotlib.ticker import MultipleLocator
    from matplotlib.colors import to_rgba
    from itertools import cycle

    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(6,3))
    gs = gridspec.GridSpec(2, 3)
    gs.update(wspace=0.1, hspace=0.1)
    axes = [fig.add_subplot(gs[i]) for i in range(6)]

    ticklabelsize = 7
    ticklabelpad = 1
    titlefontsize = 10.5
    dlim = 0.02

    colors = cycle(['#377eb8', '#ff7f00', '#4daf4a', '#f781bf'])
    linestyles = cycle(['-', '--', ':', '-.'])

    # (*, T, H)
    ax = axes[0]

    ax.plot(*TH0, color=next(colors), linestyle=next(linestyles))
    ax.plot(*TH1, color=next(colors), linestyle=next(linestyles))
    ax.plot(*TH2, color=next(colors), linestyle=next(linestyles))
    ax.plot(*TH3, color=next(colors), linestyle=next(linestyles))
    
    ax.text(0.98+dlim, 0.05-dlim, "(*,T,H)", ha="right", va="baseline", fontsize=titlefontsize, fontweight="normal")

    ax.set_xticklabels([])
    ax.set_ylim((0-dlim, 1+dlim))
    ax.set_xlim((0-dlim, 1+dlim))
    ax.yaxis.set_major_locator(MultipleLocator(0.25))
    ax.yaxis.set_minor_locator(MultipleLocator(0.05))
    ax.xaxis.set_major_locator(MultipleLocator(0.50))
    ax.xaxis.set_minor_locator(MultipleLocator(0.10))
    ax.tick_params("both", labelsize=ticklabelsize, pad=ticklabelpad)
    ax.grid(True, which="major", axis="y", ls="--", alpha=0.5)
    ax.grid(True, which="both", axis="x", ls="--", alpha=0.5)
    ax.set_ylabel("CDF", fontsize=ticklabelsize+1)

    # (V, *, H)
    ax = axes[1]

    ax.plot(*VH0, label="St./Sub.", color=next(colors), linestyle=next(linestyles))
    ax.plot(*VH1, label="Di./Sub.", color=next(colors), linestyle=next(linestyles))
    ax.plot(*VH2, label="St./Ex.", color=next(colors), linestyle=next(linestyles))
    ax.plot(*VH3, label="Di./Ex.", color=next(colors), linestyle=next(linestyles))

    ax.text(0.98+dlim, 0.05-dlim, "(V,*,H)", ha="right", va="baseline", fontsize=titlefontsize, fontweight="normal")

    ax.set_xticklabels([])
    ax.set_yticklabels([])
    ax.set_ylim((0-dlim, 1+dlim))
    ax.set_xlim((0-dlim, 1+dlim))
    ax.yaxis.set_major_locator(MultipleLocator(0.25))
    ax.yaxis.set_minor_locator(MultipleLocator(0.05))
    ax.xaxis.set_major_locator(MultipleLocator(0.50))
    ax.xaxis.set_minor_locator(MultipleLocator(0.10))
    ax.tick_params("both", labelsize=ticklabelsize, pad=ticklabelpad)
    ax.grid(True, which="major", axis="y", ls="--", alpha=0.5)
    ax.grid(True, which="both", axis="x", ls="--", alpha=0.5)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1), ncols=4)

    # (V, T, *)
    ax = axes[2]

    ax.plot(*VT0, color=next(colors), linestyle=next(linestyles))
    ax.plot(*VT1, color=next(colors), linestyle=next(linestyles))
    ax.plot(*VT2, color=next(colors), linestyle=next(linestyles))
    ax.plot(*VT3, color=next(colors), linestyle=next(linestyles))

    ax.text(0.98+dlim, 0.05-dlim, "(V,T,*)", ha="right", va="baseline", fontsize=titlefontsize, fontweight="normal")

    ax.set_xticklabels([])
    ax.set_yticklabels([])
    ax.set_ylim((0-dlim, 1+dlim))
    ax.set_xlim((0-dlim, 1+dlim))
    ax.yaxis.set_major_locator(MultipleLocator(0.25))
    ax.yaxis.set_minor_locator(MultipleLocator(0.05))
    ax.xaxis.set_major_locator(MultipleLocator(0.50))
    ax.xaxis.set_minor_locator(MultipleLocator(0.10))
    ax.tick_params("both", labelsize=ticklabelsize, pad=ticklabelpad)
    ax.grid(True, which="major", axis="y", ls="--", alpha=0.5)
    ax.grid(True, which="both", axis="x", ls="--", alpha=0.5)

    # (*, *, H)
    ax = axes[3]

    ax.plot(*H0, color=next(colors), linestyle=next(linestyles))
    ax.plot(*H1, color=next(colors), linestyle=next(linestyles))
    ax.plot(*H2, color=next(colors), linestyle=next(linestyles))
    ax.plot(*H3, color=next(colors), linestyle=next(linestyles))

    ax.text(0.98+dlim, 0.05-dlim, "(*,*,H)", ha="right", va="baseline", fontsize=titlefontsize, fontweight="normal")

    ax.set_ylim((0-dlim, 1+dlim))
    ax.set_xlim((0-dlim, 1+dlim))
    ax.yaxis.set_major_locator(MultipleLocator(0.25))
    ax.yaxis.set_minor_locator(MultipleLocator(0.05))
    # ax.xaxis.set_major_locator(MultipleLocator(0.50))
    ax.xaxis.set_minor_locator(MultipleLocator(0.10))
    ax.set_xticks([0.0, 0.5, 1.0])
    ax.set_xticklabels([0.0, None, 1.0])
    ax.tick_params("y", labelsize=ticklabelsize, pad=ticklabelpad)
    ax.tick_params("x", labelsize=ticklabelsize, labelrotation=45, pad=ticklabelpad)
    ax.grid(True, which="major", axis="y", ls="--", alpha=0.5)
    ax.grid(True, which="both", axis="x", ls="--", alpha=0.5)
    ax.set_ylabel("CDF", fontsize=ticklabelsize+1)
    ax.set_xlabel("Agg. Risk Level", fontsize=ticklabelsize+1, labelpad=-9)

    # (*, T, *)
    ax = axes[4]

    ax.plot(*T0, color=next(colors), linestyle=next(linestyles))
    ax.plot(*T1, color=next(colors), linestyle=next(linestyles))
    ax.plot(*T2, color=next(colors), linestyle=next(linestyles))
    ax.plot(*T3, color=next(colors), linestyle=next(linestyles))

    ax.text(0.98+dlim, 0.05-dlim, "(*,T,*)", ha="right", va="baseline", fontsize=titlefontsize, fontweight="normal")

    ax.set_yticklabels([])
    ax.set_ylim((0-dlim, 1+dlim))
    ax.set_xlim((0-dlim, 1+dlim))
    ax.yaxis.set_major_locator(MultipleLocator(0.25))
    ax.yaxis.set_minor_locator(MultipleLocator(0.05))
    # ax.xaxis.set_major_locator(MultipleLocator(0.50))
    ax.xaxis.set_minor_locator(MultipleLocator(0.10))
    ax.set_xticks([0.0, 0.5, 1.0])
    ax.set_xticklabels([0.0, None, 1.0])
    ax.tick_params("y", labelsize=ticklabelsize, pad=ticklabelpad)
    ax.tick_params("x", labelsize=ticklabelsize, labelrotation=45, pad=ticklabelpad)
    ax.grid(True, which="major", axis="y", ls="--", alpha=0.5)
    ax.grid(True, which="both", axis="x", ls="--", alpha=0.5)
    ax.set_xlabel("Agg. Risk Level", fontsize=ticklabelsize+1, labelpad=-9)

    # (V, *, *)
    ax = axes[5]

    ax.plot(*V0, color=next(colors), linestyle=next(linestyles))
    ax.plot(*V1, color=next(colors), linestyle=next(linestyles))
    ax.plot(*V2, color=next(colors), linestyle=next(linestyles))
    ax.plot(*V3, color=next(colors), linestyle=next(linestyles))

    ax.text(0.98+dlim, 0.05-dlim, "(V,*,*)", ha="right", va="baseline", fontsize=titlefontsize, fontweight="normal")

    ax.set_yticklabels([])
    ax.set_ylim((0-dlim, 1+dlim))
    ax.set_xlim((0-dlim, 1+dlim))
    ax.yaxis.set_major_locator(MultipleLocator(0.25))
    ax.yaxis.set_minor_locator(MultipleLocator(0.05))
    # ax.xaxis.set_major_locator(MultipleLocator(0.50))
    ax.xaxis.set_minor_locator(MultipleLocator(0.10))
    ax.set_xticks([0.0, 0.5, 1.0])
    ax.set_xticklabels([0.0, None, 1.0])
    ax.tick_params("y", labelsize=ticklabelsize, pad=ticklabelpad)
    ax.tick_params("x", labelsize=ticklabelsize, labelrotation=45, pad=ticklabelpad)
    ax.grid(True, which="major", axis="y", ls="--", alpha=0.5)
    ax.grid(True, which="both", axis="x", ls="--", alpha=0.5)
    ax.set_xlabel("Agg. Risk Level", fontsize=ticklabelsize+1, labelpad=-9)

    fig.savefig(save_dir/"aggregated_risk_level.pdf", bbox_inches="tight")
    # fig.savefig(save_dir/"aggregated_risk_level.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
aggregated_risk_level()

def distribution_over_ASes():
    save_dir = result_dir
    cache_file = cache_dir/"distribution_over_ASes.cache"

    if cache_file.exists():
        hijk_st, vict_st, tgt_st, \
        hijk_di, vict_di, tgt_di, \
        hijk_tot, vict_tot, tgt_tot = pickle.load(open(cache_file, "rb"))
        s = len(hijk_st)
        x = np.arange(s)
    else:
        s = len(RMatrix.__idx2asn__)
        x = np.arange(s)

        hijk_vict = lz4load(matrix_dir/"mat_hijk_vict_num.lz4")
        hijk_target = lz4load(matrix_dir/"mat_hijk_target_num.lz4")
        r1 = (rm1.__state__ > 0b00111111).astype(np.float64)

        # stealthy hijacking ratios
        hijk_st = np.sum(hijk_vict, axis=1)/s**2
        vict_st = np.sum(hijk_vict, axis=0)/s**2
        tgt_st = np.sum(hijk_target, axis=0)/s**2

        # direct hijacking ratios
        hijk_di = np.sum(r1, axis=0)/s
        vict_di = np.sum(r1, axis=1)/s
        tgt_di = np.full_like(vict_di, np.sum(r1)/s**2)

        # total hijacking ratios
        hijk_tot = hijk_st + hijk_di
        vict_tot = vict_st + vict_di
        tgt_tot = tgt_st + tgt_di

        pickle.dump([
            hijk_st, vict_st, tgt_st,
            hijk_di, vict_di, tgt_di,
            hijk_tot, vict_tot, tgt_tot
        ], open(cache_file, "wb"))

    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    from matplotlib.ticker import MultipleLocator
    from matplotlib.colors import to_rgba
    from matplotlib.patches import Rectangle
    import seaborn as sns
    # sns.set_style("white")
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(12,2))
    gs = gridspec.GridSpec(1, 3, width_ratios=[1,1,1])
    axes = [fig.add_subplot(gs[i]) for i in range(3)]

    plot_args = dict(lw=1.1, alpha=0.8)
    plot_color1 = "crimson"
    plot_color2 = "darkorange"
    textfontsize = 9
    fill_color1 = "orange"
    fill_color2 = "green"
    labelsize = 11
    ticksize = 8
    legendfontsize = 9
    titlesize = 12
    title_y = -0.28
    rect_lw = 1.1
    note_lw = 1.1
    note_lspacing = 1

    # hijacker
    idx = np.argsort(hijk_tot)[::-1]
    hijk_st = hijk_st[idx]*100
    hijk_di = hijk_di[idx]*100
    hijk_tot = hijk_tot[idx]*100

    ax = axes[0]

    ax.plot(x, hijk_st, color=plot_color1, zorder=2, **plot_args)
    ax.plot(x, hijk_di, color=plot_color2, zorder=1, **plot_args)

    ax.text(0.04, 0.15, "Stealthy hijacking", ha="left", va="top", color=plot_color1, fontsize=textfontsize, fontstyle="italic", fontweight="bold", fontstretch="semi-expanded", alpha=1, zorder=3, transform=ax.transAxes)
    ax.text(0.04, 0.7, "Direct hijacking", ha="left", va="bottom", color=plot_color2, fontsize=textfontsize, fontstyle="italic", fontweight="bold", fontstretch="semi-expanded", alpha=1, zorder=3, transform=ax.transAxes)

    ax.fill_between(x, hijk_tot, 0, label="Hijacked", color=fill_color1, lw=0, alpha=0.15, zorder=0.5)
    ax.fill_between(x, hijk_tot, 100, label="Protected", color=fill_color2, lw=0, alpha=0.15, zorder=0.5)

    ax.add_patch(Rectangle(xy=(0.4*s, 50), width=0.2*s, height=14, fill=False, edgecolor="black", ls="--", lw=rect_lw, zorder=3))
    ax.add_patch(Rectangle(xy=(0.4*s, 18), width=0.2*s, height=8, fill=False, edgecolor="black", ls="--", lw=rect_lw, zorder=3))

    ax.annotate("Opposing Trends", xy=(0.45, 0.5), xycoords="axes fraction", xytext=(0.25, 0.35), textcoords="axes fraction", arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=0.2", relpos=(1, 1), facecolor="black", edgecolor=None), ha="center", fontsize=textfontsize-1, bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black", lw=note_lw, boxstyle="Round"), linespacing=note_lspacing)
    ax.annotate("Opposing Trends", xy=(0.45, 0.26), xycoords="axes fraction", xytext=(0.25, 0.35), textcoords="axes fraction", arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=-0.2", relpos=(1, 0), facecolor="black", edgecolor=None), ha="center", fontsize=textfontsize-1, bbox=dict(alpha=0, lw=note_lw, boxstyle="Round"), alpha=0, linespacing=note_lspacing)

    ax.add_patch(Rectangle(xy=(0.61*s, 0), width=0.13*s, height=60, fill=False, edgecolor="black", ls="--", lw=rect_lw, zorder=3))
    
    ax.annotate("Aligned\nTrends", xy=(0.74, 0.4), xycoords="axes fraction", xytext=(0.8, 0.7), textcoords="axes fraction", arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=-0.2", relpos=(1, 1), facecolor="black", edgecolor=None), ha="center", fontsize=textfontsize-1, bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black", lw=note_lw, boxstyle="Round"), linespacing=note_lspacing)

    ax.set_xticks([])
    ax.set_xlim(0, len(x)-1)
    ax.set_xlabel(">> Indices by descending success rate. >>", fontsize=labelsize)
    ax.set_ylabel("Succ. Rate (%)", fontsize=labelsize)
    ax.set_ylim((0, 100))
    ax.yaxis.set_major_locator(MultipleLocator(20))
    ax.yaxis.set_minor_locator(MultipleLocator(5))
    ax.yaxis.set_tick_params(labelsize=ticksize)
    ax.yaxis.set_zorder(0)
    ax.yaxis.grid(True, ls="--", alpha=0.5)
    # ax.legend(loc="upper right", fontsize=legendfontsize)
    ax.set_title("(a) Hijacker.", fontsize=titlesize, va="top", y=title_y)

    # victim
    idx = np.argsort(vict_tot)[::-1]
    vict_st = vict_st[idx]*100
    vict_di = vict_di[idx]*100
    vict_tot = vict_tot[idx]*100

    ax = axes[1]

    def convolve_smooth(y, box_pts):
        box = np.ones(box_pts)/box_pts
        y_padded = np.concatenate((y[[0]].tolist()*(box_pts-1), y))
        y_smooth = np.convolve(y_padded, box, mode='valid')
        return y_smooth
    convolve_w = 32
    smooth = lambda x: convolve_smooth(x, convolve_w)
    print(f"Convovle window: {convolve_w}")

    # ax.plot(x, vict_st, color="lightgray", zorder=0.6, alpha=0.8, lw=0.5)
    # ax.plot(x, vict_di, color="lightgray", zorder=0.7, alpha=0.8, lw=0.5)
    ax.plot(x, smooth(vict_st), color=plot_color1, zorder=2, **plot_args)
    ax.plot(x, smooth(vict_di), color=plot_color2, zorder=1, **plot_args)

    # ax.text(5000, 20, "Stealthy hijacking", ha="left", va="bottom", color=plot_color1, fontsize=textfontsize, fontstyle="italic", fontweight="bold", fontstretch="semi-expanded", alpha=1, zorder=3)
    # ax.text(7000, 7, "(Conv. smoothed$^*$)", ha="left", va="bottom", color=plot_color1, fontsize=textfontsize-2, fontstyle="italic", fontweight="bold", fontstretch="semi-expanded", alpha=1, zorder=3)
    # ax.text(5000, 75, "Direct hijacking", ha="left", va="top", color=plot_color2, fontsize=textfontsize, fontstyle="italic", fontweight="bold", fontstretch="semi-expanded", alpha=1, zorder=3)
    # ax.text(6200, 63, "(Conv. smoothed$^*$)", ha="left", va="top", color=plot_color2, fontsize=textfontsize-2, fontstyle="italic", fontweight="bold", fontstretch="semi-expanded", alpha=1, zorder=3)
    ax.text(500, 96, f"$^*$The convolution kernel size is {convolve_w}.", ha="left", va="top", color="black", fontsize=textfontsize-2, fontstyle="italic", fontweight="normal", fontstretch="normal", alpha=1, zorder=3)

    ax.fill_between(x, vict_tot, 0, label="Hijacked", color=fill_color1, lw=0, alpha=0.15, zorder=0.5)
    ax.fill_between(x, vict_tot, 100, label="Protected", color=fill_color2, lw=0, alpha=0.15, zorder=0.5)

    ax.add_patch(Rectangle(xy=(0.68*s, 0), width=0.319*s, height=60, fill=False, edgecolor="black", ls="--", lw=rect_lw, zorder=3))

    ax.annotate("Stealthy hijacking\npredominates", xy=(0.9, 0.6), xycoords="axes fraction", xytext=(0.84, 0.79), textcoords="axes fraction", arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=-0.2", relpos=(1, 1), facecolor="black", edgecolor=None), ha="center", fontsize=textfontsize-1, bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black", lw=note_lw, boxstyle="Round"), linespacing=note_lspacing)

    ax.set_xticks([])
    ax.set_xlim(0, len(x)-1)
    ax.set_xlabel(">> Indices by descending success rate. >>", fontsize=labelsize)
    ax.set_ylim((0, 100))
    ax.yaxis.set_major_locator(MultipleLocator(20))
    ax.yaxis.set_minor_locator(MultipleLocator(5))
    ax.set_yticklabels([])
    ax.yaxis.set_tick_params(labelsize=ticksize)
    ax.yaxis.set_zorder(0)
    ax.yaxis.grid(True, ls="--", alpha=0.5)
    # ax.legend(loc="upper right", fontsize=legendfontsize)
    ax.set_title("(b) Victim.", fontsize=titlesize, va="top", y=title_y)

    # target
    idx = np.argsort(tgt_tot)[::-1]
    tgt_st = tgt_st[idx]*100
    tgt_di = tgt_di[idx]*100
    tgt_tot = tgt_tot[idx]*100

    ax = axes[2]

    ax.plot(x, tgt_st, color=plot_color1, zorder=2, lw=plot_args["lw"]+0.5, alpha=plot_args["alpha"])
    ax.plot(x, tgt_di, color=plot_color2, zorder=1, lw=plot_args["lw"]+0.5, alpha=plot_args["alpha"])

    # ax.text(5000, 20, "Stealthy hijacking", ha="left", va="bottom", color=plot_color1, fontsize=textfontsize, fontstyle="italic", fontweight="bold", fontstretch="semi-expanded", alpha=1, zorder=3)
    # ax.text(5000, 80, "Direct hijacking", ha="left", va="top", color=plot_color2, fontsize=textfontsize, fontstyle="italic", fontweight="bold", fontstretch="semi-expanded", alpha=1, zorder=3)

    ax.fill_between(x, tgt_tot, 0, label="Hijacked", color=fill_color1, lw=0, alpha=0.15, zorder=0.5)
    ax.fill_between(x, tgt_tot, 100, label="Protected", color=fill_color2, lw=0, alpha=0.15, zorder=0.5)

    zero_idx = np.searchsorted(-tgt_st, 0)
    ax.annotate(f"Zero starts at\n{int(zero_idx/s*100)}th percentile", xy=(zero_idx/s, 0), xycoords="axes fraction", xytext=(0.79, 0.17), textcoords="axes fraction", arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=-0.2", relpos=(1, 0.5), facecolor="black", edgecolor=None), ha="center", fontsize=textfontsize-1, bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black", lw=note_lw, boxstyle="Round"), linespacing=note_lspacing)

    ax.annotate(f"Maximum: {tgt_st[0]:.1f}%", xy=(0, tgt_st[0]/100-0.03), xycoords="axes fraction", xytext=(0.2, 0.06), textcoords="axes fraction", arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=-0.2", relpos=(0, 0.5), facecolor="black", edgecolor=None), ha="center", fontsize=textfontsize-1, bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black", lw=note_lw, boxstyle="Round"), linespacing=note_lspacing)

    ax.annotate(f"Constant: {tgt_di[0]:.1f}%", xy=(0.6, tgt_di[0]/100+0.01), xycoords="axes fraction", xytext=(0.42, 0.56), textcoords="axes fraction", arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=-0.2", relpos=(1, 0.5), facecolor="black", edgecolor=None), ha="center", fontsize=textfontsize-1, bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black", lw=note_lw, boxstyle="Round"), linespacing=note_lspacing)

    ax.set_xticks([])
    ax.set_xlim(0, len(x)-1)
    ax.set_xlabel(">> Indices by descending success rate. >>", fontsize=labelsize)
    ax.set_ylim((0, 100))
    ax.yaxis.set_major_locator(MultipleLocator(20))
    ax.yaxis.set_minor_locator(MultipleLocator(5))
    ax.set_yticklabels([])
    ax.yaxis.set_tick_params(labelsize=ticksize)
    ax.yaxis.set_zorder(0)
    ax.yaxis.grid(True, ls="--", alpha=0.5)
    ax.legend(loc="upper right", fontsize=legendfontsize, ncols=2)
    ax.set_title("(c) Target.", fontsize=titlesize, va="top", y=title_y)

    fig.tight_layout()
    fig.savefig(save_dir/"distribution_over_ASes.pdf", bbox_inches="tight")
    # fig.savefig(save_dir/"distribution_over_ASes.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
distribution_over_ASes()

def distribution_over_geo():
    save_dir = result_dir
    cache_file = cache_dir/"distribution_over_geo.cache"

    if cache_file.exists():
        hijk_geoloc, vict_geoloc, tgt_geoloc, \
        hijk_cty, vict_cty, tgt_cty = pickle.load(open(cache_file, "rb"))
    else:
        hijk, vict, tgt, \
        _, _, _, \
        _, _, _ = pickle.load(open(cache_dir/"distribution_over_ASes.cache", "rb"))

        from data.geolite.load import load_asn2geoloc
        asn2geoloc = load_asn2geoloc("20250318")
        from data.caida.as_org import get as get_org, load as load_org
        get_org(20250301)
        as_info, org_info = load_org(20250301)

        def get_country(asn):
            if asn in as_info:
                org_id = as_info[asn]["org_id"]
                if org_id in org_info:
                    return org_info[org_id]["country"]

        n_sample = 100000

        def get_hijk_geoloc():
            geoloc = []
            for asn, w in zip(RMatrix.__idx2asn__, np.clip(hijk*2-vict-tgt, 0, None)):
                if asn in asn2geoloc:
                    geoloc += [(*i, w) for i in set(asn2geoloc[asn])]
            return np.array(geoloc)

        def get_vict_geoloc():
            geoloc = []
            for asn, w in zip(RMatrix.__idx2asn__, np.clip(vict*2-hijk-tgt, 0, None)):
                if asn in asn2geoloc:
                    geoloc += [(*i, w) for i in set(asn2geoloc[asn])]
            return np.array(geoloc)

        def get_tgt_geoloc():
            geoloc = []
            for asn, w in zip(RMatrix.__idx2asn__, np.clip(tgt*2-hijk-vict, 0, None)):
                if asn in asn2geoloc:
                    geoloc += [(*i, w) for i in set(asn2geoloc[asn])]
            return np.array(geoloc)

        def get_country_hijk():
            record = {}
            # for asn, w in zip(RMatrix.__idx2asn__, hijk):
            for asn, w in zip(RMatrix.__idx2asn__, np.clip(hijk*2-vict-tgt, 0, None)):
                country = get_country(asn)
                if country is None: continue
                if country not in record:
                    record[country] = [w]
                else:
                    record[country].append(w)
            # return {k: np.mean(v) for k,v in record.items()}
            return {k: np.sum(v) for k,v in record.items()}

        def get_country_vict():
            record = {}
            # for asn, w in zip(RMatrix.__idx2asn__, vict):
            for asn, w in zip(RMatrix.__idx2asn__, np.clip(vict*2-hijk-tgt, 0, None)):
                country = get_country(asn)
                if country is None: continue
                if country not in record:
                    record[country] = [w]
                else:
                    record[country].append(w)
            # return {k: np.mean(v) for k,v in record.items()}
            return {k: np.sum(v) for k,v in record.items()}

        def get_country_tgt():
            record = {}
            # for asn, w in zip(RMatrix.__idx2asn__, tgt):
            for asn, w in zip(RMatrix.__idx2asn__, np.clip(tgt*2-hijk-vict, 0, None)):
                country = get_country(asn)
                if country is None: continue
                if country not in record:
                    record[country] = [w]
                else:
                    record[country].append(w)
            # return {k: np.mean(v) for k,v in record.items()}
            return {k: np.sum(v) for k,v in record.items()}

        hijk_geoloc = get_hijk_geoloc()
        vict_geoloc = get_vict_geoloc()
        tgt_geoloc = get_tgt_geoloc()
        hijk_cty = get_country_hijk()
        vict_cty = get_country_vict()
        tgt_cty = get_country_tgt()
        pickle.dump([hijk_geoloc, vict_geoloc, tgt_geoloc, hijk_cty, vict_cty, tgt_cty], open(cache_file, "wb"))

    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']
    import geopandas as gpd
    import datashader as ds
    import colorcet as cc
    from datashader.mpl_ext import dsshow
    from matplotlib.colors import to_rgba
    import datashader.transfer_functions as tf
    from PIL import Image
    import warnings
    warnings.filterwarnings('ignore')

    world = gpd.read_file(gpd.datasets.get_path("naturalearth_lowres"))
    world['iso_a2'] = world['iso_a3'].apply(lambda x: x[:2])
    pw, ph = 200, 120
    titlefontsize = 28
    titleoffset = 8

    fig = plt.figure(figsize=(20, 16))
    gs = gridspec.GridSpec(3, 2)
    gs.update(wspace=0.05, hspace=0)
    axes = [fig.add_subplot(gs[i]) for i in range(6)]

    from matplotlib.colors import Normalize
    from matplotlib.colorbar import ColorbarBase
    import matplotlib.cm as cm
    cb_offset = 0.015 
    cb_height = 0.02
    ticklabelsize = 18
    pos0 = axes[4].get_position()
    pos1 = axes[5].get_position()
    cax0 = fig.add_axes([pos0.x0, pos0.y1-pos0.height-cb_offset-cb_height, pos0.width, cb_height])
    cax1 = fig.add_axes([pos1.x0, pos1.y1-pos1.height-cb_offset-cb_height, pos1.width, cb_height])
    norm = Normalize(vmin=0, vmax=1)
    cb0 = ColorbarBase(cax0, cmap="cet_fire", norm=norm, orientation='horizontal')
    cb1 = ColorbarBase(cax1, cmap="viridis", norm=norm, orientation='horizontal')
    cb0.ax.tick_params(labelsize=ticklabelsize, rotation=45)
    cb1.ax.tick_params(labelsize=ticklabelsize, rotation=45)

    # hijk tendency
    ax = axes[0]
    world.plot(color=to_rgba("black", 0.08), edgecolor="white", ax=ax, zorder=1)
    ax.set_xlim((-180, 180))
    ax.set_ylim((-90, 90))
    ax.set_xticks([])
    ax.set_yticks([])

    df = pd.DataFrame(hijk_geoloc, columns=["lat", "lon", "w"])
    canvas = ds.Canvas(plot_width=pw, plot_height=ph,
                       x_range=(-180, 180), y_range=(-90, 90))
    agg = canvas.points(df, "lon", "lat", agg=ds.mean("w"))
    img = tf.shade(agg, cmap=cc.fire, how="eq_hist")
    img_array = np.array(img.to_pil())
    ax.imshow(img_array, extent=[-180, 180, -90, 90], origin="upper", zorder=2)
    ax.text(-180+titleoffset, -90+titleoffset, "(a) Hijacker (ASes)", ha="left", va="bottom", fontsize=titlefontsize, fontweight="normal", fontstretch="semi-condensed")

    # hijk country
    ax = axes[1]
    world['weight'] = world['iso_a2'].map(hijk_cty)
    world['weight'] = world['weight'].fillna(0)
    norm = plt.Normalize(vmin=world['weight'].min(), vmax=world['weight'].max())
    world.plot(column='weight', cmap="viridis", ax=ax, edgecolor="white", norm=norm)
    ax.set_xlim((-180, 180))
    ax.set_ylim((-90, 90))
    ax.set_xticks([])
    ax.set_yticks([])
    ax.text(-180+titleoffset, -90+titleoffset, "(d) Hijacker (Countries)", ha="left", va="bottom", fontsize=titlefontsize, fontweight="normal", fontstretch="semi-condensed", bbox=dict(facecolor="white", lw=0, alpha=0.8, boxstyle="round,pad=0.1"))

    # vict tendency
    ax = axes[2]
    world.plot(color=to_rgba("black", 0.08), edgecolor="white", ax=ax, zorder=1)
    ax.set_xlim((-180, 180))
    ax.set_ylim((-90, 90))
    ax.set_xticks([])
    ax.set_yticks([])

    df = pd.DataFrame(vict_geoloc, columns=["lat", "lon", "w"])
    canvas = ds.Canvas(plot_width=pw, plot_height=ph,
                       x_range=(-180, 180), y_range=(-90, 90))
    agg = canvas.points(df, "lon", "lat", agg=ds.mean("w"))
    img = tf.shade(agg, cmap=cc.fire, how="eq_hist")
    img_array = np.array(img.to_pil())
    ax.imshow(img_array, extent=[-180, 180, -90, 90], origin="upper", zorder=2)
    ax.text(-180+titleoffset, -90+titleoffset, "(b) Victim (ASes)", ha="left", va="bottom", fontsize=titlefontsize, fontweight="normal", fontstretch="semi-condensed")

    # vict
    ax = axes[3]
    world['weight'] = world['iso_a2'].map(vict_cty)
    world['weight'] = world['weight'].fillna(0)
    norm = plt.Normalize(vmin=world['weight'].min(), vmax=world['weight'].max())
    world.plot(column='weight', cmap="viridis", ax=ax, edgecolor="white", norm=norm)
    ax.set_xlim((-180, 180))
    ax.set_ylim((-90, 90))
    ax.set_xticks([])
    ax.set_yticks([])
    ax.text(-180+titleoffset, -90+titleoffset, "(e) Victim (Countries)", ha="left", va="bottom", fontsize=titlefontsize, fontweight="normal", fontstretch="semi-condensed", bbox=dict(facecolor="white", lw=0, alpha=0.8, boxstyle="round,pad=0.1"))

    # tgt tendency
    ax = axes[4]
    world.plot(color=to_rgba("black", 0.08), edgecolor="white", ax=ax, zorder=1)
    ax.set_xlim((-180, 180))
    ax.set_ylim((-90, 90))
    ax.set_xticks([])
    ax.set_yticks([])

    df = pd.DataFrame(tgt_geoloc, columns=["lat", "lon", "w"])
    canvas = ds.Canvas(plot_width=pw, plot_height=ph,
                       x_range=(-180, 180), y_range=(-90, 90))
    agg = canvas.points(df, "lon", "lat", agg=ds.mean("w"))
    img = tf.shade(agg, cmap=cc.fire, how="eq_hist")
    img_array = np.array(img.to_pil())
    ax.imshow(img_array, extent=[-180, 180, -90, 90], origin="upper", zorder=2)
    ax.text(-180+titleoffset, -90+titleoffset, "(c) Target (ASes)", ha="left", va="bottom", fontsize=titlefontsize, fontweight="normal", fontstretch="semi-condensed")

    # tgt
    ax = axes[5]
    world['weight'] = world['iso_a2'].map(tgt_cty)
    world['weight'] = world['weight'].fillna(0)
    world = world.dropna(subset=['weight'])
    norm = plt.Normalize(vmin=world['weight'].min(), vmax=world['weight'].max())
    world.plot(column='weight', cmap="viridis", ax=ax, edgecolor="white", norm=norm)
    ax.set_xlim((-180, 180))
    ax.set_ylim((-90, 90))
    ax.set_xticks([])
    ax.set_yticks([])
    ax.text(-180+titleoffset, -90+titleoffset, "(f) Target (Countries)", ha="left", va="bottom", fontsize=titlefontsize, fontweight="normal", fontstretch="semi-condensed", bbox=dict(facecolor="white", lw=0, alpha=0.8, boxstyle="round,pad=0.1"))


    fig.savefig(save_dir/f"distribution_over_geo.pdf", bbox_inches="tight")
    plt.close(fig)
distribution_over_geo()

def factor_analysis():
    save_dir = result_dir

    hijk, vict, tgt, \
    _, _, _, \
    _, _, _ = pickle.load(open(cache_dir/"distribution_over_ASes.cache", "rb"))

    df = pd.read_csv(matrix_dir/"as_stats"/"as_stats_all.csv")

    from scipy.stats import pearsonr

    def fit2(x, y):
        a, b, c = np.polyfit(x, y, deg=2)
        y_est = a*x**2 + b*x + c
        y_err = x.std()*np.sqrt(1/len(x)+(x-x.mean())**2/np.sum((x-x.mean())**2))
        y_err = (y-y_est).std()/y_err.max()*y_err
        return y_est, y_err

    labels = [["Deg.", "Out.Deg.", "In.Deg.", "Prov.Deg.", "Cust.Deg."], ["Cust.C.Size", "Cust.C.Size(ROV)"], ["Prov.Num.", "Prov.Num.(ROV)"], ["Heg.", "Heg.(ROV)", "Heg.(Pre-ROV)", "Heg.(Post-ROV)"], ["Min.Dist.ROV", "Max.Dist.ROV", "Avg.Dist.ROV"], ["Cumul.Heg.", "Cumul.Heg.(ROV)", "Cumul.Heg.(Pre-ROV)", "Cumul.Heg.(Post-ROV)"], ["Avg.Heg.", "Avg.Heg.(ROV)", "Avg.Heg.(Pre-ROV)", "Avg.Heg.(Post-ROV)"]]
    groups = ["Degree Related", "Cone Related", "Funnel Related", "Hegemony Related", "Distance Related", "Cumulative Stats", "Average Stats"]
    show_labels = [[f"{j}{x}" for x in range(len(i))]
                for i,j in zip(labels, ["De", "Co", "Fu", "He", "Di", "Cm", "Av"])]
    hatches =['//', '\\\\', 'xx', '..', '//', '\\\\', 'xx']
    colors = [
        "#C68F00",  # Darker Orange
        "#46A4D9",  # Darker Sky Blue
        "#008E63",  # Darker Bluish Green
        "#E0D442",  # Darker Yellow
        "#0062A2",  # Darker Blue
        "#B55000",  # Darker Vermilion
        "#BC6999"   # Darker Reddish Purple
    ]

    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    from matplotlib.ticker import MultipleLocator
    from matplotlib.patches import ConnectionPatch, Rectangle
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(6, 5))
    gs = gridspec.GridSpec(3, 1)
    gs.update(hspace=0.1)
    axes = [fig.add_subplot(gs[i]) for i in range(3)]

    # hijacker
    ax = axes[0]

    start_idx = 0
    bars = []
    columns = df.columns
    for ls, g, hat, c in zip(labels, groups, hatches, colors):
        h1 = np.abs([pearsonr(
                hijk, df[columns[start_idx+i]].values).statistic
                for i, m in enumerate(ls)])
        h2 = np.abs([pearsonr(
                hijk, fit2(df[columns[start_idx+i]].values, hijk)[0]).statistic
                for i, m in enumerate(ls)])
        h = np.maximum(h1, h2)
        b = ax.bar(np.arange(start_idx, start_idx+len(ls)),
                h+0.05, bottom=-0.05, label=g, hatch=hat, edgecolor=c, color="white")
        start_idx += len(ls)
        bars.append(b)

        if g == "Cumulative Stats":
            ax_inset = ax.inset_axes((10.5, 0.62, 4, 0.3), transform=ax.transData)
            bars_inset = ax_inset.bar(np.arange(len(ls)), h,
                            hatch=hat, edgecolor=c, color="white")
            ax_inset.set_xlim(-0.5, len(ls)-0.5)
            ax_inset.set_xticks([])
            ax_inset.set_ylim(0.9945, 0.9975)
            ax_inset.set_yticks([0.995, 0.996, 0.997])
            ax_inset.set_yticks([0.9955, 0.9965], minor=True)
            ax_inset.set_yticklabels(["0.995", "", "0.997"], fontsize=8)
            ax_inset.tick_params(axis="both", which="major", pad=0)
            ax_inset.yaxis.set_zorder(0)
            ax_inset.grid(True, ls="--", alpha=0.5)

            rect = Rectangle((15.4, 0.90), 4.2, 0.12,
                    lw=0.8, ls="--", ec="black", fc="none", transform=ax.transData)
            ax.add_patch(rect)

            con1 = ConnectionPatch(xyA=(15.3, 0.97), xyB=(3, 0.9975),
                    coordsA="data", coordsB="data", arrowstyle="fancy",
                    connectionstyle="arc3,rad=0.2", ec="none",
                    axesA=ax, axesB=ax_inset, fc="black", alpha=0.8)
            ax.add_patch(con1)

    legend_labels = [""] + groups
    legend_handles = [plt.Line2D([0], [0], color='none')] + [bar[0] for bar in bars]
    ordered_handles = [
        legend_handles[0], legend_handles[1], legend_handles[4], legend_handles[2],
        legend_handles[5], legend_handles[3], legend_handles[6], legend_handles[7]
    ]
    ordered_labels = [
        legend_labels[0], legend_labels[1], legend_labels[4], legend_labels[2],
        legend_labels[5], legend_labels[3], legend_labels[6], legend_labels[7]
    ]
    legend = ax.legend(handles=ordered_handles, labels=ordered_labels,
            loc='lower left', bbox_to_anchor=(-0.05, 1), ncol=4, frameon=False,
            fontsize=8, handletextpad=0.4, labelspacing=0.4, columnspacing=0.6,
            handlelength=1, handleheight=0.8)
    ax.text(-0.03, 1.25, "Feature Group:", ha='left', va="center", transform=ax.transAxes, fontsize=8, weight='bold')

    ax.set_xlabel(None)
    ax.set_xlim(-1, start_idx)
    ax.set_xticks(np.arange(start_idx, dtype=int))
    ax.set_xticklabels([])
    ax.set_ylabel(None)
    ax.set_ylim((-.05, 1.05))
    ax.set_yticks(MultipleLocator(.05).tick_values(vmin=.05, vmax=.95), minor=True)
    ax.yaxis.set_major_locator(MultipleLocator(.2))
    ax.yaxis.set_zorder(0)
    ax.yaxis.grid(True, ls="--", alpha=0.5)
    ax.text(0.02, 0.95, "(a) Attacker", ha='left', va="top", transform=ax.transAxes, fontsize=12, bbox=dict(facecolor="white", lw=0, alpha=0.8))

    # victim
    ax = axes[1]

    start_idx = 0
    for ls, g, hat, c in zip(labels, groups, hatches, colors):
        h1 = np.abs([pearsonr(
                vict, df[columns[start_idx+i]].values).statistic
                for i, m in enumerate(ls)])
        h2 = np.abs([pearsonr(
                vict, fit2(df[columns[start_idx+i]].values, vict)[0]).statistic
                for i, m in enumerate(ls)])
        h = np.maximum(h1, h2)
        ax.bar(np.arange(start_idx, start_idx+len(ls)),
            h+0.05, bottom=-0.05, label=g, hatch=hat, edgecolor=c, color="white")
        start_idx += len(ls)

        if g == "Cumulative Stats":
            ax_inset = ax.inset_axes((10.5, 0.65, 4, 0.3), transform=ax.transData)
            bars_inset = ax_inset.bar(np.arange(len(ls)), h,
                            hatch=hat, edgecolor=c, color="white")
            ax_inset.set_xlim(-0.5, len(ls)-0.5)
            ax_inset.set_xticks([])
            ax_inset.set_ylim(0.9475, 0.9493)
            ax_inset.set_yticks([0.9478, 0.9484, 0.9490])
            ax_inset.set_yticks([0.9481, 0.9487], minor=True)
            ax_inset.set_yticklabels(["0.9478", "", "0.9490"], fontsize=8)
            ax_inset.tick_params(axis="both", which="major", pad=0)
            ax_inset.yaxis.set_zorder(0)
            ax_inset.grid(True, ls="--", alpha=0.5)

            rect = Rectangle((15.4, 0.88), 4.2, 0.14,
                    lw=0.8, ls="--", ec="black", fc="none", transform=ax.transData)
            ax.add_patch(rect)

            con1 = ConnectionPatch(xyA=(15.3, 0.98), xyB=(3, 0.9493),
                    coordsA="data", coordsB="data", arrowstyle="fancy",
                    connectionstyle="arc3,rad=0.2", ec="none",
                    axesA=ax, axesB=ax_inset, fc="black", alpha=0.8)
            ax.add_patch(con1)

    ax.set_xlabel(None)
    ax.set_xlim(-1, start_idx)
    ax.set_xticks(np.arange(start_idx, dtype=int))
    ax.set_xticklabels([])
    ax.set_ylabel("Absolute Pearson Correlation Coefficient")
    ax.set_ylim((-.05, 1.05))
    ax.set_yticks(MultipleLocator(.05).tick_values(vmin=.05, vmax=.95), minor=True)
    ax.yaxis.set_major_locator(MultipleLocator(.2))
    ax.yaxis.set_zorder(0)
    ax.yaxis.grid(True, ls="--", alpha=0.5)
    ax.text(0.02, 0.95, "(b) Victim", ha='left', va="top", transform=ax.transAxes, fontsize=12, bbox=dict(facecolor="white", lw=0, alpha=0.8))

    # target
    ax = axes[2]

    start_idx = 0
    for ls, g, hat, c in zip(labels, groups, hatches, colors):
        h1 = np.abs([pearsonr(
                tgt, df[columns[start_idx+i]].values).statistic
                for i, m in enumerate(ls)])
        h2 = np.abs([pearsonr(
                tgt, fit2(df[columns[start_idx+i]].values, tgt)[0]).statistic
                for i, m in enumerate(ls)])
        h = np.maximum(h1, h2)
        ax.bar(np.arange(start_idx, start_idx+len(ls)), h+0.05, bottom=-0.05, label=g, hatch=hat, edgecolor=c, color="white")
        start_idx += len(ls)

        if g == "Cumulative Stats":
            ax_inset = ax.inset_axes((10.5, 0.6, 4, 0.3), transform=ax.transData)
            bars_inset = ax_inset.bar(np.arange(len(ls)), h,
                            hatch=hat, edgecolor=c, color="white")
            ax_inset.set_xlim(-0.5, len(ls)-0.5)
            ax_inset.set_xticks([])
            ax_inset.set_ylim(0.7775, 0.7865)
            ax_inset.set_yticks([0.779, 0.782, 0.785])
            ax_inset.set_yticks([0.7805, 0.7835], minor=True)
            ax_inset.set_yticklabels(["0.779", "", "0.785"], fontsize=8)
            ax_inset.tick_params(axis="both", which="major", pad=0)
            ax_inset.yaxis.set_zorder(0)
            ax_inset.grid(True, ls="--", alpha=0.5)

            rect = Rectangle((15.4, 0.73), 4.2, 0.14,
                    lw=0.8, ls="--", ec="black", fc="none", transform=ax.transData)
            ax.add_patch(rect)

            con1 = ConnectionPatch(xyA=(15.3, 0.8), xyB=(3.5, 0.782),
                    coordsA="data", coordsB="data", arrowstyle="fancy",
                    connectionstyle="arc3,rad=0.2", ec="none",
                    axesA=ax, axesB=ax_inset, fc="black", alpha=0.8)
            ax.add_patch(con1)

    ax.set_xlabel(None)
    ax.set_xlim(-1, start_idx)
    ax.set_xticks(np.arange(start_idx, dtype=int))
    ax.set_xticklabels([j for i in show_labels for j in i], rotation=45, fontsize=8)
    ax.set_ylabel(None)
    ax.set_ylim((-.05, 1.05))
    ax.set_yticks(MultipleLocator(.05).tick_values(vmin=.05, vmax=.95), minor=True)
    ax.yaxis.set_major_locator(MultipleLocator(.2))
    ax.yaxis.set_zorder(0)
    ax.yaxis.grid(True, ls="--", alpha=0.5)
    ax.text(0.02, 0.95, "(c) Target", ha='left', va="top", transform=ax.transAxes, fontsize=12, bbox=dict(facecolor="white", lw=0, alpha=0.8))

    fig.savefig(save_dir/f"factor_analysis.pdf", bbox_inches="tight")
    plt.close(fig)
factor_analysis()

def correlation_scatter():
    save_dir = result_dir

    hijk, vict, tgt, \
    _, _, _, \
    _, _, _ = pickle.load(open(cache_dir/"distribution_over_ASes.cache", "rb"))

    df = pd.read_csv(matrix_dir/"as_stats"/"as_stats_all.csv")
    labels = [["Deg.", "Out.Deg.", "In.Deg.", "Prov.Deg.", "Cust.Deg."], ["Cust.C.Size", "Cust.C.Size(ROV)"], ["Prov.Num.", "Prov.Num.(ROV)"], ["Heg.", "Heg.(ROV)", "Heg.(Pre-ROV)", "Heg.(Post-ROV)"], ["Min.Dist.ROV", "Max.Dist.ROV", "Avg.Dist.ROV"], ["Cumul.Heg.", "Cumul.Heg.(ROV)", "Cumul.Heg.(Pre-ROV)", "Cumul.Heg.(Post-ROV)"], ["Avg.Heg.", "Avg.Heg.(ROV)", "Avg.Heg.(Pre-ROV)", "Avg.Heg.(Post-ROV)"]]
    groups = ["Degree Related", "Cone Related", "Funnel Related", "Hegemony Related", "Distance Related", "Cumulative Stats", "Averagd Stats"]
    show_labels = [[f"{j}{x}" for x in range(len(i))]
                for i,j in zip(labels, ["De", "Co", "Fu", "He", "Di", "Cm", "Av"])]

    from scipy.stats import pearsonr

    def fit1(x, y):
        a, b = np.polyfit(x, y, deg=1)
        y_est = a*x + b
        y_err = x.std()*np.sqrt(1/len(x)+(x-x.mean())**2/np.sum((x-x.mean())**2))
        y_err = (y-y_est).std()/y_err.max()*y_err
        return y_est, y_err

    def fit2(x, y):
        a, b, c = np.polyfit(x, y, deg=2)
        y_est = a*x**2 + b*x + c
        y_err = x.std()*np.sqrt(1/len(x)+(x-x.mean())**2/np.sum((x-x.mean())**2))
        y_err = (y-y_est).std()/y_err.max()*y_err
        return y_est, y_err

    def norm(x):
        xmin = np.min(x)
        xmax = np.max(x)
        return (x-xmin)/(xmax-xmin)

    def get_data(stats):
        group_best_r = []
        group_best_col = []
        label_best = []
        col_idx = 0
        for s_labels, g_labels in zip(show_labels, labels):
            columns = df.columns[col_idx:col_idx+len(g_labels)]
            r1_values = [pearsonr(stats, df[metric].values).statistic
                            for metric in columns]
            r2_values = [pearsonr(stats, fit2(df[metric].values, stats)[0]).statistic
                            for metric in columns]
            r_values = np.maximum(np.abs(r1_values), np.abs(r2_values))
            idx = np.argmax(r_values)
            group_best_col.append(columns[idx])
            label_best.append(s_labels[idx])
            group_best_r.append((r1_values[idx], r2_values[idx]))
            col_idx += len(g_labels)
        return group_best_col, group_best_r, label_best


    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator
    from matplotlib.gridspec import GridSpec
    import datashader as ds
    import colorcet as cc
    from datashader.mpl_ext import dsshow
    from matplotlib.colors import to_rgba
    import datashader.transfer_functions as tf
    from PIL import Image
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(30, 5))
    gs = GridSpec(2, 12, figure=fig)

    titleoffset = 0.06

    all_axes = []
    for column_base in [0, 4, 8]:
        all_axes.append(fig.add_subplot(gs[0:2, column_base:column_base+2]))
        all_axes.append(fig.add_subplot(gs[0, column_base+2]))
        all_axes.append(fig.add_subplot(gs[0, column_base+3]))
        all_axes.append(fig.add_subplot(gs[1, column_base+2]))
        all_axes.append(fig.add_subplot(gs[1, column_base+3]))

    for i, ax in enumerate(all_axes):
        ax.set_aspect('equal')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.tick_params(axis='both', which='major', direction='in',
                       bottom=True, top=True, left=True, right=True,
                       width=2, length=7.5 if i%5 == 0 else 5)
        ax.yaxis.set_major_locator(MultipleLocator(0.05))
        ax.xaxis.set_major_locator(MultipleLocator(0.05))
        for p in ["left", "right", "top", "bottom"]:
            ax.spines[p].set_linewidth(2)
        ax.set_xticklabels([])
        ax.set_yticklabels([])

    fig.text(1/6, -0.035, "(a) Hijacker", ha="center", va="top", fontsize=30)
    fig.text(1/2, -0.035, "(b) Victim", ha="center", va="top", fontsize=30)
    fig.text(5/6, -0.035, "(c) Target", ha="center", va="top", fontsize=30)

    def plot(axes, stats, title_no):
        group_best_col, group_best_r, label_best = get_data(stats)
        for idx, (i, ax) in enumerate(zip(np.argsort(
                    np.max(np.abs(group_best_r), axis=1))[:-6:-1], axes)):
            values = df[group_best_col[i]].values
            sorted_indices = np.argsort(values)
            values = values[sorted_indices]
            stats = stats[sorted_indices]

            ax.text((titleoffset/2) if idx == 0 else titleoffset,
                    (1-titleoffset/2) if idx == 0 else (1-titleoffset),
                    f"({title_no}{idx+1}) {label_best[i]}", ha="left", va="top",
                    bbox=dict(facecolor="white", lw=0, alpha=0.8,
                    boxstyle="round,pad=0.1"),
                    fontsize=20, transform=ax.transAxes)

            values = norm(values)
            stats = norm(stats)

            y_est, y_err = fit1(values, stats)
            p1 = ax.plot(values, y_est, ls="--", lw=2, zorder=2)
            ax.fill_between(values, (y_est-y_err), (y_est+y_err),
                            alpha=0.2, zorder=1.5)

            y_est, y_err = fit2(values, stats)
            p2 = ax.plot(values, y_est, ls="--", lw=2, zorder=2)
            ax.fill_between(values, (y_est-y_err), (y_est+y_err),
                            alpha=0.2, zorder=1.5)

            canvas = ds.Canvas(plot_width=150, plot_height=150,
                               x_range=(0, 1), y_range=(0, 1))
            agg = canvas.points(pd.DataFrame.from_dict(dict(x=values, y=stats)),
                                "x", "y", agg=ds.count())
            img = tf.shade(agg, cmap=['#A0A0A0', '#000000'], how="eq_hist")
            img_array = np.array(img.to_pil())
            ax.imshow(img_array, extent=[0, 1, 0, 1],
                    origin="upper", zorder=0, alpha=0.75)

            if title_no == "a" and idx == 0:
                r1, r2 = group_best_r[i]
                ax.text(0.65, 0.45, f"r1={r1:.2f}", fontweight="semibold",
                        va="center", ha="center", color=p1[0].get_color(),
                        transform=ax.transData, rotation=38, fontsize=20, alpha=0.7)
                ax.text(0.20, 0.7, f"r2={r2:.2f}", fontweight="semibold",
                        va="center", ha="center", color=p2[0].get_color(),
                        transform=ax.transData, rotation=52, fontsize=20, alpha=0.7)
            if title_no == "b" and idx == 0:
                r1, r2 = group_best_r[i]
                ax.text(0.5-0.2, 0.4+0.2*np.tan(np.tan(30/180*np.pi)),
                        f"r1={r1:.2f}", fontweight="semibold",
                        va="center", ha="center", color=p1[0].get_color(),
                        transform=ax.transData, rotation=-32, fontsize=20, alpha=0.7)
                ax.text(0.5+0.2, 0.4-0.2*np.tan(np.tan(30/180*np.pi)),
                        f"r2={r2:.2f}", fontweight="semibold",
                        va="center", ha="center", color=p2[0].get_color(),
                        transform=ax.transData, rotation=-32, fontsize=20, alpha=0.7)
            if title_no == "c" and idx == 0:
                r1, r2 = group_best_r[i]
                ax.text(0.5-0.06, 0.7-0.2*np.tan(np.tan(20/180*np.pi)),
                        f"r1={r1:.2f}", fontweight="semibold",
                        va="center", ha="right", color=p1[0].get_color(),
                        transform=ax.transData, rotation=20, fontsize=20, alpha=0.7)
                ax.text(0.5+0.06, 0.7+0.2*np.tan(np.tan(20/180*np.pi)),
                        f"r2={r2:.2f}", fontweight="semibold",
                        va="center", ha="left", color=p2[0].get_color(),
                        transform=ax.transData, rotation=20, fontsize=20, alpha=0.7)

    # hijacker
    column_base = 0
    axes = all_axes[column_base:column_base+5]
    plot(axes, hijk, "a")

    # victim
    column_base = 5
    axes = all_axes[column_base:column_base+5]
    plot(axes, vict, "b")

    # target
    column_base = 10
    axes = all_axes[column_base:column_base+5]
    plot(axes, tgt, "c")

    fig.tight_layout()
    fig.savefig(save_dir/f"correlation_scatter.pdf", bbox_inches="tight")
    plt.close(fig)
correlation_scatter()

def risk_attribution():
    save_dir = result_dir
    cache_file = cache_dir/"risk_attribution.cache"

    def load_key_stats(role):
        role_key = lz4load(matrix_dir/f"mat_{role}_key_num.lz4")
        key_sizes = np.sum(role_key, axis=0)
        return key_sizes, role_key

    from numba import njit
    @njit("void(int64[:],int32[:],int32[:])", nogil=True)
    def set_rov_count(vec_count, rov_idx, weight):
        for idx, cnt in zip(rov_idx, weight):
            vec_count[idx] += cnt

    def load_rov_stats():
        vict_hijk_rov_idx = lz4load(matrix_dir/f"vict_hijk_rov_idx.lz4")
        vict_hijk = lz4load(matrix_dir/f"mat_hijk_vict_num.lz4").T
        mask = vict_hijk_rov_idx != -1
        vec_count = np.zeros(vict_hijk.shape[0], dtype=np.int64)
        set_rov_count(vec_count, vict_hijk_rov_idx[mask], vict_hijk[mask])
        rov_cnt = vec_count[vec_count > 0]
        return rov_cnt

    if cache_file.exists():
        key_sizes, vict_key, rov_cnt = pickle.load(open(cache_file, "rb"))
    else:
        key_sizes, vict_key = load_key_stats("vict")
        rov_cnt = load_rov_stats()
        pickle.dump([key_sizes, vict_key, rov_cnt], open(cache_file, "wb"))

    def get_pareto(data):
        sorted_data = np.sort(data.ravel())[::-1]
        cumulative_sum = np.cumsum(sorted_data)
        cumulative_percentage = cumulative_sum / cumulative_sum[-1] * 100
        return sorted_data, cumulative_percentage

    def insert_origin(xy_tuple):
        x, y = xy_tuple
        x = np.insert(x, 0, 0.)
        y = np.insert(y, 0, 0.)
        return x, y

    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator
    from matplotlib.gridspec import GridSpec
    from matplotlib.colors import to_rgba
    import matplotlib.patches as patches
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

    fig = plt.figure(figsize=(8, 3))
    gs = GridSpec(1, 2)
    gs.update(wspace=0.2)
    axes = [fig.add_subplot(gs[i]) for i in range(2)]

    dlim = 0.02
    xlabelpad = -8
    ylabelpad = 4
    labelfontsize = 11
    ticklabelsize = 10
    ticklabelpad = 4

    colors = ['#377eb8', '#ff7f00']

    # Risk-Critical ASes
    ax = axes[0]

    key_sizes = key_sizes[key_sizes>0]
    x = np.arange(len(key_sizes))
    y1, y2 = get_pareto(key_sizes)

    l = ax.plot(x, y1, color=colors[0], lw=2, zorder=1, label="Instance Count")
    ax.fill_between(x, y1, 0, color=l[0].get_color(), lw=0, alpha=0.5, zorder=0.5)

    ax.set_xlim(-dlim*x[-1], x[-1]*(1+dlim))
    ax.set_ylim(-dlim*y1[0], y1[0]*(1+dlim))
    ax.set_xticks(np.linspace(0, x[-1], 11))
    ax.set_xticklabels(["0"]+[""]*9+[str(x[-1])])
    ax.yaxis.set_major_locator(MultipleLocator(1e11))
    ax.yaxis.set_minor_locator(MultipleLocator(2e10))
    ax.set_xlabel("Risk-Critical AS Index", fontsize=labelfontsize+2, labelpad=xlabelpad)
    ax.set_ylabel("Instance Count", fontsize=labelfontsize+1, labelpad=ylabelpad)
    ax.tick_params("both", labelsize=ticklabelsize, pad=ticklabelpad)
    ax.yaxis.set_zorder(0)
    ax.xaxis.set_zorder(0)
    ax.grid(True, which="major", axis="both", ls="--", alpha=0.5)

    ax_ = ax.twinx()
    ax_.set_xlim(-dlim*x[-1], x[-1]*(1+dlim))
    ax_.set_ylim(-dlim*100, 100*(1+dlim))
    l = ax_.plot(*insert_origin((x, y2)), lw=2, color=colors[1], label="Cumulative Percentage")

    idx80 = np.searchsorted(y2, 80)
    ax_.hlines(80, xmin=idx80, xmax=np.max(x), lw=2, ls=":", color="black", zorder=1)
    ax_.vlines(idx80, ymin=0, ymax=80, lw=2, ls=":", color="black", zorder=1)
    ax_.scatter([idx80], [y2[idx80]], s=18, c=l[0].get_color(), marker="o", lw=0, zorder=2)
    ax_.text(np.max(x), 80, "80% Cut off (80:20 Rule)",
            color="black", va="bottom", ha="right",
            fontsize=labelfontsize-1, transform=ax_.transData)

    ax.axvspan(0, idx80, ymin=dlim/(1+dlim*2), ymax=1-dlim/(1+dlim*2),
                color='yellow', alpha=0.3, zorder=0)
    ax_.annotate(f"Vital Few: {idx80}", xy=(idx80*0.40, 35),
             xytext=(np.max(x)*0.1, 50),
             arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=0.1",
                 relpos=(0, 0), facecolor="black", edgecolor=None),
             fontsize=labelfontsize, color="black",
             bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black",
                 lw=1, boxstyle="Round"))

    loff = 0.01*np.max(x)
    bracket_x = [idx80+loff, idx80+loff, (idx80+loff+np.max(x))/2, (idx80+loff+np.max(x))/2, (idx80+loff+np.max(x))/2, np.max(x), np.max(x)]
    bracket_y = [4, 8, 8, 12, 8, 8, 4]
    bracket = patches.Polygon(xy=list(zip(bracket_x, bracket_y)), closed=False, facecolor='none', edgecolor="black", linewidth=1)
    ax_.add_patch(bracket)
    ax_.text((idx80+loff+np.max(x))/2, 17, f"Trivial Many: {np.max(x)-idx80:,}",
            va = "bottom", ha="center",
            transform=ax_.transData, fontsize=labelfontsize, color="black",
            bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black",
                 lw=1, boxstyle="Round"))

    ax_.yaxis.set_major_locator(MultipleLocator(20))
    ax_.yaxis.set_minor_locator(MultipleLocator(5))
    ax_.tick_params("both", labelsize=ticklabelsize, pad=ticklabelpad)
    ax_.yaxis.set_zorder(0)
    ax_.xaxis.set_zorder(0)

    ax.spines['left'].set_color(colors[0])
    ax.spines["right"].set_visible(False)
    ax.spines["top"].set_visible(False)
    ax.tick_params(axis='y', which="both", colors=colors[0])
    ax.yaxis.label.set_color(colors[0])

    ax_.spines["right"].set_color(colors[1])
    ax_.spines['left'].set_visible(False)
    ax_.spines["top"].set_visible(False)
    ax_.tick_params(axis='y', which="both", colors=colors[1])
    ax_.yaxis.label.set_color(colors[1])

    # fig.legend(fontsize=labelfontsize, loc="lower center", bbox_to_anchor=(0.5, 0.88), ncols=2)

    # ROV-Enabled ASes
    ax = axes[1]

    x = np.arange(len(rov_cnt))
    y1, y2 = get_pareto(rov_cnt)

    l = ax.plot(x, y1, color=colors[0], lw=2, zorder=1)
    ax.fill_between(x, y1, 0, color=l[0].get_color(), lw=0, alpha=0.5, zorder=0.5)

    ax.set_xlim(-dlim*x[-1], x[-1]*(1+dlim))
    ax.set_ylim(-dlim*y1[0], y1[0]*(1+dlim))
    ax.set_xticks(np.linspace(0, x[-1], 11))
    ax.set_xticklabels(["0"]+[""]*9+[str(x[-1])])
    ax.yaxis.set_major_locator(MultipleLocator(1e12))
    ax.yaxis.set_minor_locator(MultipleLocator(2e11))
    ax.set_xlabel("ROV-Enabled AS Index", fontsize=labelfontsize+2, labelpad=xlabelpad)
    ax.tick_params("both", labelsize=ticklabelsize, pad=ticklabelpad)
    ax.yaxis.set_zorder(0)
    ax.xaxis.set_zorder(0)
    ax.grid(True, which="major", axis="both", ls="--", alpha=0.5)

    ax_ = ax.twinx()
    ax_.set_xlim(-dlim*x[-1], x[-1]*(1+dlim))
    ax_.set_ylim(-dlim*100, 100*(1+dlim))
    l = ax_.plot(*insert_origin((x, y2)), lw=2, color=colors[1])

    idx80 = np.searchsorted(y2, 80)
    ax_.hlines(80, xmin=idx80, xmax=np.max(x), lw=2, ls=":", color="black", zorder=1)
    ax_.vlines(idx80, ymin=0, ymax=80, lw=2, ls=":", color="black", zorder=1)
    ax_.scatter([idx80], [y2[idx80]], s=18, c=l[0].get_color(), marker="o", lw=0, zorder=2)
    ax_.text(np.max(x), 80, "80% Cut off (80:20 Rule)",
            color="black", va="bottom", ha="right",
            fontsize=labelfontsize-1, transform=ax_.transData)

    ax.axvspan(0, idx80, ymin=dlim/(1+dlim*2), ymax=1-dlim/(1+dlim*2),
                color='yellow', alpha=0.3, zorder=0)
    ax_.annotate(f"Vital Few: {idx80}", xy=(idx80*0.40, 35),
             xytext=(np.max(x)*0.1, 50),
             arrowprops=dict(arrowstyle="fancy", connectionstyle="arc3,rad=0.1",
                 relpos=(0, 0), facecolor="black", edgecolor=None),
             fontsize=labelfontsize, color="black",
             bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black",
                 lw=1, boxstyle="Round"))

    loff = 0.01*np.max(x)
    bracket_x = [idx80+loff, idx80+loff, (idx80+loff+np.max(x))/2, (idx80+loff+np.max(x))/2, (idx80+loff+np.max(x))/2, np.max(x), np.max(x)]
    bracket_y = [4, 8, 8, 12, 8, 8, 4]
    bracket = patches.Polygon(xy=list(zip(bracket_x, bracket_y)), closed=False, facecolor='none', edgecolor="black", linewidth=1)
    ax_.add_patch(bracket)
    ax_.text((idx80+loff+np.max(x))/2, 18, f"Trivial Many: {np.max(x)-idx80:,}",
            va = "bottom", ha="center",
            transform=ax_.transData, fontsize=labelfontsize, color="black",
            bbox=dict(facecolor=to_rgba("white", alpha=0.5), edgecolor="black",
                 lw=1, boxstyle="Round"))

    ax_.set_ylabel("Cumulative Percentage", fontsize=labelfontsize+1, labelpad=ylabelpad)
    ax_.yaxis.set_major_locator(MultipleLocator(20))
    ax_.yaxis.set_minor_locator(MultipleLocator(5))
    ax_.tick_params("both", labelsize=ticklabelsize, pad=ticklabelpad)
    ax_.yaxis.set_zorder(0)
    ax_.xaxis.set_zorder(0)

    ax.spines['left'].set_color(colors[0])
    ax.spines["right"].set_visible(False)
    ax.spines["top"].set_visible(False)
    ax.tick_params(axis='y', which="both", colors=colors[0])
    ax.yaxis.label.set_color(colors[0])

    ax_.spines["right"].set_color(colors[1])
    ax_.spines['left'].set_visible(False)
    ax_.spines["top"].set_visible(False)
    ax_.tick_params(axis='y', which="both", colors=colors[1])
    ax_.yaxis.label.set_color(colors[1])

    fig.savefig(save_dir/f"risk_attribution.pdf", bbox_inches="tight")
    plt.close(fig)
risk_attribution()

def rov_measurement_stats():
    from data.rov_measurement.process import illustrate_all
    illustrate_all(rov_date, result_dir)
rov_measurement_stats()
