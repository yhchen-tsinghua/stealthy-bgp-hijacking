#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
import seaborn as sns
from matplotlib_venn import venn3_unweighted, venn3_circles
import json
sns.set_style("white")

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman'] + plt.rcParams['font.serif']

script_dir = Path(__file__).resolve().parent

def load_cloudflare(date):
    df = pd.read_csv(script_dir/f"rov_list_{date}"/"cloudflare.csv", dtype={"asn": str})
    df.replace({
        " ISP": "ISP",
        "Safe": "safe",
        "transit": "Transit",
        "cloud": "Cloud"}, inplace=True)
    df["status"] = pd.Categorical(df["status"], ["safe", "partially safe", "unsafe"])
    return df

def load_rovista(date):
    return pd.read_csv(script_dir/f"rov_list_{date}"/"rovista.csv", dtype={"asn": str, "ratio": np.float64})

def load_apnic(date):
    df = pd.read_csv(script_dir/f"rov_list_{date}"/"apnic.csv", dtype={"asn": str})
    weighted_avg = lambda x: np.average(x, weights=df.loc[x.index, "samples"])/100
    df = df.groupby(["asn", "as_name"]).agg(
            cc_visible=("cc", "count"),
            samples=("samples", "sum"),
            ratio=("rov_filtering_ratio", weighted_avg)).reset_index()
    return df

def illustrate_cloudflare(date, output_dir):
    output_dir = script_dir/f"rov_list_{date}"
    df = load_cloudflare(date)
    fig = plt.figure(figsize=(5, 3))
    ax = fig.add_subplot(111)
    sns.histplot(data=df, x="status", hue="type", multiple="dodge", shrink=.8,
                    hue_order=["Transit", "ISP", "Cloud"], ax=ax)
    lh = ax.get_legend().legend_handles
    hatches = ['//', '\\\\', 'xx']
    for container, hatch, handle in zip(ax.containers, hatches, lh[::-1]):
        handle.set_hatch(hatch*2)
        for rectangle in container:
            rectangle.set_hatch(hatch)
    ax.legend(lh, ["Transit", "ISP", "Cloud"],
            ncol=3, loc="upper left", handleheight=1)
    ax.set_xlabel(None)
    ax.set_xticks(ax.get_xticks())
    n1 = np.count_nonzero(df["status"] == "safe")
    n2 = np.count_nonzero(df["status"] == "partially safe")
    n3 = np.count_nonzero(df["status"] == "unsafe")
    ax.set_xticklabels([f"Filtering\n({n1:,} ASes)",
            f"Partial-filtering\n({n2:,} ASes)",
            f"Non-filtering\n({n3:,} ASes)"])
    ax.grid(True, axis="y")
    ax.tick_params(axis="y", direction='out', length=2, width=1, left=True)

    fig.tight_layout()
    fig.savefig(output_dir/f"cloudflare_{date}.pdf", bbox_inches="tight")
    # fig.savefig(output_dir/f"cloudflare_{date}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

def illustrate_rovista(date, output_dir):
    df = load_rovista(date)
    df["type"] = df["ratio"] >= 0.8
    fig = plt.figure(figsize=(5, 3))
    ax = fig.add_subplot(111)
    sns.histplot(data=df, x="ratio", hue="type", multiple="stack",
                    hue_order=[True, False],
                    bins=20, log_scale=(False, True), ax=ax)
    lh = ax.get_legend().legend_handles
    hatches = ['//', '\\\\']
    for container, hatch, handle in zip(ax.containers, hatches, lh[::-1]):
        handle.set_hatch(hatch*2)
        for rectangle in container:
            rectangle.set_hatch(hatch)
    ax.legend(lh, [f"Filtering ratio ≥ 80% ({np.count_nonzero(df['type']):,} ASes)",
            f"Filtering ratio < 80% ({np.count_nonzero(~df['type']):,} ASes)"],
            ncol=1, loc="upper right", handleheight=1)

    ax.set_xticks(np.linspace(0, 1, 11))
    ax.set_xticklabels(list(map(str, np.linspace(0, 100, 11).astype(int))))
    ax.set_xlabel("Filtering Ratio (%)")
    ax.grid(True, axis="y")
    ax.set_ylim(1e1, 1e5)
    ax.tick_params(axis="both", which="both", direction='out', left=True, bottom=True)

    fig.tight_layout()
    fig.savefig(output_dir/f"rovista_{date}.pdf", bbox_inches="tight")
    # fig.savefig(output_dir/f"rovista_{date}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

def illustrate_apnic(date, output_dir):
    df = load_apnic(date)
    df["type"] = df["ratio"] >= 0.8
    fig = plt.figure(figsize=(5, 3))
    ax = fig.add_subplot(111)
    sns.histplot(data=df, x="ratio", hue="type", multiple="stack",
                    hue_order=[True, False],
                    bins=20, log_scale=(False, True), ax=ax)
    lh = ax.get_legend().legend_handles
    hatches = ['//', '\\\\']
    for container, hatch, handle in zip(ax.containers, hatches, lh[::-1]):
        handle.set_hatch(hatch*2)
        for rectangle in container:
            rectangle.set_hatch(hatch)
    ax.legend(lh, [f"Filtering ratio ≥ 80% ({np.count_nonzero(df['type']):,} ASes)",
            f"Filtering ratio < 80% ({np.count_nonzero(~df['type']):,} ASes)"],
            ncol=1, loc="upper right", handleheight=1)

    ax.set_xticks(np.linspace(0, 1, 11))
    ax.set_xticklabels(list(map(str, np.linspace(0, 100, 11).astype(int))))
    ax.set_xlabel("Filtering Ratio (%)")
    ax.grid(True, axis="y")
    ax.set_ylim(1e1, 1e5)
    ax.tick_params(axis="both", which="both", direction='out', left=True, bottom=True)
    fig.tight_layout()
    fig.savefig(output_dir/f"apnic_{date}.pdf", bbox_inches="tight")
    # fig.savefig(output_dir/f"apnic_{date}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

def illustrate_venn(date, output_dir):
    df = load_cloudflare(date)
    set_cloudflare = set(df.loc[df["status"] != "unsafe"]["asn"])

    df = load_apnic(date)
    set_apnic = set(df.loc[df["ratio"] >= 0.8]["asn"])

    df = load_rovista(date)
    set_rovista = set(df.loc[df["ratio"] >= 0.8]["asn"])

    fig = plt.figure(figsize=(5, 5))
    venn3_unweighted([set_cloudflare, set_apnic, set_rovista], ('Cloudflare', 'APNIC(≥80%)', 'RoVista(≥80%)'))
    fig.tight_layout()
    fig.savefig(output_dir/"venn.pdf", bbox_inches="tight")
    # fig.savefig(output_dir/"venn.png", dpi=200, bbox_inches="tight")

def illustrate_all(date, output_dir):
    import matplotlib.gridspec as gridspec

    fig = plt.figure(figsize=(20, 5))
    # axes = fig.subplots(1, 4)

    gs = gridspec.GridSpec(1, 4, width_ratios=[1.05,1.05,1.05,0.9])
    axes = [fig.add_subplot(gs[i]) for i in range(4)]

    title_y = -0.20
    titlesize = 20
    labelsize = 18
    ticklabelsize = 16
    ticksize = 14

    # apnic
    ax = axes[0]
    df_apnic = load_apnic(date)
    df = df_apnic
    df["type"] = df["ratio"] >= 0.8
    sns.histplot(data=df, x="ratio", hue="type", multiple="stack",
                    hue_order=[True, False],
                    bins=20, log_scale=(False, True), ax=ax)
    lh = ax.get_legend().legend_handles
    hatches = ['//', '\\\\']
    for container, hatch, handle in zip(ax.containers, hatches, lh[::-1]):
        handle.set_hatch(hatch*2)
        for rectangle in container:
            rectangle.set_hatch(hatch)
    ax.legend(lh, [f"Ratio ≥ 80% ({np.count_nonzero(df['type']):,} ASes)",
            f"Ratio < 80% ({np.count_nonzero(~df['type']):,} ASes)"],
            ncol=1, loc="upper right", handleheight=1, fontsize=ticksize)
    ax.set_xticks(np.linspace(0, 1, 11))
    ax.set_xticklabels(list(map(str, np.linspace(0, 100, 11).astype(int))))
    ax.set_xlabel("Filtering Ratio (%)", fontsize=labelsize)
    ax.set_ylabel("Count", fontsize=labelsize)
    ax.yaxis.set_tick_params(labelsize=ticksize)
    ax.xaxis.set_tick_params(labelsize=ticksize)
    ax.grid(True, axis="y")
    ax.set_ylim(1e1, 1e5)
    ax.tick_params(axis="both", which="both", direction='out', left=True, bottom=True)
    ax.set_title("(a) APNIC", fontsize=titlesize, va="top", y=title_y)

    # rovista
    ax = axes[1]
    df_rovista = load_rovista(date)
    df = df_rovista
    df["type"] = df["ratio"] >= 0.8
    sns.histplot(data=df, x="ratio", hue="type", multiple="stack",
                    hue_order=[True, False],
                    bins=20, log_scale=(False, True), ax=ax)
    lh = ax.get_legend().legend_handles
    hatches = ['//', '\\\\']
    for container, hatch, handle in zip(ax.containers, hatches, lh[::-1]):
        handle.set_hatch(hatch*2)
        for rectangle in container:
            rectangle.set_hatch(hatch)
    ax.legend(lh, [f"Ratio ≥ 80% ({np.count_nonzero(df['type']):,} ASes)",
            f"Ratio < 80% ({np.count_nonzero(~df['type']):,} ASes)"],
            ncol=1, loc="upper right", handleheight=1, fontsize=ticksize)
    ax.set_xticks(np.linspace(0, 1, 11))
    ax.set_xticklabels(list(map(str, np.linspace(0, 100, 11).astype(int))))
    ax.set_xlabel("Filtering Ratio (%)", fontsize=labelsize)
    ax.grid(True, axis="y")
    ax.set_ylim(1e1, 1e5)
    ax.yaxis.set_tick_params(labelsize=ticksize)
    ax.xaxis.set_tick_params(labelsize=ticksize)
    ax.set_ylabel(None)
    ax.tick_params(axis="both", which="both", direction='out', left=True, bottom=True)
    ax.set_title("(b) RoVista", fontsize=titlesize, va="top", y=title_y)

    # cloudflare
    ax = axes[2]
    df_cloudflare = load_cloudflare(date)
    df = df_cloudflare
    sns.histplot(data=df, x="status", hue="type", multiple="dodge", shrink=.8,
                    hue_order=["Transit", "ISP", "Cloud"], ax=ax)
    lh = ax.get_legend().legend_handles
    hatches = ['//', '\\\\', 'xx']
    for container, hatch, handle in zip(ax.containers, hatches, lh[::-1]):
        handle.set_hatch(hatch*2)
        for rectangle in container:
            rectangle.set_hatch(hatch)
    ax.legend(lh, ["Transit", "ISP", "Cloud"],
            ncol=1, loc="upper left", handleheight=1, fontsize=ticksize)
    ax.set_xlabel(None)
    ax.set_xticks(ax.get_xticks())
    ax.set_ylabel(None)
    n1 = np.count_nonzero(df["status"] == "safe")
    n2 = np.count_nonzero(df["status"] == "partially safe")
    n3 = np.count_nonzero(df["status"] == "unsafe")
    ax.set_xticklabels([f"Full-filter\n({n1:,} ASes)",
            f"Partial-filter\n({n2:,} ASes)",
            f"Non-filter\n({n3:,} ASes)"], fontsize=ticklabelsize)
    ax.grid(True, axis="y")
    ax.yaxis.set_tick_params(labelsize=ticksize)
    ax.tick_params(axis="y", direction='out', length=2, width=1, left=True)
    ax.set_title("(c) Cloudflare", fontsize=titlesize, va="top", y=title_y)

    # venn
    ax = axes[3]
    ax.set_clip_on(False)
    set_apnic = set(df_apnic.loc[df_apnic["ratio"] >= 0.8]["asn"])
    set_rovista = set(df_rovista.loc[df_rovista["ratio"] >= 0.8]["asn"])
    # set_cloudflare = set(df_cloudflare.loc[df_cloudflare["status"] != "unsafe"]["asn"])
    set_cloudflare = set(df_cloudflare.loc[df_cloudflare["status"] == "safe"]["asn"])

    v = venn3_unweighted([set_apnic, set_rovista, set_cloudflare], ("", "", ""), ax=ax)
    # for i in ["110", "101", "011", "111"]:
    for i in ["001", "010", "100", "110", "101", "011", "111"]:
        patch = v.get_patch_by_id(i)
        patch.set_hatch("//")
        patch.set_alpha(0.3)
        v.get_label_by_id(i).set_fontsize(ticksize)
    # for i in ["100", "010", "001"]:
    #     v.get_patch_by_id(i).set_color("white")
    #     v.get_label_by_id(i).set_fontsize(ticksize)
    c = venn3_circles(subsets=(1, 1, 1, 1, 1, 1, 1), linestyle='dashed')
    # ax.set_title("(d) The cross-validation", fontsize=titlesize, va="top", y=title_y)
    ax.set_title("(d) Consolidated results", fontsize=titlesize, va="top", y=title_y)
    ax.axis("on")
    # ax.set_clip_on(False)
    # ax.set_xlim(-0.60, 0.60)
    # ax.set_ylim(-0.65, 0.55)
    ax.set_xticklabels([])
    ax.set_yticklabels([])

    ax.text(-0.65, 0.60, "APNIC(≥80%)", fontsize=ticksize, ha="left", va="top")
    ax.text( 0.65,  0.60, "RoVista(≥80%)", fontsize=ticksize, ha="right", va="top")
    ax.text( 0.0, -0.72, "Cloudflare(full)", fontsize=ticksize, ha="center", va="bottom")
    # ax.annotate("Unknown set", xy=v.get_label_by_id('101').get_position() - np.array([0.05, 0.05]), clip_on=False, xytext=(0.5, -0.1), ha='center', textcoords='axes fraction', fontsize=labelsize, arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0.5', color='gray', relpos=(0, 1)))
    ax.set_xlabel(f"{len(set_apnic|set_cloudflare|set_rovista):,} ASes identified ROV-enabled\nby three sources collectively", fontsize=ticklabelsize, labelpad=6)

    fig.tight_layout()
    fig.savefig(output_dir/f"rov_measurement_{date}.pdf", bbox_inches="tight")
    # fig.savefig(output_dir/f"rov_measurement_{date}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

def gen_rov_list(date):
    output_dir = script_dir/f"rov_list_{date}"

    rov_status = dict()

    for asn, status in load_cloudflare(date)[["asn", "status"]].values:
        s = rov_status.setdefault(asn,
                dict(rovista=None, apnic=None, cloudflare=None))
        s["cloudflare"] = status

    for asn, ratio in load_apnic(date)[["asn", "ratio"]].values:
        s = rov_status.setdefault(asn,
                dict(rovista=None, apnic=None, cloudflare=None))
        s["apnic"] = ratio

    for asn, ratio in load_rovista(date)[["asn", "ratio"]].values:
        s = rov_status.setdefault(asn,
                dict(rovista=None, apnic=None, cloudflare=None))
        s["rovista"] = ratio

    set_rov = set()
    
    for asn, status in rov_status.items():
        if status["cloudflare"] == "safe":
            set_rov.add(asn)
            continue
        s1 = 0 if status["apnic"] is None else status["apnic"]
        s2 = 0 if status["rovista"] is None else status["rovista"]
        if max(s1, s2) >= 0.8:
            set_rov.add(asn)

    json.dump(sorted(set_rov), open(output_dir/f"rov_{date}_list.json", "w"))
