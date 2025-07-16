#!/usr/bin/env python
import numpy as np
import pandas as pd
import time
from pathlib import Path
from pybgpsim import CaidaReader, Graph, GraphSearch
from matrix_bgpsim import RMatrix 
from data.caida.as_rel import get as get_rels

script_dir = Path(__file__).resolve().parent
data_dir = script_dir/"data"
cache_dir = script_dir/".cache"
cache_dir.mkdir(parents=True, exist_ok=True)

np.random.seed(0)

def get_sample_topo(as_rel_date, max_asn_num):
    as_rel_fpath = get_rels("2", as_rel_date)
    sample_topo_path = cache_dir/f"sample_topo.{as_rel_date}.{max_asn_num}.txt"

    if sample_topo_path.exists():
        sample_asn = set()
        for line in open(sample_topo_path, "r").readlines():
            if line.startswith("#"): continue
            a, b = line.strip().split("|")[:2]
            sample_asn.add(a)
            sample_asn.add(b)
        return sample_topo_path, sorted(sample_asn)

    ngbrs = {}
    for line in open(as_rel_fpath, "r").readlines():
        if line.startswith("#"): continue
        a, b, rel = line.strip().split("|")[:3]

        if a not in ngbrs:
            ngbrs[a] = {RMatrix.C2P: set(), RMatrix.P2P: set(), RMatrix.P2C: set()}
        ngbrs[a][int(rel)].add(b)

        if b not in ngbrs:
            ngbrs[b] = {RMatrix.C2P: set(), RMatrix.P2P: set(), RMatrix.P2C: set()}
        ngbrs[b][-int(rel)].add(a)


    queue = ["174", "209", "286", "701", "1239", "1299", "2828", "2914", "3257", "3320", "3356", "3491", "5511", "6453", "6461", "6762", "6830", "7018", "12956"] # starting with Tier-1 AS
    sample_asn = set()
    while queue and len(sample_asn) < max_asn_num:
        a = queue.pop(0)
        if a in sample_asn: continue
        sample_asn.add(a)
        for b in ngbrs[a][RMatrix.P2C]:
            if b not in sample_asn:
                queue.append(b)
        for b in ngbrs[a][RMatrix.P2P]:
            if b not in sample_asn:
                queue.append(b)

    print(f"Sampled {len(sample_asn)} ASes")

    edges = []
    for a in sample_asn:
        for b in ngbrs[a][RMatrix.P2C] & sample_asn:
            edges.append(f"{a}|{b}|-1")
        for b in ngbrs[a][RMatrix.P2P] & sample_asn:
            if a <= b:
                edges.append(f"{a}|{b}|0")
    sample_topo_path.write_text("\n".join(edges)+"\n")
    print(f"Sampled {len(edges)} Rels")
    return sample_topo_path, sorted(sample_asn)

max_asn_num = 10000
sample_topo_path, sample_asn = get_sample_topo("20250101", max_asn_num)
np.random.shuffle(sample_asn)

def test_bgpsim():
    g = Graph()
    r = CaidaReader(g)
    r.ReadFile(str(sample_topo_path))
    s = GraphSearch(g)

    results = dict()

    for n in range(10, 110, 10): # from 10x10 ASes to 100x100 ASes
        for _ in range(10): # repeat 10 run
            t0 = time.perf_counter()
            for i in range(n):
                for j in range(n):
                    s.GetPath(int(sample_asn[i]), int(sample_asn[j]))
            t1 = time.perf_counter()
            dt = t1 - t0
            print(f"bgpsim on {n}x{n} ASes: {dt:.4f}s")
            results.setdefault(n, []).append(dt)
    df = pd.DataFrame.from_dict(results)
    df.to_csv(cache_dir/"bgpsim.csv", index=False)

test_bgpsim()

RMatrix.init_class(sample_topo_path)
def test_matrix_bgpsim(n_jobs):
    # NOTE: the actual scale of matrix_bgpsim's computation is 10000x10000 ASes
    assert len(sample_asn) == max_asn_num

    results = dict()

    for _ in range(10): # repeat 10 run
        t0 = time.perf_counter()
        RMatrix().update_runner(n_jobs=n_jobs, max_iter=20)()
        t1 = time.perf_counter()
        for n in range(10, 110, 10):
            dt = (t1 - t0)/((max_asn_num/n)**2) # scaled to the actual average time on nxn ASes
            print(f"matrix_bgpsim(CPUx{n_jobs}) on {n}x{n} ASes: {dt:.4f}s")
            results.setdefault(n, []).append(dt)
    df = pd.DataFrame.from_dict(results)
    df.to_csv(cache_dir/f"matrix_bgpsim_{n_jobs}.csv", index=False)

test_matrix_bgpsim(n_jobs=1)
test_matrix_bgpsim(n_jobs=20)
test_matrix_bgpsim(n_jobs=40)

# NOTE: the GPU version of matrix_bgpsim has not been packaged yet, and it is a demo below.
def test_matrix_bgpsim_gpu(): 
    import torch
    assert torch.cuda.is_available(), "CUDA is not available"
    device = "cuda:0"

    def init_tensor(p_size, idx_ngbrs, device):
        shape = (p_size, p_size)
        
        state = torch.full(shape, 0b00_111111, dtype=torch.uint8, device=device, requires_grad=False).t()
        link1 = torch.zeros(shape, dtype=torch.uint8, device=device, requires_grad=False)
        link2 = torch.full(shape, 0b00_111111, dtype=torch.uint8, device=device, requires_grad=False)
        link3 = torch.zeros(shape, dtype=torch.uint8, device=device, requires_grad=False)
        
        with torch.no_grad():
            for i, ngbrs in enumerate(idx_ngbrs):
                state[ngbrs[RMatrix.C2P], i] = 0b11_111110
                state[ngbrs[RMatrix.P2P], i] = 0b10_111110
                state[ngbrs[RMatrix.P2C], i] = 0b01_111110
                link1[i, ngbrs[RMatrix.P2C]] = 0b11_000000
                link1[i, ngbrs[RMatrix.P2P]] = 0b10_000000
                link1[i, ngbrs[RMatrix.C2P]] = 0b01_000000
                link2[i, ngbrs[RMatrix.C2P]] = 0b01_111111
                link3[i, ngbrs[RMatrix.P2C]] = 0b00_000001
                link3[i, ngbrs[RMatrix.P2P]] = 0b00_000001
                link3[i, ngbrs[RMatrix.C2P]] = 0b00_000001

        return state, link1, link2, link3

    def process(state, link1, link2, link3, tmp0, tmp1, tmp2, tmp3):
        torch.bitwise_and(state, 0b11_000000, out=tmp0)
        torch.bitwise_left_shift(tmp0, 1, out=tmp1)
        torch.bitwise_right_shift(tmp0, 1, out=tmp2[:tmp0.shape[1]].t())
        torch.bitwise_or(tmp1, tmp2.t()[:, :tmp0.shape[1]], out=tmp1)
        torch.bitwise_and(tmp1, 0b11_000000, out=tmp1)
        torch.bitwise_and(tmp0, tmp1, out=tmp0)
        torch.bitwise_or(tmp1, state, out=tmp1)

        for j in range(state.size(1)):
            torch.bitwise_and(link1, tmp0[:, j], out=tmp2)
            torch.bitwise_and(link2, tmp1[:, j], out=tmp3)
            torch.bitwise_or(tmp2, tmp3, out=tmp2)
            tmp2.sub_(link3)
            state[:, j] = torch.max(tmp2, dim=1)[0]

        return state

    def run(p_size, idx_ngbrs, max_iter):
        torch.cuda.set_device(device)

        state, link1, link2, link3 = init_tensor(p_size, idx_ngbrs, device=device)

        link1 = link1.to(device)
        link2 = link2.to(device)
        link3 = link3.to(device)
        tmp0 = torch.empty(state.shape, dtype=state.dtype, device=device).t().contiguous().t()
        tmp1 = torch.empty(state.shape, dtype=state.dtype, device=device).t().contiguous().t()
        tmp2 = torch.empty_like(link1)
        tmp3 = torch.empty_like(link2)

        hash_before = torch.sum(state.to(torch.int64)).item()

        d0 = time.perf_counter()
        for iter_num in range(max_iter):
            state = process(state, link1, link2, link3, tmp0, tmp1, tmp2, tmp3)
            hash_after = torch.sum(state.to(torch.int64)).item()
            print(f"Iteration {iter_num+1} completed")
            if hash_after == hash_before: # early stop
                break
            else:
                hash_before = hash_after
        d1 = time.perf_counter()
        return d1 - d0

    p_size = len(RMatrix.__idx2asn__)
    idx_ngbrs = RMatrix.__idx_ngbrs__

    results = dict()

    for _ in range(10): # repeat 10 run
        _dt = run(p_size, idx_ngbrs, max_iter=20)
        for n in range(10, 110, 10):
            dt = _dt/((max_asn_num/n)**2) # scaled to the actual average time on nxn ASes
            print(f"matrix_bgpsim(GPU) on {n}x{n} ASes: {dt:.4f}s")
            results.setdefault(n, []).append(dt)
    df = pd.DataFrame.from_dict(results)
    df.to_csv(cache_dir/f"matrix_bgpsim_gpu.csv", index=False)
test_matrix_bgpsim_gpu()
