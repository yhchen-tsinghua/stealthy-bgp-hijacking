#!/usr/bin/env python
#-*- coding: utf-8 -*-
from matrix_bgpsim import RMatrix
from pathlib import Path
import json
import pickle
import numpy as np
import pandas as pd
from numba import njit, prange, config, set_num_threads
import lz4.frame
import time

script_dir = Path(__file__).resolve().parent
data_dir = script_dir/"data"

def lz4dump(obj, fpath):
    pickle.dump(obj, lz4.frame.open(fpath, "wb"), protocol=4)

def lz4load(fpath):
    return pickle.load(lz4.frame.open(fpath, "rb"))

def time_track(fn, text):
    def fn_t(*args, **kwargs):
        t0 = time.perf_counter()
        ret = fn(*args, **kwargs)
        t1 = time.perf_counter()
        print(f"{text}: {t1-t0}s")
        return ret
    return fn_t

def pre_process(rov_date, as_rel_date, n_jobs):
    rov_list_fpath = data_dir/"rov_measurement"/f"rov_list_{rov_date}"/f"rov_{rov_date}_list.json"
    rov_list = list(map(str, json.load(open(rov_list_fpath))))
    print(f"ROVs: {len(rov_list):,}")

    as_rel_fpath = data_dir/"caida"/"serial-2"/f"{as_rel_date}.as-rel2.txt"
    matrix_dir = data_dir/"matrices"/f"as_rel_{as_rel_date}_rov_{rov_date}"
    matrix_dir.mkdir(parents=True, exist_ok=True)

    RMatrix.init_class(as_rel_fpath)

    # normal circumstances
    fpath = matrix_dir/"normal.rm.lz4"
    if fpath.exists():
        rm0 = RMatrix.load(fpath)
        np.clip(rm0.__state__, 0b00111111, None, out=rm0.__state__)
    else:
        rm0 = RMatrix()
        rm0.run(n_jobs=n_jobs, max_iter=20, record_next_hop=True)
        rm0.dump(fpath)

    # ROV block circumstances
    fpath = matrix_dir/"rov_block.rm.lz4"
    if fpath.exists():
        rm1 = RMatrix.load(fpath)
        np.clip(rm1.__state__, 0b00111111, None, out=rm1.__state__)
    else:
        rm1 = RMatrix(exclude=set(rov_list))
        rm1.run(n_jobs=n_jobs, max_iter=20, record_next_hop=True)
        rm1.dump(fpath)

    return rov_list, rm0, rm1, matrix_dir, as_rel_fpath


class AttackerAnalyzer:
    @staticmethod
    @njit("int32[:,:](int32[:],uint8[:],int32[:,:],int32)", nogil=True)
    def analyze_hijk_instances(blinded_idx, state_to_hijacker, next_hop, max_rnd):
        hijk_instances = []
        for src in blinded_idx:
            for dst, nhp in enumerate(next_hop[src]):
                if nhp == -1: continue
                if nhp == dst: continue
                for _ in range(max_rnd):
                    if state_to_hijacker[nhp] > 0b00_111111:
                        hijk_instances.append((src, dst, nhp))
                        break
                    nhp = next_hop[nhp, dst]
                    if nhp == -1: break
                    if nhp == dst: break
        return np.array(hijk_instances, dtype=np.int32)

    @staticmethod
    @njit("void(boolean[:,:],boolean[:,:],int32[:,:],int32,int32[:,:])", nogil=True, parallel=True)
    def analyze_hijk_key(reach0, reach1, next_hop, max_rnd, mat_hijk_key_num):
        for hijk in prange(reach1.shape[1]):
            rch0 = reach0[:, hijk]
            rch1 = reach1[:, hijk]
            for src, (r0, r1) in enumerate(zip(rch0, rch1)):
                if not r0 or r1: continue
                for dst, nhp in enumerate(next_hop[src]):
                    if nhp == -1: continue
                    if nhp == dst: continue
                    for _ in range(max_rnd):
                        if rch1[nhp]:
                            mat_hijk_key_num[hijk, nhp] += 1
                            break
                        nhp = next_hop[nhp, dst]
                        if nhp == -1: break
                        if nhp == dst: break

    @staticmethod
    def attacker_key_analysis(rm0, rm1, matrix_dir, fname="mat_hijk_key_num.lz4", n_jobs=48):
        set_num_threads(n_jobs)

        reach0 = rm0.__state__ > 0b00_111111
        reach1 = rm1.__state__ > 0b00_111111
        mat_hijk_key_num = np.zeros(rm0.__state__.shape, dtype=np.int32)

        time_track(AttackerAnalyzer.analyze_hijk_key, "analyze stats")(
                reach0, reach1, rm0.__next_hop__, 20, mat_hijk_key_num)

        fpath = matrix_dir/fname
        time_track(lz4dump, "dump to disk")(mat_hijk_key_num, fpath)

        return mat_hijk_key_num

    @staticmethod
    @njit("void(boolean[:,:],boolean[:,:],int32[:,:],int32,int32[:,:])", nogil=True, parallel=True)
    def analyze_hijk_target(reach0, reach1, next_hop, max_rnd, mat_hijk_target_num):
        for hijk in prange(reach1.shape[1]):
            rch0 = reach0[:, hijk]
            rch1 = reach1[:, hijk]
            for src, (r0, r1) in enumerate(zip(rch0, rch1)):
                if not r0 or r1: continue
                for dst, nhp in enumerate(next_hop[src]):
                    if nhp == -1: continue
                    if nhp == dst: continue
                    for _ in range(max_rnd):
                        if rch1[nhp]:
                            mat_hijk_target_num[hijk, dst] += 1
                            break
                        nhp = next_hop[nhp, dst]
                        if nhp == -1: break
                        if nhp == dst: break

    @staticmethod
    def attacker_target_analysis(rm0, rm1, matrix_dir, fname="mat_hijk_target_num.lz4", n_jobs=48):
        set_num_threads(n_jobs)

        reach0 = rm0.__state__ > 0b00_111111
        reach1 = rm1.__state__ > 0b00_111111
        mat_hijk_target_num = np.zeros(rm0.__state__.shape, dtype=np.int32)

        time_track(AttackerAnalyzer.analyze_hijk_target, "analyze stats")(
                reach0, reach1, rm0.__next_hop__, 20, mat_hijk_target_num)

        fpath = matrix_dir/fname
        time_track(lz4dump, "dump to disk")(mat_hijk_target_num, fpath)

        return mat_hijk_target_num

    @staticmethod
    @njit("void(boolean[:,:],boolean[:,:],int32[:,:],int32,int32[:,:])", nogil=True, parallel=True)
    def analyze_hijk_vict(reach0, reach1, next_hop, max_rnd, mat_hijk_vict_num):
        for hijk in prange(reach1.shape[1]):
            rch0 = reach0[:, hijk]
            rch1 = reach1[:, hijk]
            for src, (r0, r1) in enumerate(zip(rch0, rch1)):
                if not r0 or r1: continue
                for dst, nhp in enumerate(next_hop[src]):
                    if nhp == -1: continue
                    if nhp == dst: continue
                    for _ in range(max_rnd):
                        if rch1[nhp]:
                            mat_hijk_vict_num[hijk, src] += 1
                            break
                        nhp = next_hop[nhp, dst]
                        if nhp == -1: break
                        if nhp == dst: break

    @staticmethod
    def attacker_victim_analysis(rm0, rm1, matrix_dir, fname="mat_hijk_vict_num.lz4", n_jobs=48):
        set_num_threads(n_jobs)

        reach0 = rm0.__state__ > 0b00_111111
        reach1 = rm1.__state__ > 0b00_111111
        mat_hijk_vict_num = np.zeros(rm0.__state__.shape, dtype=np.int32)

        time_track(AttackerAnalyzer.analyze_hijk_vict, "analyze stats")(
                reach0, reach1, rm0.__next_hop__, 20, mat_hijk_vict_num)

        fpath = matrix_dir/fname
        time_track(lz4dump, "dump to disk")(mat_hijk_vict_num, fpath)

        return mat_hijk_vict_num

class VictimAnalyzer:
    @staticmethod
    @njit("int32[:,:](int32[:],uint8[:,:],int32[:,:],int32,int32)", nogil=True)
    def analyze_hijk_instances(invisible_idx, state1, next_hop, vict, max_rnd):
        hijk_instances = []
        for hijk in invisible_idx:
            state_to_hijacker = state1[:, hijk]
            for dst, nhp in enumerate(next_hop[vict]):
                if nhp == -1: continue
                if nhp == dst: continue
                for _ in range(max_rnd):
                    if state_to_hijacker[nhp] > 0b00_111111:
                        hijk_instances.append((dst, hijk, nhp))
                        break
                    nhp = next_hop[nhp, dst]
                    if nhp == -1: break
                    if nhp == dst: break
        return np.array(hijk_instances, dtype=np.int32)

    @staticmethod
    @njit("void(boolean[:,:],boolean[:,:],int32[:,:],int32,int32[:,:])", nogil=True, parallel=True)
    def analyze_vict_key(reach0, reach1, next_hop, max_rnd, mat_vict_key_num):
        for src in prange(reach0.shape[0]):
            rch0 = reach0[src]
            rch1 = reach1[src]
            for hijk, (r0, r1) in enumerate(zip(rch0, rch1)):
                if not r0 or r1: continue
                for dst, nhp in enumerate(next_hop[src]):
                    if nhp == -1: continue
                    if nhp == dst: continue
                    for _ in range(max_rnd):
                        if reach1[nhp, hijk]:
                            mat_vict_key_num[src, nhp] += 1
                            break
                        nhp = next_hop[nhp, dst]
                        if nhp == -1: break
                        if nhp == dst: break

    @staticmethod
    def victim_key_analysis(rm0, rm1, matrix_dir, fname="mat_vict_key_num.lz4", n_jobs=48):
        set_num_threads(n_jobs)

        reach0 = rm0.__state__ > 0b00_111111
        reach1 = rm1.__state__ > 0b00_111111
        mat_vict_key_num = np.zeros(rm0.__state__.shape, dtype=np.int32)

        time_track(VictimAnalyzer.analyze_vict_key, "analyze stats")(
                reach0, reach1, rm0.__next_hop__, 20, mat_vict_key_num)

        fpath = matrix_dir/fname
        time_track(lz4dump, "dump to disk")(mat_vict_key_num, fpath)

        return mat_vict_key_num

    @staticmethod
    @njit("void(boolean[:,:],boolean[:,:],int32[:,:],int32,int32[:,:])", nogil=True, parallel=True)
    def analyze_vict_target(reach0, reach1, next_hop, max_rnd, mat_vict_target_num):
        for src in prange(reach0.shape[0]):
            rch0 = reach0[src]
            rch1 = reach1[src]
            for hijk, (r0, r1) in enumerate(zip(rch0, rch1)):
                if not r0 or r1: continue
                for dst, nhp in enumerate(next_hop[src]):
                    if nhp == -1: continue
                    if nhp == dst: continue
                    for _ in range(max_rnd):
                        if reach1[nhp, hijk]:
                            mat_vict_target_num[src, dst] += 1
                            break
                        nhp = next_hop[nhp, dst]
                        if nhp == -1: break
                        if nhp == dst: break

    @staticmethod
    def victim_target_analysis(rm0, rm1, matrix_dir, fname="mat_vict_target_num.lz4", n_jobs=48):
        set_num_threads(n_jobs)

        reach0 = rm0.__state__ > 0b00_111111
        reach1 = rm1.__state__ > 0b00_111111
        mat_vict_target_num = np.zeros(rm0.__state__.shape, dtype=np.int32)

        time_track(VictimAnalyzer.analyze_vict_target, "analyze stats")(
                reach0, reach1, rm0.__next_hop__, 20, mat_vict_target_num)

        fpath = matrix_dir/fname
        time_track(lz4dump, "dump to disk")(mat_vict_target_num, fpath)

        return mat_vict_target_num

class TargetAnalyzer:
    @staticmethod
    @njit("int32[:,:](boolean[:,:],boolean[:,:],int32[:,:],int32,int32)", nogil=True)
    def analyze_hijk_instances(reach0, reach1, next_hop, target, max_rnd):
        hijk_instances = []
        for src, (rch0, rch1) in enumerate(zip(reach0, reach1)):
            if not rch0[target]: continue
            for hijk, (r0, r1) in enumerate(zip(rch0, rch1)):
                if not r0 or r1: continue
                nhp = next_hop[src, target]
                if nhp == target: continue
                for _ in range(max_rnd):
                    if reach1[nhp, hijk]:
                        hijk_instances.append((src, hijk, nhp))
                        break
                    nhp = next_hop[nhp, target]
                    if nhp == -1: break
                    if nhp == target: break
        return np.array(hijk_instances, dtype=np.int32)

    @staticmethod
    @njit("void(boolean[:,:],boolean[:,:],int32[:,:],int32,int32[:,:])", nogil=True, parallel=True)
    def analyze_target_key(reach0, reach1, next_hop, max_rnd, mat_target_key_num): # not so fast as single thread!
        for dst in prange(reach0.shape[1]):
            for src, (rch0, rch1) in enumerate(zip(reach0, reach1)):
                if not rch0[dst]: continue
                for hijk, (r0, r1) in enumerate(zip(rch0, rch1)):
                    if not r0 or r1: continue
                    nhp = next_hop[src, dst]
                    if nhp == dst: continue
                    for _ in range(max_rnd):
                        if reach1[nhp, hijk]:
                            mat_target_key_num[dst, nhp] += 1
                            break
                        nhp = next_hop[nhp, dst]
                        if nhp == -1: break
                        if nhp == dst: break

    @staticmethod
    @njit("void(boolean[:,:],boolean[:,:],int32[:,:],int32,int32[:,:])", nogil=True)
    def analyze_target_key_single_thread(reach0, reach1, next_hop, max_rnd, mat_target_key_num):
        for hijk, (rch0, rch1) in enumerate(zip(reach0.T, reach1.T)):
            for src, (r0, r1) in enumerate(zip(rch0, rch1)):
                if not r0 or r1: continue
                for dst, nhp in enumerate(next_hop[src]):
                    if nhp == -1: continue
                    if nhp == dst: continue
                    for _ in range(max_rnd):
                        if rch1[nhp]:
                            mat_target_key_num[dst, nhp] += 1
                            break
                        nhp = next_hop[nhp, dst]
                        if nhp == -1: break
                        if nhp == dst: break

    @staticmethod
    def target_key_analysis(rm0, rm1, matrix_dir, fname="mat_target_key_num.lz4",  n_jobs=24):
        set_num_threads(n_jobs)

        reach0 = rm0.__state__ > 0b00_111111
        reach1 = rm1.__state__ > 0b00_111111
        mat_target_key_num = np.zeros(rm0.__state__.shape, dtype=np.int32)

        time_track(TargetAnalyzer.analyze_target_key if n_jobs > 1
            else TargetAnalyzer.analyze_target_key_single_thread, "analyze stats")(
                reach0, reach1, rm0.__next_hop__, 20, mat_target_key_num)

        fpath = matrix_dir/fname
        time_track(lz4dump, "dump to disk")(mat_target_key_num, fpath)

        return mat_target_key_num


@njit("void(boolean[:,:],uint8[:,:],uint8[:,:],int32[:,:],int32,int32[:,:,:])", nogil=True, parallel=True)
def analyze_hijk_exact_prefix(better, state0, state1, next_hop, max_rnd, mat_hijk_vt_num_ex):
    for hijk in prange(state1.shape[1]):
        st0 = state0[:, hijk]
        st1 = state1[:, hijk]
        bt = better[:, hijk]
        for src, (s0, s1) in enumerate(zip(st0, st1)):
            if s0 <= 0b00111111 or s1 > 0b00111111: continue
            for dst, nhp in enumerate(next_hop[src]):
                if nhp == -1: continue
                if nhp == dst: continue
                for _ in range(max_rnd):
                    if bt[nhp]:
                        mat_hijk_vt_num_ex[hijk, src, 0] += 1
                        mat_hijk_vt_num_ex[hijk, dst, 1] += 1
                        break
                    nhp = next_hop[nhp, dst]
                    if nhp == -1: break
                    if nhp == dst: break

def attacker_exact_prefix_analysis(rm0, rm1, matrix_dir, suffix="", n_jobs=48):
    set_num_threads(n_jobs)

    state0 = rm0.__state__
    state1 = rm1.__state__
    better = state1 > state0

    mat_hijk_vt_num_ex = np.zeros((*rm0.__state__.shape, 2), dtype=np.int32)

    time_track(analyze_hijk_exact_prefix, "analyze stats")(
            better, state0, state1, rm0.__next_hop__, 20, mat_hijk_vt_num_ex)

    mat_hijk_vict_num_ex = mat_hijk_vt_num_ex[:,:,0]
    mat_hijk_target_num_ex = mat_hijk_vt_num_ex[:,:,1]

    fpath = matrix_dir/f"mat_hijk_vict_num_ex{suffix}.lz4"
    time_track(lz4dump, "dump to disk")(mat_hijk_vict_num_ex, fpath)
    fpath = matrix_dir/f"mat_hijk_target_num_ex{suffix}.lz4"
    time_track(lz4dump, "dump to disk")(mat_hijk_target_num_ex, fpath)
    
    return mat_hijk_vict_num_ex, mat_hijk_target_num_ex 

@njit("void(boolean[:,:],uint8[:,:],uint8[:,:],int32[:,:],int32,int32[:,:])", nogil=True, parallel=True)
def analyze_vict_exact_prefix(better, state0, state1, next_hop, max_rnd, mat_vict_target_num_ex):
    for src in prange(state0.shape[0]):
        st0 = state0[src]
        st1 = state1[src]
        for hijk, (s0, s1) in enumerate(zip(st0, st1)):
            if s0 <= 0b00111111 or s1 > 0b00111111: continue
            for dst, nhp in enumerate(next_hop[src]):
                if nhp == -1: continue
                if nhp == dst: continue
                for _ in range(max_rnd):
                    if better[nhp, hijk]:
                        mat_vict_target_num_ex[src, dst] += 1
                        break
                    nhp = next_hop[nhp, dst]
                    if nhp == -1: break
                    if nhp == dst: break

def victim_exact_prefix_analysis(rm0, rm1, matrix_dir, suffix="", n_jobs=48):
    set_num_threads(n_jobs)

    state0 = rm0.__state__
    state1 = rm1.__state__
    better = state1 > state0

    mat_vict_target_num_ex = np.zeros(rm0.__state__.shape, dtype=np.int32)

    time_track(analyze_vict_exact_prefix, "analyze stats")(
            better, state0, state1, rm0.__next_hop__, 20, mat_vict_target_num_ex)

    fpath = matrix_dir/f"mat_vict_target_num_ex{suffix}.lz4"
    time_track(lz4dump, "dump to disk")(mat_vict_target_num_ex, fpath)

    return mat_vict_target_num_ex

@njit("void(uint8[:,:],uint8[:,:],int32[:,:])", nogil=True, parallel=True)
def direct_vict_tgt_exact_prefix(state0, state1, vict_tgt):
    for src in prange(state0.shape[0]):
        for dst in range(state0.shape[1]):
            n = 0
            for hijk in range(state1.shape[1]):
                if state0[src, dst] < state1[src, hijk]:
                    n += 1
            vict_tgt[src, dst] = n

@njit("void(uint8[:,:],uint8[:,:],int32[:,:])", nogil=True, parallel=True)
def direct_vict_hijk_exact_prefix(state0, state1, vict_hijk):
    for src in prange(state0.shape[0]):
        for hijk in range(state1.shape[1]):
            n = 0
            for dst in range(state0.shape[1]):
                if state0[src, dst] < state1[src, hijk]:
                    n += 1
            vict_hijk[src, hijk] = n

@njit("void(uint8[:,:],uint8[:,:],int32[:,:])", nogil=True, parallel=True)
def direct_tgt_hijk_exact_prefix(stateT0, stateT1, tgt_hijk):
    for dst in prange(stateT0.shape[0]):
        for hijk in range(stateT1.shape[0]):
            n = 0
            for src in range(stateT0.shape[1]):
                if stateT0[dst, src] < stateT1[hijk, src]:
                    n += 1
            tgt_hijk[dst, hijk] = n

def direct_exact_prefix_analysis(rm0, rm1, matrix_dir, vict_tgt=True, vict_hijk=True, tgt_hijk=True, suffix="", n_jobs=48):
    set_num_threads(n_jobs)
    ret = np.zeros((len(RMatrix.__idx2asn__),)*2, dtype=np.int32)
    results = dict()

    state0 = rm0.__state__
    state1 = rm1.__state__
    assert not np.isfortran(state0)
    assert not np.isfortran(state1)

    if vict_tgt:
        time_track(direct_vict_tgt_exact_prefix, "analyze stats")(state0, state1, ret)
        fpath = matrix_dir/f"mat_vict_tgt_num_ex_direct{suffix}.lz4"
        time_track(lz4dump, "dump to disk")(ret, fpath)
        results["vict_tgt"] = ret.copy()

    if vict_hijk:
        time_track(direct_vict_hijk_exact_prefix, "analyze stats")(state0, state1, ret)
        fpath = matrix_dir/f"mat_vict_hijk_num_ex_direct{suffix}.lz4"
        time_track(lz4dump, "dump to disk")(ret, fpath)
        results["vict_hijk"] = ret.copy()

    if tgt_hijk:
        stateT0 = rm0.__state__.T.copy()
        stateT1 = rm1.__state__.T.copy()
        assert not np.isfortran(stateT0)
        assert not np.isfortran(stateT1)

        time_track(direct_tgt_hijk_exact_prefix, "analyze stats")(stateT0, stateT1, ret)
        fpath = matrix_dir/f"mat_tgt_hijk_num_ex_direct{suffix}.lz4"
        time_track(lz4dump, "dump to disk")(ret, fpath)
        results["tgt_hijk"] = ret.copy()

    return results


@njit("void(uint8[:,:],uint8[:,:],int32[:,:],boolean[:],int32[:,:],int32)", nogil=True, parallel=True)
def set_vict_hijk_rov_idx(state0, state1, next_hop, is_rov, vict_hijk_rov_idx, max_rnd):
    for src in prange(state0.shape[0]):
        st0 = state0[src]
        st1 = state1[src]
        for hijk, (s0, s1) in enumerate(zip(st0, st1)):
            if s0 <= 0b00111111 or s1 > 0b00111111: continue
            nhp = next_hop[src, hijk]
            if nhp == -1: continue
            if nhp == hijk: continue
            for _ in range(max_rnd):
                if is_rov[nhp]:
                    vict_hijk_rov_idx[src, hijk] = nhp
                    break
                nhp = next_hop[nhp, hijk]
                if nhp == -1: break
                if nhp == hijk: break

def vict_hijk_rov_attribution(rm0, rm1, matrix_dir, n_jobs=48):
    set_num_threads(n_jobs)
    vict_hijk_rov_idx = np.full((len(RMatrix.__idx2asn__),)*2, -1, dtype=np.int32)

    state0 = rm0.__state__
    state1 = rm1.__state__
    next_hop = rm0.__next_hop__
    is_rov = rm1.__exclude_mask__

    time_track(set_vict_hijk_rov_idx, "analyze stats")(
            state0, state1, next_hop, is_rov, vict_hijk_rov_idx, 20)
    fpath = matrix_dir/f"vict_hijk_rov_idx.lz4"
    time_track(lz4dump, "dump to disk")(vict_hijk_rov_idx, fpath)

@njit("void(int64,int32[:,:],boolean[:],int64[:,:],int64[:,:],int64[:,:],int64[:,:],int64[:],int64[:],int32)", nogil=True)
def AS_hegemony_thread_wrapper(thread_id, next_hop, rov_array, counts, counts_with_rov, counts_prev_rov, counts_post_rov, start_indices, end_indices, max_rnd):
    count = counts[thread_id]
    count_with_rov = counts_with_rov[thread_id]
    count_prev_rov = counts_prev_rov[thread_id]
    count_post_rov = counts_post_rov[thread_id] # (prev) - rov - ... - rov - (post)
    non_rov = np.empty(max_rnd, dtype=np.int32)
    for src in range(start_indices[thread_id], end_indices[thread_id]):
        for dst, nhp in enumerate(next_hop[src]):
            if nhp == -1: continue
            if nhp == dst: continue
            non_rov_idx = 0
            prev_rov_idx = -1
            post_rov_idx = -1
            for _ in range(max_rnd):
                count[nhp] += 1
                if rov_array[nhp]:
                    if prev_rov_idx < 0:
                        prev_rov_idx = non_rov_idx
                    post_rov_idx = non_rov_idx
                else:
                    non_rov[non_rov_idx] = nhp
                    non_rov_idx += 1
                nhp = next_hop[nhp, dst]
                if nhp == -1: break
                if nhp == dst: break
            if prev_rov_idx >= 0: # at least one ROV
                count_with_rov[non_rov[:non_rov_idx]] += 1
                count_prev_rov[non_rov[:prev_rov_idx]] += 1
                count_post_rov[non_rov[post_rov_idx:non_rov_idx]] += 1

@njit("void(int32[:,:],boolean[:],int64[:],int64[:],int64[:],int64[:])", nogil=True, parallel=True)
def AS_hegemony(next_hop, rov_array, counts_save, counts_with_rov_save, counts_prev_rov_save, counts_post_rov_save):
    n_threads = config.NUMBA_NUM_THREADS
    counts = np.zeros((n_threads, next_hop.shape[1]), dtype=np.int64)
    counts_with_rov = np.zeros((n_threads, next_hop.shape[1]), dtype=np.int64)
    counts_prev_rov = np.zeros((n_threads, next_hop.shape[1]), dtype=np.int64)
    counts_post_rov = np.zeros((n_threads, next_hop.shape[1]), dtype=np.int64)

    split_indices = np.linspace(0, next_hop.shape[0], n_threads+1).astype(np.int64)
    start_indices = split_indices[:-1]
    end_indices = split_indices[1:]

    for thread_id in prange(n_threads):
        AS_hegemony_thread_wrapper(thread_id, next_hop, rov_array, counts,
                counts_with_rov, counts_prev_rov, counts_post_rov,
                start_indices, end_indices, max_rnd=20)

    counts_save[:] = np.sum(counts, axis=0)
    counts_with_rov_save[:] = np.sum(counts_with_rov, axis=0)
    counts_prev_rov_save[:] = np.sum(counts_prev_rov, axis=0)
    counts_post_rov_save[:] = np.sum(counts_post_rov, axis=0)

def get_as_stats(rm0, rm1, save_dir): # get all kinds of AS topological characteristics
    # degree centrality
    def get_degs():
        degs_fpath = save_dir/"degs"
        if degs_fpath.exists():
            degs = pickle.load(open(degs_fpath, "rb"))
            deg_all, deg_out, deg_in, deg_prov, deg_cust = degs
        else:
            size = len(RMatrix.__idx2asn__)
            degs = np.zeros((5, size), dtype=np.float64)
            deg_all, deg_out, deg_in, deg_prov, deg_cust = degs

            branches = RMatrix.gateway_branches()

            for i, ngbrs in enumerate(RMatrix.__idx_ngbrs__):
                n_provs = len(ngbrs[RMatrix.C2P])
                n_peers = len(ngbrs[RMatrix.P2P])
                n_custs = len(ngbrs[RMatrix.P2C]) + len(branches[i])

                deg_all[i] = n_provs + n_peers + n_custs
                deg_out[i] = n_peers + n_custs
                deg_in[i] = n_provs + n_peers
                deg_prov[i] = n_provs
                deg_cust[i] = n_custs

            degs /= (size-1)
            pickle.dump(degs, open(degs_fpath, "wb"), protocol=4)
        return deg_all, deg_out, deg_in, deg_prov, deg_cust
    deg_all, deg_out, deg_in, deg_prov, deg_cust = get_degs()

    # customer cone size and provider funnel size (w/ or w/o ROV)
    def get_cone_funnel_size():
        cone_funnel_fpath = save_dir/"cone_funnel_sizes"
        if cone_funnel_fpath.exists():
            cone_funnel_sizes = pickle.load(open(cone_funnel_fpath, "rb"))
            cust_cone_s, cust_cone_s_rov, prov_funnel_s, prov_funnel_s_rov = cone_funnel_sizes
        else:
            size = len(RMatrix.__idx2asn__)
            cone_funnel_sizes = np.zeros((4, size), dtype=np.int64)
            cust_cone_s, cust_cone_s_rov, prov_funnel_s, prov_funnel_s_rov = cone_funnel_sizes

            state0_p2c = (rm0.__state__ >= 0b11_000000)
            state1_p2c = (rm1.__state__ >= 0b11_000000)

            cust_cone_s[:] = np.sum(state0_p2c * RMatrix.gateway_weights(), axis=1)
            cust_cone_s_rov[:] = np.sum(state1_p2c * RMatrix.gateway_weights(), axis=1)

            prov_funnel_s[:] = np.sum(state0_p2c, axis=0)
            prov_funnel_s_rov[:] = np.sum(state1_p2c, axis=0)

            pickle.dump(cone_funnel_sizes, open(cone_funnel_fpath, "wb"), protocol=4)
        return cust_cone_s, cust_cone_s_rov, prov_funnel_s, prov_funnel_s_rov
    cust_cone_s, cust_cone_s_rov, prov_funnel_s, prov_funnel_s_rov = get_cone_funnel_size()

    # AS hegemony (global/with ROV)
    def get_hegemony():
        hegemony_fpath = save_dir/"hegemony"
        if hegemony_fpath.exists():
            hegemony = pickle.load(open(hegemony_fpath, "rb"))
            counts, counts_with_rov, counts_prev_rov, counts_post_rov = hegemony
        else:
            size = len(RMatrix.__idx2asn__)
            hegemony = np.zeros((4, size), dtype=np.int64)
            counts, counts_with_rov, counts_prev_rov, counts_post_rov = hegemony
            rov_array = rm1.__exclude_mask__
            AS_hegemony(rm0.__next_hop__, rov_array, counts, counts_with_rov, counts_prev_rov, counts_post_rov)
            pickle.dump(hegemony, open(hegemony_fpath, "wb"), protocol=4)
        return counts, counts_with_rov, counts_prev_rov, counts_post_rov
    counts, counts_with_rov, counts_prev_rov, counts_post_rov = get_hegemony()

    # path length (characteristic/from ROV networks/eccentricity)
    def get_path_length():
        path_length_fpath = save_dir/"path_length"
        if path_length_fpath.exists():
            path_length = pickle.load(open(path_length_fpath, "rb"))
            min_rov_dist, max_rov_dist, avg_rov_dist = path_length
        else:
            size = len(RMatrix.__idx2asn__)
            path_length = np.empty((3, size), dtype=np.float64)
            min_rov_dist, max_rov_dist, avg_rov_dist = path_length

            rov = rm1.__exclude_mask__

            def get_dist_stats(row):
                keep = row > 0b00_111111
                if not keep.any(): # NOTE
                    return -1, -1, -1
                dist = 0b00_111111 - (row[keep] & 0b00_111111)
                return dist.min(), dist.max(), dist.mean()

            path_length.T[:] = list(map(get_dist_stats, rm0.__state__[:, rov]))
            pickle.dump(path_length, open(path_length_fpath, "wb"), protocol=4)
        return min_rov_dist, max_rov_dist, avg_rov_dist
    min_rov_dist, max_rov_dist, avg_rov_dist = get_path_length()

    # impact index (AS hegemony stats for rm1 reachable nodes)
    def get_impact_index(counts, counts_with_rov, counts_prev_rov, counts_post_rov):
        impact_index_fpath = save_dir/"impact_index"
        if impact_index_fpath.exists():
            impact_index = pickle.load(open(impact_index_fpath, "rb"))
            total_impact, total_rov_impact, total_prev_rov_impact, total_post_rov_impact, avg_impact, avg_rov_impact, avg_prev_rov_impact, avg_post_rov_impact = impact_index
        else:
            size = len(RMatrix.__idx2asn__)
            impact_index = np.empty((8, size), dtype=np.float64)
            total_impact, total_rov_impact, total_prev_rov_impact, total_post_rov_impact, avg_impact, avg_rov_impact, avg_prev_rov_impact, avg_post_rov_impact = impact_index

            def get_impact_stats(row):
                reachable = row > 0b00_111111
                if not reachable.any(): # NOTE
                    return 0, 0, 0, 0, 0, 0, 0, 0
                cr = counts[reachable]
                cr_with_rov = counts_with_rov[reachable]
                cr_prev_rov = counts_prev_rov[reachable]
                cr_post_rov = counts_post_rov[reachable]
                return cr.sum(), cr_with_rov.sum(), cr_prev_rov.sum(), cr_post_rov.sum(), cr.mean(), cr_with_rov.mean(), cr_prev_rov.mean(), cr_post_rov.mean()

            impact_index.T[:] = list(map(get_impact_stats, rm1.__state__))
            pickle.dump(impact_index, open(impact_index_fpath, "wb"), protocol=4)
        return total_impact, total_rov_impact, total_prev_rov_impact, total_post_rov_impact, avg_impact, avg_rov_impact, avg_prev_rov_impact, avg_post_rov_impact
    total_impact, total_rov_impact, total_prev_rov_impact, total_post_rov_impact, avg_impact, avg_rov_impact, avg_prev_rov_impact, avg_post_rov_impact = get_impact_index(counts, counts_with_rov, counts_prev_rov, counts_post_rov)

    df = pd.DataFrame.from_dict({
        # degree centrality
        "degree_all": deg_all,
        "degree_out": deg_out,
        "degree_in": deg_in,
        "degree_prov": deg_prov,
        "degree_cust": deg_cust,
        # customer cone size
        "cust_cone_size": cust_cone_s,
        "cust_cone_size_rov": cust_cone_s_rov,
        # provider funnel size
        "prov_funnel_size": prov_funnel_s,
        "prov_funnel_size_rov": prov_funnel_s_rov,
        # AS hegemony
        "hegemony_counts": counts,
        "hegemony_counts_with_rov": counts_with_rov,
        "hegemony_counts_prev_rov": counts_prev_rov,
        "hegemony_counts_post_rov": counts_post_rov,
        # path length
        "min_distance_to_rov": min_rov_dist,
        "max_distance_to_rov": max_rov_dist,
        "avg_distance_to_rov": avg_rov_dist,
        # impact index
        "total_impact": total_impact,
        "total_impact_with_rov": total_rov_impact,
        "total_impact_prev_rov": total_prev_rov_impact,
        "total_impact_post_rov": total_post_rov_impact,
        "avg_impact": avg_impact,
        "avg_impact_with_rov": avg_rov_impact,
        "avg_impact_prev_rov": avg_prev_rov_impact,
        "avg_impact_post_rov": avg_post_rov_impact,
    })

    df.to_csv(save_dir/"as_stats_all.csv", index=False)
    return df

@click.command()
@click.option('--n-jobs', type=int, default=1, help="Max number of parallel processes.")
def main(n_jobs):
    rov_list, rm0, rm1, matrix_dir, as_rel_fpath = \
        pre_process("20250310", "20250301", n_jobs=n_jobs)

    AttackerAnalyzer.attacker_key_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)
    AttackerAnalyzer.attacker_target_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)
    AttackerAnalyzer.attacker_victim_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)

    VictimAnalyzer.victim_key_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)
    VictimAnalyzer.victim_target_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)

    TargetAnalyzer.target_key_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)

    attacker_exact_prefix_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)
    victim_exact_prefix_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)

    direct_exact_prefix_analysis(rm0, rm1, matrix_dir, n_jobs=n_jobs)
    direct_exact_prefix_analysis(rm0, rm0, matrix_dir, suffix="_without_ROV", n_jobs=n_jobs)

    vict_hijk_rov_attribution(rm0 ,rm1, matrix_dir, n_jobs=n_jobs)

    as_stats_dir = matrix_dir/"as_stats"
    as_stats_dir.mkdir(parents=True, exist_ok=True)
    get_as_stats(rm0, rm1, as_stats_dir)

if __name__ == "__main__":
    main()
