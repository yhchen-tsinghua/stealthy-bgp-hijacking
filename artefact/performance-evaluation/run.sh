#!/usr/bin/env bash

# Exit immediately if any command exits with a non-zero status
set -e

# Get into the directory where this bash script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1 

# === STEP 1 (Optional) ===
# Benchmark the runtime of matrix-bgpsim and bgpsim. This script will:
# 1. Generate a sampled Internet topology that contains 10,000 ASes, based
#    on CAIDA serial-2 AS relationship dataset on 2025/01/01. This process
#    starts with Tier-1 mesh and progressively adds new ASes that connects
#    to the existing topology, until the number of ASes reaches 10,000. It
#    is saved to '.cache/sample_topo.20250101.10000.txt'.
# 2. Test how long bgpsim generates all routes between any random 10, 20,
#    30, 40, 50, 60, 70, 80, 90, and 100 ASes, resp. on the aforementioned
#    sampled topology. Each run is repeated ten times. The result is saved
#    to '.cache/bgpsim.csv'.
# 3. Test how long matrix-bgpsim generates routes between all 10,000 ASes
#    on the aforementioned sampled topology, and then scales the time by
#    the number of routes linearly to approximate the time matrix-bgpsim
#    takes to generate all routes between any random 10, 20, 30, 40, 50,
#    60, 70, 80, 90, and 100 ASes, resp. The number of CPU cores 'n_jobs'
#    is also set to 1, 20, and 40, resp. The result is saved to '.cache/
#    matrix_bgpsim_1.csv', '.cache/matrix_bgpsim_20.csv', and '.cache/mat
#    rix_bgpsim_40.csv'.
# 4. Test how long matrix-bgpsim generates routes between all 10,000 ASes
#    on the aforementioned sampled topology using GPU, and then scales the
#    time by the number of routes linearly to approximate the time matrix-
#    bgpsim takes to generate all routes between any random 10, 20, 30, 40,
#    50, 60, 70, 80, 90, and 100 ASes, resp. The result is saved to '.cache
#    /matrix_bgpsim_gpu.csv'.
# NOTE: These results are used to reproduce Figure 16. However, since the
#       runtime would vary on different platforms, and it requires certain
#       hardware such as GPU, the results would not be exactly same as what
#       is reported in the paper. For this reason, we provide the benchmark
#       results on our platform under the '.cache/', and you can skip this
#       part by default if you don't want to run it and the next step would
#       then use these results to reproduce Figure 16. If you do want to run
#       benchmarking on your own, please uncomment the line below so it will
#       run this part. The new results will override the old ones.

# -- Uncomment the next line to re-run this part --
# RERUN=1

if [[ -n "$RERUN" ]]; then
    echo "Benchmarking..."
    ./benchmark.py
fi

# === STEP 2 ===
# Reprodue all figures and tables in the performance evaluation
# section (i.e., Section VII of the paper). The results are stored
# in './result' and also copied to "/shared" so users can access
# them from outside the docker container.
RESULT_DIR="$SCRIPT_DIR/result"
SHARED_DIR="/shared"
echo "Reproducing all results in Section VII..."
./reproduce.py
chmod -R 777 $RESULT_DIR/*
cp -a $RESULT_DIR/* $SHARED_DIR
