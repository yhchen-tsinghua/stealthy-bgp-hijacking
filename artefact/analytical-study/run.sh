#!/usr/bin/env bash

# Exit immediately if any command exits with a non-zero status
set -e

# Get into the directory where this bash script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1 

# === STEP 1 (Optional) ===
# Run matrix-based BGP route inference. This script will:
# 1. Infer routes on the bengin reach.
#       => matrix stored at 'data/matrices/*/normal.rm.lz4'
# 2. Infer routes on the malicious reach.
#       => matrix stored at 'data/matrices/*/rov_block.rm.lz4'
# 3. Do all kinds of analysis based on these results.
#       => matrices stored as 'data/matrices/*/mat_*.lz4'
#       => AS statistics stored under 'data/matrices/*/as_stats/'
# NOTE: A complete run of this part would normally take 10+ hours
#       to days, depending on n_jobs/CPU power. For convenience, we
#       provide pre-computed matrices under the 'data/matrices/',
#       and you can skip this part if you don't want to run it.
#       If you do want to re-run it on your own, please uncomment
#       the line below so the script will run this part. The new
#       results will override the old ones. You can also adjust 
#       the number of parallel processes to fit your platform.

# -- Uncomment the next line to re-run this part --
# RERUN=1

# -- Set N_JOBS to the number of available CPU cores --
N_JOBS="$(nproc)"

if [[ -n "$RERUN" ]]; then
    echo "Running risk analysis..."
    echo "Maximal parallel workers: $N_JOBS"
    ./risk_analysis.py --n-jobs "$N_JOBS"
fi

# === STEP 2 ===
# Reprodue all statistics, figures, and tables in the analytical
# study (i.e., Section VI of the paper). The results are stored
# in './result' and also copied to "/shared" so users can access
# them from outside the docker container.
RESULT_DIR="$SCRIPT_DIR/result"
SHARED_DIR="/shared"
echo "Reproducing all results in Section VI..."
./reproduce.py
chmod -R 777 $RESULT_DIR/*
cp -a $RESULT_DIR/* $SHARED_DIR
