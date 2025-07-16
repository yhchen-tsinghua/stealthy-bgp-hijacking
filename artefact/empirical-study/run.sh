#!/usr/bin/env bash

# Exit immediately if any command exits with a non-zero status
set -e

# Select RouteViews collectors as input
COLLECTORS=("wide" "amsix" "route-views2")

# Get into the directory where this bash script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1 

# === STEP 1 ===
# Run the backend routine to discover stealthy BGP hijacking incidents
# using RouteViews RIBs from collectors wide, amsix, and route-views2,
# each captured at 12:00 Jan 1, 2025. The initial-incident-id parameter
# is set to zero since this is our first run. In actual deployment, we
# register a cron-job to call this backend routine daily, in which case
# we have to track the total number of incidents discovered so far and
# set the initial-incident-id to that number plus one for the next run.
# For artefact evaluation, you can ignore this parameter as we only run
# the backend routine once for demonstration, rather than daily. Results
# are stored in "./result" and have symbolic links for the frontend to 
# use in STEP 3 later. Results are also copied to "/shared" so users can
# access them from outside the docker container.
RESULT_DIR="$SCRIPT_DIR/result"
RESULT_PREFIX="20250101.1200.$(printf "%s\n" "${COLLECTORS[@]}" | sort | paste -sd "_")"
RESULT1="$RESULT_DIR/$RESULT_PREFIX.alarms.json"
RESULT2="$RESULT_DIR/$RESULT_PREFIX.incidents.json"
LINK_DIR="$SCRIPT_DIR/frontend/public/webpage"
LINK1="$LINK_DIR/all-alarms.json"
LINK2="$LINK_DIR/all-incidents.json"
if [ ! -f "$RESULT1" ] || [ ! -f "$RESULT2" ]; then
    echo "Calling backend routine..."
    ./backend_routine.py \
        --collectors "$(printf "%s\n" "${COLLECTORS[@]}" | sort | paste -sd ",")" \
        --year 2025 \
        --month 1 \
        --day 1 \
        --hour 12 \
        --initial-incident-id 0
else
    echo "Backend results already exist."
fi

[ ! -e "$LINK1" ] && ln -s "$RESULT1" "$LINK1"
[ ! -e "$LINK2" ] && ln -s "$RESULT2" "$LINK2"

SHARED_DIR="/shared"
chmod -R 777 $RESULT_DIR/*
cp -a $RESULT_DIR/* $SHARED_DIR

# === STEP 2 ===
# Reprodue all figures (except for Figure 5, which is manually created
# using MS PPT) in the empirical study (i.e., Section IV of the paper).
# The results are stored in './result' and also copied to "/shared" so
# users can access them from outside the docker container. Note that,
# this script do not use results of the previous step, which are only
# one-day's results. To reproduce, it uses all incidents and alarms
# captured in the first two months of year 2025, which are preserved in 
# "data/service" beforehand and are exactly a snapshot of the results 
# on 2025/07/11 captured by our service in production.
echo "Reproducing all results in Section IV..."
./reproduce.py
chmod -R 777 $RESULT_DIR/*
cp -a $RESULT_DIR/* $SHARED_DIR

# === STEP 3 ===
# Set up the frontend to present backend results. Once the service is
# up, it can be accessed at http://localhost:3000/ using a browser.
# Reviewers are also encouraged to view a production version of this
# service at https://anonymized4review.online/.
echo "Setting up frontend service..."
echo "(Enter CTRL-C to stop)"
cd frontend
npm start
