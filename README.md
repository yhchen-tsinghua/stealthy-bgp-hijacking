# Artefact for NDSS26 Summer Paper: Understanding the Stealthy BGP Hijacking Risk in the ROV Era

This is the artefact reporsitory for the [paper](https://dx.doi.org/10.14722/ndss.2026.230097) _Understanding the Stealthy BGP Hijacking Risk in the ROV Era_ in the summer cycle of NDSS 2026. Please follow the steps below to reproduce all results in the paper.

**NOTE:** The matrix-based BGP simulator is maintained in a standalone [GitHub repository](https://github.com/yhchen-tsinghua/matrix-bgpsim) and has already been released on [PyPI](https://pypi.org/project/matrix-bgpsim/). Please check it out!

## Overview

Overall, the paper has three parts of experiments: an empricial study (§IV), an analytical study (§VI), and performance evaluation (§VII). Particularly, the analytical study and performance evaluation center around the proposed matrix-based BGP route inference approach, which is implemented as a standalone Python package (`matrix-bgpsim`). The repository outlines this structure exactly:

```bash
.
├── artefact
│   ├── empirical-study         # ----- Part 1 -----
│   │   ├── backend_routine.py  # service backend
│   │   ├── data/               # data directory
│   │   ├── frontend/           # service frontend
│   │   ├── reproduce.py        # reproduce §IV
│   │   └── run.sh              # run through part 1
│   ├── analytical-study        # ----- Part 2 -----
│   │   ├── data/               # data directory
│   │   ├── reproduce.py        # reproduce §VI
│   │   ├── risk_analysis.py    # analyze the risk
│   │   └── run.sh              # run through part 2
│   ├── performance-evaluation  # ----- Part 3 -----
│   │   ├── benchmark.py        # test performance
│   │   ├── data/               # data directory
│   │   ├── reproduce.py        # reproduce §VII
│   │   └── run.sh              # run through part 3
│   └── matrix-bgpsim           # - Implementation -
│       ├── matrix_bgpsim/      # package code
│       ├── pyproject.toml      # package config
│       └── README.md           # package README
├── docker-compose.gpu.yml # docker config for GPU
├── docker-compose.yml     # docker config for CPU
├── environment.yml        # conda package config
├── README.md              # this readme
└── run.sh                 # start docker container
```

The high-level workflow is as follows:

1. Prepare the runtime environment (see [Environment Preparation](#environment-preparation))
2. Run `artefact/empirical-study/run.sh` (see [Reproducing the Empirical Study](#1-reproducing-the-empirical-study))
3. Run `artefact/analytical-study/run.sh` (see [Reproducing the Analytical Study](#2-reproducing-the-analytical-study))
4. Run `artefact/performance/run.sh` (see [Reproducing the Performance Evaluation](#3-reproducing-the-performance-evaluation))

The resource required during the runtime is estimated as follows:

-   At least 120GB free memory
-   At least 60GB free disk space
-   Internet access
-   3-4 hours run-through time

**Please kindly read this before you proceed:**

-   We understand that the required resource is significant, so **we have prepared a cloud platform ready for your evaluation**. The access key is provided via HotCRP. As such, we highly recommend you to use our prepared platform to reduce the burden.
-   If you want to test the artefact on your own platform, **we highly recommend you to choose the docker approach** (detailed later) rather than build the environment from scratch, as there are many third-party tools (e.g., NodeJS, [BGPdump](https://github.com/RIPE-NCC/bgpdump), and [BGPsim](https://github.com/Fraunhofer-SIT/bgpsim/tree/main)) that we do not include in this repository and that you have to compile from source following their instructions, which are non-trivial.

## Environment Preparation

### Using Our Cloud Platform

You do not need extra preparations. Just SSH into the provided user account on our cloud platform and start a docker container:

```bash
# Step 1: SSH into our cloud platform.
# The user account will be provided via HotCRP.
ssh $YOUR_USER_NAME@$OUR_CLOUD_PLATFORM_ADDRESS

# Step 2: On the cloud platform, enter the repository and starts a container.
cd ndss26-ae20
./run.sh
```

Now you are in the container and can proceed with the [Detailed Steps](#detailed-steps). Note that the container is started with `--rm` option, which means once you exit the container, the container will be automatically removed and any changes within the container would be gone. To preserve any results within the container, please copy them into the shared directory `/shared`, which is mounted to `./shared` on the host. Our scripts in the [Detailed Steps](#detailed-steps) will also automatically copy the expected results to this shared directory. Please see `./run.sh` for detailed container startup configuration and modify it for your custom needs.

### Using Your Own Platform with Docker

Please follow these steps to prepare the environment:

1. Download the repository.
    ```bash
    git clone git@github.com:yhchen-tsinghua/stealthy-bgp-hijacking.git ndss26-ae20
    cd ndss26-ae20
    ```
2. Download the pre-built docker image (\~7.8GB).

    ```bash
    URL="https://zenodo.org/records/16732324/files/docker-image.tar.gz?download=1"
    curl -L $URL -o docker-image.tar.gz
    ```

3. Download the pre-computed matrices archive (\~31.2GB), extract it, and configure its location within `docker-compose.yml` and `docker-compose-gpu.yml` so that it can be properly mounted into the docker container. See [Detailed Steps](#detailed-steps) for why these matrices are needed.

    ```bash
    URL="https://zenodo.org/records/16732324/files/matrices.tar.gz?download=1"
    curl -L $URL -o matrices.tar.gz
    tar -xzvf matrices.tar.gz

    # Move the matrices directory to the mounted location. You may
    # also modify docker-compose.yml and docker-compose-gpu.yml to
    # change this mounted location.
    mv matrices /opt/matrices
    ```

4. Start the docker container.

    ```bash
    ./run.sh
    ```

Now you are in the container and can proceed with the [Detailed Steps](#detailed-steps). Note that the container is started with `--rm` option, which means once you exit the container, the container will be automatically removed and any changes within the container would be gone. To preserve any results within the container, please copy them into the shared directory `/shared`, which is mounted to `./shared` on the host. Our scripts in the [Detailed Steps](#detailed-steps) will also automatically copy the expected results to this shared directory. Please see `./run.sh` for detailed container startup configuration and modify it for your custom needs.

### Using Your Own Platform without Docker

Please follow these steps to prepare the environment:

1.  Download the repository.

    ```bash
    git clone git@github.com:yhchen-tsinghua/stealthy-bgp-hijacking.git ndss26-ae20
    cd ndss26-ae20/artefact
    ```

2.  Download the pre-computed matrices archive (\~31.2GB), extract it, and move it to the data directory that can be found by all scripts.

    ```bash
    URL="https://zenodo.org/records/16732324/files/matrices.tar.gz?download=1"
    curl -L $URL -o matrices.tar.gz
    tar -xzvf matrices.tar.gz

    # Move matrices to the data directory
    mv matrices ./empirical-study/data
    ```

3.  Install all required tools.

    ```bash
    # All tools for compiling
    BUILD_DEPS="cmake build-essential swig autoconf zlib1g-dev libbz2-dev wget"
    # All tools for runtime
    RUNTIME_DEPS="whois ca-certificates time"

    sudo apt-get update
    sudo apt-get install -y --no-install-recommends $BUILD_DEPS $RUNTIME_DEPS
    ```

4.  Install miniconda and create an environment with all the required Python packages.

    ```bash
    CONDA_DIR=/opt/conda
    CONDA_ENV_NAME=artefact

    # Install miniconda
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh && \
    bash /tmp/miniconda.sh -b -p $CONDA_DIR && \
    $CONDA_DIR/bin/conda update -n base -c defaults conda -y
    rm /tmp/miniconda.sh

    # Create the environment
    $CONDA_DIR/bin/conda env create -f environment.yml && \
    $CONDA_DIR/bin/conda clean --all -y && \
    $CONDA_DIR/bin/conda activate $CONDA_ENV_NAME
    echo "source activate $CONDA_ENV_NAME" >> ~/.bashrc
    ```

5.  Install frontend NodeJS modules (NodeJS and NPM were installed with miniconda in the previous step).

    ```bash
    cd ./empirical-study/frontend
    npm install
    cd ../../
    ```

6.  Install `matrix-bgpsim` module.

    ```bash
    cd ./matrix-bgpsim
    pip install .
    cd ../
    ```

7.  Install `bgpsim` module (this is a third-party tool for baseline comparison).

    ```bash
    git clone https://github.com/Fraunhofer-SIT/bgpsim.git
    cd ./bgpsim
    mkdir -p build
    cd build
    cmake ..
    make
    sudo make install
    cd ../../
    ```

    Note that the compiling process may encouter several errors. Following the suggestions by the compiler should fix them all.

    See their [original repository](https://github.com/Fraunhofer-SIT/bgpsim/tree/main) for detailed instructions.

8.  Install `bgpdump` tool (this is a third-party tool for parsing BGP data).

    ```bash
    git clone https://github.com/RIPE-NCC/bgpdump.git
    cd ./bgpdump
    sh ./bootstrap.sh
    make
    cp bgpdump /usr/bin/
    cd ../
    ```

    See their [original repository](https://github.com/RIPE-NCC/bgpdump) for detailed instructions.

9.  Clean up.

    ```bash
    rm -rf ./bgpsim ./bgpdump
    sudo apt-get purge -y --auto-remove $BUILD_DEPS
    sudo apt-get clean
    ```

Now you can proceed with the [Detailed Steps](#detailed-steps).

## Detailed Steps

The working directory should be now at the `artefact` directory of the repository, meaning that `ls` should show `empirical-study`, `analytical-study`, `performance-evaluation`, and `matrix-bgpsim`. Next, please follow the steps below in sequence to reproduce all results.

### 1. Reproducing the Empirical Study

The files relevant to this part are structured as follows:

```bash
.
└── empirical-study         # ----- Part 1 -----
    ├── backend_routine.py  # service backend
    ├── data/               # data directory
    ├── frontend/           # service frontend
    ├── reproduce.py        # reproduce §IV
    └── run.sh              # run through part 1
```

Run `./empirical-study/run.sh`, which will:

1. Run the backend routine (`./empirical-study/backend_routine.py`).

    - **What happens:** This routine call discovers stealthy BGP hijacking incidents using RouteViews RIBs from collectors `wide`, `amsix`, and `route-views2`, each captured at 12:00 Jan 1, 2025. This is a scaled-down demo for a one-day discovery. In actual deployment, we register a cron-job to call this backend routine daily.
    - **What to expect:** The results will be saved to `./empirical-study/results`, including `20250101.1200.amsix_route-views2_wide.alarms.json` and `20250101.1200.amsix_route-views2_wide.incidents.json`. Symbolic links are also created under `./empirical-study/frontend/public/webpage` for the frontend to display these results later. These results are also copied to `/shared` so you can access them from outside the docker container at `./shared` on the host.

2. Run `./empirical-study/reproduce.py` to reproduce all figures and tables in §IV, except for Figure 5, which is manually created using MS PPT.

    - **What happens:** This script does not use results of the previous step, which are only one-day's results. To reproduce, it uses all incidents and alarms captured in the first two months of year 2025, which are preserved in `./empirical-study/data/service` beforehand and are exactly a snapshot of the results by 2025/07/11 from [our service in production](https://yhchen.cn/stealthy-bgp-hijacking).
    - **What to expect:** The figures listed below are created under `./empirical-study/results`, and are also copied to `/shared` so you can access them from outside the docker container at `./shared` on the host.
        - `incidents-breakdown.pdf` -> Figure 2
        - `overall_impact.json` -> Table II
        - `daily-incidents.pdf` -> Figure 3
        - `vp-distribution.pdf` -> Figure 4

3. Set up the service frontend (`./empirical-study/frontend/`)
    - **What happens:** this step starts the frontend service through `npm start` to display the backend results (i.e., `20250101.1200.amsix_route-views2_wide.alarms.json` and `20250101.1200.amsix_route-views2_wide.incidents.json`) generated from the first step.
    - **What to expect:** Once the service is up, it can be accessed at http://localhost:3000/ using a browser. If you are using a docker container, the port is also mapped to 3000 on the host, so you can also access the service through http://localhost:3000/ on the host using a browser. If a browser is not available, try use `wget` or `curl`, which, however, would only get the static html page and would not render the JS script. Reviewers are also encouraged to view our production version of this service at https://yhchen.cn/stealthy-bgp-hijacking.

### 2. Reproducing the Analytical Study

The files relevant to this part are structured as follows:

```bash
.
└── analytical-study        # ----- Part 2 -----
    ├── data/               # data directory
    ├── reproduce.py        # reproduce §VI
    ├── risk_analysis.py    # analyze the risk
    └── run.sh              # run through part 2
```

Run `./analytical-study/run.sh`, which will:

1. (Optional) run `./analytical-study/risk_analysis.py` for matrix-based BGP route inference.

    - **What happens:** This script will

        - Infer routes on the benign reach, with its matrix saved to `./analytical-study/data/matrices/*/normal.rm.lz4`.
        - Infer routes on the malicious reach, with its matrix saved to `./analytical-study/data/matrices/*/rov_block.rm.lz4`.
        - Do all kinds of risk analysis based on these matrices, and save more intermediate matrices to `./analytical-study/data/matrices/*/mat_*.lz4` and save various AS statistics information under `./analytical-study/data/matrices/*/as_stats/`.

        **Note:** A clean run of this script would normally take 10+ hours to even days, depending on the CPU power and the number of parallel processes set by `n_jobs` (see the script). For convenience, we provide pre-computed matrices mounted to `./analytical-study/data/matrices/`, and by default the script will not run this step. If you do want to re-run it on your own, please edit `./analytical-study/run.sh` and uncomment the line `# RERUN=1` so the script will run this part. The new results will override the pre-computed ones. You can also adjust the number of parallel processes in the script to fit your platform.

    - **What to expect:** The intermediate results will be saved under `./analytical-study/data/matrices/`, which are used by the next step to reproduce the end results in §VI.

2. Run `./analytical-study/reproduce.py` to reproduce all figures and tables in §VI.

    - **What happens:** This script uses the results of the previous step, conducts further analysis, and generates all kinds of figures and tables in §VI.
    - **What to expect:** The figures listed below are created under `./analytical-study/results`, and are also copied to `/shared` so you can access them from outside the docker container at `./shared` on the host.
        - `route_number.json` -> the numbers in the second paragraph of §VI.A
        - `rov_measurement_20250310.pdf` -> Figure 7
        - `tab-risk-dissection.tex` -> Table IV
        - `aggregated_risk_level.pdf` -> Figure 8
        - `distribution_over_ASes.pdf` -> Figure 9
        - `distribution_over_geo.pdf` -> Figure 10
        - `factor_analysis.pdf` -> Figure 11
        - `correlation_scatter.pdf` -> Figure 12
        - `risk_attribution.pdf` -> Figure 13

### 3. Reproducing the Performance Evaluation

The files relevant to this part are structured as follows:

```bash
.
└── performance-evaluation  # ----- Part 3 -----
    ├── benchmark.py        # test performance
    ├── data/               # data directory
    ├── reproduce.py        # reproduce §VII
    └── run.sh              # run through part 3
```

Run `./performance-evaluation/run.sh`, which will:

1. (Optional) run `./performance-evaluation/benchmark.py` to benchmark the runtime of our `matrix-bgpsim` and the baseline `bgpsim`.

    - **What happens:** This script will

        - Generate a sampled Internet topology that contains 10,000 ASes, based on CAIDA serial-2 AS relationship dataset on 2025/01/01. This process starts with Tier-1 mesh and progressively adds new ASes that connects to the existing topology, until the number of ASes reaches 10,000. It is saved to `./performance-evaluation/.cache/sample_topo.20250101.10000.txt`.
        - Test how long `bgpsim` generates all routes between any random 10, 20, 30, 40, 50, 60, 70, 80, 90, and 100 ASes, respectively, on the aforementioned sampled topology. Each run is repeated ten times. The result is saved to `./performance-evaluation/.cache/bgpsim.csv`.
        - Test how long `matrix-bgpsim` generates routes between all 10,000 ASes on the aforementioned sampled topology, and then linearly scales the time by the number of routes to approximate the time `matrix-bgpsim` takes to generate all routes between any random 10, 20, 30, 40, 50, 60, 70, 80, 90, and 100 ASes, respectively. Each setting is tested with the number of parallel processes set to 1, 20, and 40, respectively. The result is saved to `./performance-evaluation/.cache/matrix_bgpsim_1.csv`, `./performance-evaluation/.cache/matrix_bgpsim_20.csv`, and `./performance-evaluation/.cache/matrix_bgpsim_40.csv`.
        - Repeat the previous setting but test `matrix-bgpsim` with GPU. The result is saved to `./performance-evaluation/.cache/matrix_bgpsim_gpu.csv`.

        **Note:** These results are used to reproduce Figure 16. However, since the runtime would vary on different platforms, and it requires certain hardware such as GPU, the results would not be exactly the same as what is reported in the paper. For this reason, we provide our previously benchmarked results under the `./performance-evaluation/.cache/`, so this part would be skipped by default and the next step would then use these preserved results to reproduce Figure 16. If you do want to run benchmarking on your own, please edit `./performance-evaluation/run.sh` and uncomment the line `# RERUN=1` so the script will run this part. The new results will override the provided ones.

    - **What to expect:** The benchmark results will be saved under `./performance-evaluation/.cache`, which are used by the next step to reproduce the end results in §VII.

2. Run `./performance-evaluation/reproduce.py` to reproduce all figures and tables in §VII.

    - **What happens:** This script uses the results of the previous step and also those preserved in `./empirical-study/data/service` ([previously](#1-reproducing-the-empirical-study) described) to evaluate the performance of our framework, and generates all kinds of figures and tables in §VII.
    - **What to expect:** The figures listed below are created under `./performance-evaluation/results`, and are also copied to `/shared` so you can access them from outside the docker container at `./shared` on the host.
        - `acc.pdf` -> Figure 15
        - `resistance.pdf` -> Figure 16
        - `ablation-table.tex` -> Table V
        - `runtime_performance.pdf` -> Figure 17

---
