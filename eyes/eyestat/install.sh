#!/usr/bin/env bash
#
# install.sh — Fresh-system setup for EyeStat on Ubuntu 24.04 LTS.
#
# What it does (in order):
#   0. Pre-flight        verify Ubuntu version, sudo, project files present
#   1. System packages   python3-venv, build-essential, gcc, git, etc.
#   2. Nvidia driver     detect or install (reboot required if installed)
#   3. CUDA toolkit 12.8 via NVIDIA's apt repo (needed for sm_120 / RTX 50xx)
#   4. Python venv       create + activate ~/.venvs/eyestat
#   5. Python packages   numpy, scipy, and cupy-cuda12x (if GPU present)
#   6. Validation        run eyestat_selftest.py, eyestat_preflight.py, eyestat_gpu_probe.py
#
# USAGE
#   ./install.sh                 # full install (default — autodetects GPU)
#   ./install.sh --no-gpu        # CPU-only (skip NVIDIA driver + CUDA + CuPy)
#   ./install.sh --no-cuda       # keep existing CUDA, skip toolkit upgrade
#   ./install.sh --venv-path X   # use a different venv location (default ~/.venvs/eyestat)
#   ./install.sh --skip-validate # don't run selftest/preflight/probe at the end
#   ./install.sh --quiet         # less output (still shows errors)
#
# Safe to re-run — every step checks if the work is already done.
#

set -euo pipefail

# ----- Color + helpers -----
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    CYAN=$'\033[96m'; GREEN=$'\033[92m'; YELLOW=$'\033[93m'
    RED=$'\033[91m'; DIM=$'\033[90m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    CYAN=''; GREEN=''; YELLOW=''; RED=''; DIM=''; BOLD=''; RESET=''
fi

ok()      { printf "  ${GREEN}[OK]${RESET}   %s\n"   "$1"; }
warn()    { printf "  ${YELLOW}[WARN]${RESET} %s\n" "$1"; }
fail()    { printf "  ${RED}[FAIL]${RESET} %s\n"   "$1" >&2; exit 1; }
info()    { printf "  ${CYAN}[INFO]${RESET} %s\n"  "$1"; }
banner()  { printf "\n${BOLD}${CYAN}[[ %s ]]${RESET}\n" "$1"; }
step()    { printf "${DIM}    ▶ %s${RESET}\n" "$1"; }

# ----- Defaults -----
SKIP_GPU=false
SKIP_CUDA=false
SKIP_VALIDATE=false
QUIET=false
VENV_PATH="$HOME/.venvs/eyestat"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CUDA_VERSION="12-8"   # Blackwell-compatible
CUPY_PACKAGE="cupy-cuda12x"

# ----- Argument parsing -----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-gpu)       SKIP_GPU=true; SKIP_CUDA=true ;;
        --no-cuda)      SKIP_CUDA=true ;;
        --skip-validate) SKIP_VALIDATE=true ;;
        --quiet)        QUIET=true ;;
        --venv-path)    VENV_PATH="$2"; shift ;;
        -h|--help)
            # Print just the leading docstring block (stop at first blank or non-# line)
            awk '/^#!/ {next} /^# / {sub(/^# ?/, ""); print; next} /^#$/ {print ""; next} {exit}' "$0"
            exit 0 ;;
        *) fail "Unknown argument: $1 (try --help)" ;;
    esac
    shift
done

# ----- Top banner -----
echo
printf "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}${CYAN}║  BF PROJECT // FRESH-SYSTEM INSTALL // Ubuntu 24.04 LTS       ║${RESET}\n"
printf "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════╝${RESET}\n"

# ====================================================================
# STAGE 0 — Pre-flight
# ====================================================================
banner "0. Pre-flight"

# Verify Ubuntu
if [[ ! -r /etc/os-release ]]; then
    fail "/etc/os-release not found — is this Linux?"
fi
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
    warn "This script targets Ubuntu — you're on ${ID:-unknown}. Proceeding anyway."
fi
if [[ "${VERSION_ID:-}" != "24.04" ]]; then
    warn "This script is tuned for Ubuntu 24.04 LTS — you're on ${VERSION_ID:-unknown}."
    warn "It will likely still work, but adjust if you hit version-specific issues."
else
    ok "Ubuntu ${VERSION_ID} (${VERSION_CODENAME:-noble}) detected"
fi

# Verify project files
REQUIRED_FILES=(eyestat_runner.py eyestat_kernels.py eyestat_prngs.py eyestat_scoring.py
                eyestat_selftest.py eyestat_preflight.py noita_eye_data.json)
MISSING=()
for f in "${REQUIRED_FILES[@]}"; do
    [[ -f "$PROJECT_DIR/$f" ]] || MISSING+=("$f")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    fail "Missing required files in $PROJECT_DIR: ${MISSING[*]}"
fi
ok "All required project files present in $PROJECT_DIR"

# Verify sudo access (will prompt later if needed; just check it's available)
if ! command -v sudo &>/dev/null; then
    fail "sudo not installed — this script needs sudo to apt-install system packages"
fi
if sudo -n true 2>/dev/null; then
    ok "sudo available (cached or passwordless)"
else
    info "sudo will prompt for password when needed"
fi

# Detect GPU
HAVE_GPU=false
if [[ "$SKIP_GPU" == "false" ]]; then
    if lspci 2>/dev/null | grep -qi nvidia; then
        GPU_NAME=$(lspci 2>/dev/null | grep -iE '(vga|3d).*nvidia' | head -1 | sed 's/.*: //' || echo "Nvidia GPU")
        ok "Nvidia GPU detected: $GPU_NAME"
        HAVE_GPU=true
    else
        warn "No Nvidia GPU detected — switching to CPU-only mode"
        SKIP_GPU=true
        SKIP_CUDA=true
    fi
fi

# ====================================================================
# STAGE 1 — System packages
# ====================================================================
banner "1. System packages (apt)"

info "Updating apt package lists..."
sudo apt-get update -qq

info "Installing base packages: python3-venv, python3-dev, build tools, scipy..."
sudo apt-get install -y -qq \
    python3 python3-venv python3-dev \
    build-essential gcc g++ make \
    git curl wget ca-certificates gnupg lsb-release \
    python3-numpy python3-scipy \
    bc \
    >/dev/null
ok "Base packages installed"

# ====================================================================
# STAGE 2 — Nvidia driver
# ====================================================================
if [[ "$SKIP_GPU" == "false" ]]; then
    banner "2. Nvidia driver"

    if command -v nvidia-smi &>/dev/null && nvidia-smi >/dev/null 2>&1; then
        DRIVER_VER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)
        ok "Nvidia driver already installed: $DRIVER_VER"
    else
        warn "No working Nvidia driver detected"
        info "Installing recommended driver via ubuntu-drivers..."
        sudo apt-get install -y -qq ubuntu-drivers-common >/dev/null
        sudo ubuntu-drivers autoinstall
        echo
        warn "Driver installed — A REBOOT IS REQUIRED before continuing."
        warn "Reboot now, then re-run this script with the same arguments."
        exit 0
    fi
fi

# ====================================================================
# STAGE 3 — CUDA toolkit 12.8
# ====================================================================
if [[ "$SKIP_CUDA" == "false" ]]; then
    banner "3. CUDA toolkit ${CUDA_VERSION/-/.}"

    # Check existing nvcc version
    INSTALL_CUDA=true
    if command -v nvcc &>/dev/null; then
        NVCC_VER=$(nvcc --version 2>/dev/null | sed -n 's/.*release \([0-9]*\.[0-9]*\).*/\1/p' | head -1)
        if [[ -n "$NVCC_VER" ]]; then
            # Compare against 12.8 numerically
            if awk -v cur="$NVCC_VER" -v min="12.8" 'BEGIN { exit !(cur+0 >= min+0) }'; then
                ok "CUDA toolkit $NVCC_VER already installed (>= 12.8 — Blackwell-ready)"
                INSTALL_CUDA=false
            else
                warn "CUDA $NVCC_VER is too old for Blackwell (sm_120) — upgrading to 12.8"
            fi
        fi
    fi

    if [[ "$INSTALL_CUDA" == "true" ]]; then
        info "Adding NVIDIA CUDA apt repo (ubuntu2404)..."
        TMPDIR=$(mktemp -d)
        cd "$TMPDIR"
        wget -q https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
        sudo dpkg -i cuda-keyring_1.1-1_all.deb >/dev/null
        cd "$PROJECT_DIR"
        rm -rf "$TMPDIR"

        info "Updating apt with NVIDIA repo..."
        sudo apt-get update -qq

        info "Installing cuda-toolkit-${CUDA_VERSION}..."
        sudo apt-get install -y -qq "cuda-toolkit-${CUDA_VERSION}" >/dev/null
        ok "CUDA ${CUDA_VERSION/-/.} installed at /usr/local/cuda-${CUDA_VERSION/-/.}"

        # Add to PATH/LD_LIBRARY_PATH (idempotent — only add if not already present)
        BASHRC="$HOME/.bashrc"
        CUDA_PATH_LINE="export PATH=/usr/local/cuda-${CUDA_VERSION/-/.}/bin:\$PATH"
        CUDA_LD_LINE="export LD_LIBRARY_PATH=/usr/local/cuda-${CUDA_VERSION/-/.}/lib64:\${LD_LIBRARY_PATH:-}"
        if ! grep -qF "cuda-${CUDA_VERSION/-/.}/bin" "$BASHRC" 2>/dev/null; then
            echo "" >> "$BASHRC"
            echo "# CUDA toolkit (added by EyeStat install.sh)" >> "$BASHRC"
            echo "$CUDA_PATH_LINE" >> "$BASHRC"
            echo "$CUDA_LD_LINE" >> "$BASHRC"
            ok "Added CUDA paths to $BASHRC"
        fi
        # Set for current shell so the next steps see nvcc
        export PATH="/usr/local/cuda-${CUDA_VERSION/-/.}/bin:$PATH"
        export LD_LIBRARY_PATH="/usr/local/cuda-${CUDA_VERSION/-/.}/lib64:${LD_LIBRARY_PATH:-}"

        # Verify
        if command -v nvcc &>/dev/null; then
            NEW_VER=$(nvcc --version | sed -n 's/.*release \([0-9.]*\).*/\1/p' | head -1)
            ok "nvcc now reports: $NEW_VER"
        fi
    fi
fi

# ====================================================================
# STAGE 4 — Python virtual environment
# ====================================================================
banner "4. Python venv"

if [[ -d "$VENV_PATH" && -x "$VENV_PATH/bin/python3" ]]; then
    ok "venv already exists at $VENV_PATH"
else
    info "Creating venv at $VENV_PATH..."
    python3 -m venv "$VENV_PATH"
    ok "venv created"
fi

# Activate for the rest of this script
# shellcheck disable=SC1091
source "$VENV_PATH/bin/activate"
PYTHON_IN_VENV=$(which python3)
ok "venv active: $PYTHON_IN_VENV"

info "Upgrading pip..."
pip install --quiet --upgrade pip
ok "pip $(pip --version | awk '{print $2}')"

# ====================================================================
# STAGE 5 — Python packages
# ====================================================================
banner "5. Python packages (in venv)"

info "Installing numpy + scipy..."
pip install --quiet numpy scipy
ok "numpy $(python3 -c 'import numpy; print(numpy.__version__)'), scipy $(python3 -c 'import scipy; print(scipy.__version__)')"

if [[ "$SKIP_GPU" == "false" ]]; then
    info "Installing $CUPY_PACKAGE (Blackwell-compatible >=13.4)..."
    info "  This downloads ~500 MB of CUDA libraries — first install takes a few minutes."
    pip install --quiet "${CUPY_PACKAGE}>=13.4"

    # Verify CuPy can import and see the GPU
    if python3 -c "import cupy" 2>/dev/null; then
        CUPY_VER=$(python3 -c "import cupy; print(cupy.__version__)")
        ok "CuPy $CUPY_VER importable"
        if python3 -c "import cupy; cupy.cuda.runtime.getDeviceCount()" 2>/dev/null; then
            N_DEV=$(python3 -c "import cupy; print(cupy.cuda.runtime.getDeviceCount())")
            ok "CuPy sees $N_DEV CUDA device(s)"
        else
            warn "CuPy installed but can't see CUDA devices — check driver/runtime mismatch"
        fi
    else
        warn "CuPy installed but failed to import — check CUDA version compatibility"
    fi
fi

# ====================================================================
# STAGE 6 — Validation
# ====================================================================
if [[ "$SKIP_VALIDATE" == "false" ]]; then
    banner "6. Validation"

    cd "$PROJECT_DIR"

    # Selftest (CPU only — no GPU dependency)
    info "Running eyestat_selftest.py..."
    if python3 eyestat_selftest.py >/tmp/eyestat_selftest.log 2>&1; then
        if grep -q "8/8 phases passed" /tmp/eyestat_selftest.log; then
            ok "selftest: 8/8 phases passed"
        else
            warn "selftest ran but result unclear — see /tmp/eyestat_selftest.log"
        fi
    else
        warn "selftest failed — see /tmp/eyestat_selftest.log"
    fi

    # Preflight (validates data files, scoring, environment)
    info "Running eyestat_preflight.py..."
    if python3 eyestat_preflight.py --no-color --output-dir /tmp/eyestat_preflight_check \
            >/tmp/eyestat_preflight.log 2>&1; then
        if grep -q "ALL SYSTEMS GREEN" /tmp/eyestat_preflight.log; then
            ok "preflight: all checks green"
        elif grep -q "WARNINGS" /tmp/eyestat_preflight.log; then
            warn "preflight passed with warnings — see /tmp/eyestat_preflight.log"
        else
            warn "preflight ran but result unclear — see /tmp/eyestat_preflight.log"
        fi
        rm -rf /tmp/eyestat_preflight_check
    else
        warn "preflight failed — see /tmp/eyestat_preflight.log"
    fi

    # GPU probe (if GPU present)
    if [[ "$SKIP_GPU" == "false" ]]; then
        info "Running eyestat_gpu_probe.py (this may take a minute on first run due to JIT compile)..."
        echo
        python3 eyestat_gpu_probe.py --no-color 2>&1 || warn "gpu_probe had issues"
    fi
fi

# ====================================================================
# Final banner
# ====================================================================
echo
printf "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}${GREEN}║                       INSTALL COMPLETE                        ║${RESET}\n"
printf "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════╝${RESET}\n"
echo
printf "  To activate the venv in a new shell:\n"
printf "    ${CYAN}source $VENV_PATH/bin/activate${RESET}\n\n"
printf "  Project directory:\n"
printf "    ${CYAN}cd $PROJECT_DIR${RESET}\n\n"
printf "  Try a small run:\n"
printf "    ${CYAN}./run.sh${RESET}  ${DIM}# convenience wrapper${RESET}\n"
printf "    ${CYAN}python3 eyestat_runner.py --data noita_eye_data.json --seed-end 1000 \\\\${RESET}\n"
printf "    ${CYAN}    --modes ctak_right --prngs park_miller --workers 4${RESET}\n\n"
printf "  Then generate the HTML report:\n"
printf "    ${CYAN}python3 eyestat_html_report.py --input eyestat_results/bruteforce_results.txt${RESET}\n\n"
