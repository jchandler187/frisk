#!/usr/bin/env bash
# ClawSec v2 Dependency Setup
# Installs all required tools for intel-sync and skill-verify on Ubuntu 24.04
set -euo pipefail

VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/lib/common/config.sh"
INTEL_DIR="${CLAWSEC_INTEL_DIR}"
CLAWSEC_USER="$(whoami)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${RESET} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
log_err()   { echo -e "${RED}[ERR ]${RESET} $*"; }

banner() {
    echo -e "${BOLD}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║     ClawSec v${VERSION} Setup               ║"
    echo "  ║     Security Verification for Skills  ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${RESET}"
}

check_cmd() {
    if command -v "$1" &>/dev/null; then
        log_ok "$1 already installed: $(command -v "$1")"
        return 0
    else
        return 1
    fi
}

install_system_deps() {
    log_info "Installing system dependencies..."
    local needed=()
    for pkg in curl wget git jq python3 python3-pip python3-venv libyara-dev yara; do
        if ! dpkg -l "$pkg" &>/dev/null 2>&1; then
            needed+=("$pkg")
        fi
    done

    if [[ ${#needed[@]} -gt 0 ]]; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq "${needed[@]}"
        log_ok "System packages installed: ${needed[*]}"
    else
        log_ok "All system packages already installed"
    fi
}

install_semgrep() {
    if check_cmd semgrep; then return 0; fi
    log_info "Installing Semgrep..."
    pip3 install --user semgrep 2>/dev/null || pip install --user semgrep 2>/dev/null
    export PATH="$HOME/.local/bin:$PATH"
    if check_cmd semgrep; then
        log_ok "Semgrep installed"
    else
        log_warn "Semgrep pip install failed, trying direct binary..."
        curl -fsSL https://raw.githubusercontent.com/returntocorp/semgrep/main/install.sh | bash
        log_ok "Semgrep installed via script"
    fi
}

install_gitleaks() {
    if check_cmd gitleaks; then return 0; fi
    log_info "Installing Gitleaks..."
    local arch="$(uname -m)"
    local gitleaks_arch="x64"
    [[ "$arch" == "aarch64" ]] && gitleaks_arch="arm64"

    local latest
    latest=$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.tag_name')
    local url="https://github.com/gitleaks/gitleaks/releases/download/${latest}/gitleaks_${latest:1}_linux_${gitleaks_arch}.tar.gz"

    local tmpdir
    tmpdir=$(mktemp -d)
    curl -fsSL "$url" | tar -xz -C "$tmpdir"
    mv "$tmpdir/gitleaks" "$HOME/.local/bin/gitleaks"
    chmod +x "$HOME/.local/bin/gitleaks"
    rm -rf "$tmpdir"
    log_ok "Gitleaks ${latest} installed"
}

install_yara_python() {
    log_info "Checking yara-python..."
    if python3 -c "import yara" 2>/dev/null; then
        log_ok "yara-python already available"
        return 0
    fi
    pip3 install --user yara-python 2>/dev/null || pip install --user yara-python 2>/dev/null
    if python3 -c "import yara" 2>/dev/null; then
        log_ok "yara-python installed"
    else
        log_warn "yara-python install failed — YARA scans may not work"
    fi
}

setup_dirs() {
    log_info "Setting up directory structure..."
    sudo mkdir -p "${INTEL_DIR}"/{cisa-kev,osv,epss,malwarebazaar,urlhaus,threatfox,feodo,yara-rules,semgrep-rules}
    sudo chown -R "${CLAWSEC_USER}:${CLAWSEC_USER}" "${INTEL_DIR}"
    log_ok "Directory structure ready at ${INTEL_DIR}"
}

clone_rule_repos() {
    log_info "Cloning/pulling rule repos..."

    # YARA rules - Neo23x0/signature-base
    local yara_dir="${INTEL_DIR}/yara-rules/repo"
    if [[ -d "$yara_dir/.git" ]]; then
        git -C "$yara_dir" pull --quiet 2>/dev/null && log_ok "YARA rules updated" || log_warn "YARA rules pull failed"
    else
        rm -rf "$yara_dir"
        git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$yara_dir" 2>/dev/null && log_ok "YARA rules cloned" || log_warn "YARA rules clone failed"
    fi

    # Semgrep rules
    local semgrep_dir="${INTEL_DIR}/semgrep-rules/repo"
    if [[ -d "$semgrep_dir/.git" ]]; then
        git -C "$semgrep_dir" pull --quiet 2>/dev/null && log_ok "Semgrep rules updated" || log_warn "Semgrep rules pull failed"
    else
        rm -rf "$semgrep_dir"
        git clone --depth 1 https://github.com/returntocorp/semgrep-rules.git "$semgrep_dir" 2>/dev/null && log_ok "Semgrep rules cloned" || log_warn "Semgrep rules clone failed"
    fi
}

setup_python_env() {
    log_info "Setting up Python virtual environment..."
    local venv_dir="${CLAWSEC_HOME}/.venv"
    if [[ ! -d "$venv_dir" ]]; then
        python3 -m venv "$venv_dir"
    fi
    source "$venv_dir/bin/activate"
    pip install --quiet --upgrade pip
    if [[ -f "${CLAWSEC_HOME}/requirements.txt" ]]; then
        pip install --quiet -r "${CLAWSEC_HOME}/requirements.txt"
    fi
    deactivate
    log_ok "Python venv ready at $venv_dir"
}

verify_install() {
    echo ""
    log_info "Verifying installations..."
    echo ""
    local all_ok=true

    for cmd in python3 jq curl git; do
        if check_cmd "$cmd"; then :; else
            log_err "$cmd NOT found"
            all_ok=false
        fi
    done

    for cmd in semgrep gitleaks yara; do
        if check_cmd "$cmd"; then :; else
            log_warn "$cmd NOT found — some checks will be unavailable"
        fi
    done

    echo ""
    if $all_ok; then
        log_ok "Core dependencies verified"
    else
        log_err "Some core dependencies missing — review above"
    fi
}

main() {
    banner

    export PATH="$HOME/.local/bin:$PATH"

    install_system_deps
    install_semgrep
    install_gitleaks
    install_yara_python
    setup_dirs
    clone_rule_repos
    setup_python_env
    verify_install

    echo ""
    log_ok "Setup complete. Run: clawsec sync    (to populate intel cache)"
    log_ok "                clawsec scan <path> (to verify a skill)"
}

main "$@"