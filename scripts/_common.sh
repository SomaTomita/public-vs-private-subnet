#!/usr/bin/env bash
# =============================================================================
# _common.sh — Shared configuration and helper functions for all scripts
# =============================================================================
# Source this from other scripts. Do not execute directly.
# Reads Terraform output values and automatically determines attack targets
# and result directories.
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Color definitions
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Project paths
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TF_DIR="${PROJECT_ROOT}/terraform"
RESULTS_BASE="${PROJECT_ROOT}/results"

# -----------------------------------------------------------------------------
# Read Terraform output values
# Calls terraform output -json once and caches the result
# -----------------------------------------------------------------------------
_tf_cache=""

tf_output() {
    # Argument: output name
    # Returns: output value (string / empty string if null)
    local key="$1"

    if [[ -z "${_tf_cache}" ]]; then
        if ! _tf_cache=$(cd "${TF_DIR}" && terraform output -json 2>/dev/null); then
            echo ""
            return 1
        fi
    fi

    local val
    val=$(echo "${_tf_cache}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
v = data.get('${key}', {}).get('value')
print('' if v is None else v)
" 2>/dev/null || echo "")
    echo "${val}"
}

# -----------------------------------------------------------------------------
# Initialize configuration
# Determines attack target and result directory from terraform output
# -----------------------------------------------------------------------------
init_config() {
    echo -e "${BLUE}[*] Reading Terraform output values...${NC}"

    CONFIG_MODE=$(tf_output "config_mode")
    ATTACK_TARGET=$(tf_output "attack_target")
    APP_PUBLIC_IP=$(tf_output "app_public_ip")
    APP_PRIVATE_IP=$(tf_output "app_private_ip")
    SSH_KEY_FILE=$(tf_output "ssh_key_file")
    RDS_ENDPOINT=$(tf_output "rds_endpoint")
    ALB_DNS_NAME=$(tf_output "alb_dns_name")

    # Abort if config_mode cannot be retrieved
    if [[ -z "${CONFIG_MODE}" ]]; then
        echo -e "${RED}[!] Cannot retrieve config_mode. Please verify that terraform apply has been run.${NC}"
        exit 1
    fi

    # Abort if attack_target is empty
    if [[ -z "${ATTACK_TARGET}" ]]; then
        echo -e "${RED}[!] Cannot retrieve attack_target.${NC}"
        exit 1
    fi

    # Result directory
    if [[ "${CONFIG_MODE}" == "public" ]]; then
        RESULTS_DIR="${RESULTS_BASE}/configA"
        CONFIG_LABEL="Config A (Public: EC2 directly exposed)"
    else
        RESULTS_DIR="${RESULTS_BASE}/configB"
        CONFIG_LABEL="Config B (Private: via ALB)"
    fi

    mkdir -p "${RESULTS_DIR}"

    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Config:       ${CONFIG_LABEL}${NC}"
    echo -e "${BOLD}  Target:       ${ATTACK_TARGET}${NC}"
    echo -e "${BOLD}  Results dir:  ${RESULTS_DIR}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------

# Check if a tool exists. If not, print a warning and return skip code
require_tool() {
    local tool="$1"
    if ! command -v "${tool}" &>/dev/null; then
        echo -e "${YELLOW}[SKIP] ${tool} is not installed. Skipping this test.${NC}"
        return 1
    fi
    return 0
}

# Run a command with a timeout across Linux/macOS environments.
run_with_timeout() {
    local seconds="$1"
    shift

    if command -v timeout &>/dev/null; then
        timeout "${seconds}" "$@"
        return $?
    fi

    if command -v gtimeout &>/dev/null; then
        gtimeout "${seconds}" "$@"
        return $?
    fi

    python3 - "$seconds" "$@" <<'PY'
import os
import signal
import subprocess
import sys

timeout_seconds = int(sys.argv[1])
command = sys.argv[2:]
proc = subprocess.Popen(command)

def handle_timeout(signum, frame):
    proc.kill()
    raise SystemExit(124)

signal.signal(signal.SIGALRM, handle_timeout)
signal.alarm(timeout_seconds)

try:
    proc.wait()
finally:
    signal.alarm(0)

raise SystemExit(proc.returncode)
PY
}

# Write to result file + display on stdout
save_result() {
    local filename="$1"
    local content="$2"
    local filepath="${RESULTS_DIR}/${filename}"
    echo "${content}" > "${filepath}"
    echo -e "${BLUE}[*] Result saved: ${filepath}${NC}"
}

# Vulnerable indicator (red = dangerous)
print_vulnerable() {
    local msg="$1"
    echo -e "${RED}[VULNERABLE] ${msg}${NC}"
}

# Blocked indicator (green = safe)
print_blocked() {
    local msg="$1"
    echo -e "${GREEN}[BLOCKED] ${msg}${NC}"
}

# Info display
print_info() {
    local msg="$1"
    echo -e "${BLUE}[INFO] ${msg}${NC}"
}

# Section header
print_header() {
    local title="$1"
    echo ""
    echo -e "${BOLD}${CYAN}========================================${NC}"
    echo -e "${BOLD}${CYAN}  ${title}${NC}"
    echo -e "${BOLD}${CYAN}========================================${NC}"
    echo ""
}

# Timestamped log
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Separate hostname and port from RDS endpoint
# RDS endpoint format: "hostname:port"
parse_rds_host() {
    echo "${RDS_ENDPOINT}" | cut -d: -f1
}

parse_rds_port() {
    echo "${RDS_ENDPOINT}" | cut -d: -f2
}
