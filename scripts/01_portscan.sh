#!/usr/bin/env bash
# =============================================================================
# 01_portscan.sh — Port scan attack
# =============================================================================
# Purpose:
#   Execute a port scan against the target and enumerate externally reachable services.
#
# Learning points:
#   - Config A (Public): EC2 is directly exposed to the internet. SSH(22), HTTP(80), etc. are visible
#   - Config B (Private): Only ALB is exposed. This lab deploys an HTTP(80) listener only
#     EC2's IP is unreachable from outside
#
# Tools used:
#   - nmap (recommended) — Detailed port scanning
#   - Fallback: Simple scan using bash /dev/tcp (works on stock macOS)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "01: Port Scan"

echo -e "${BLUE}[*] Target: ${ATTACK_TARGET}${NC}"
echo -e "${BLUE}[*] The first thing an attacker does is reconnaissance of which ports are open${NC}"
echo ""

# List of ports to scan
# Comprehensive check of common service ports
PORTS=(21 22 25 53 80 443 445 1433 3389 5432 6379 8080 8443 9200 27017)
RESULT_FILE="01_portscan.txt"

# ---------------------------------------------------------------------------
# If nmap is available: Full scan
# ---------------------------------------------------------------------------
if require_tool nmap; then
    echo -e "${BLUE}[*] Running scan with nmap (may take several tens of seconds)...${NC}"
    echo ""

    # -Pn: Skip host discovery (ICMP may be blocked on AWS)
    # -sT: TCP connect scan (alternative to SYN scan that doesn't require root)
    # --top-ports 100: Scan top 100 commonly used ports
    # -T3: Normal speed (not overly aggressive timing)
    # --open: Show only open ports
    nmap_output=$(nmap -Pn -sT --top-ports 100 -T3 --open "${ATTACK_TARGET}" 2>&1) || true

    echo "${nmap_output}"
    save_result "${RESULT_FILE}" "${nmap_output}"

    # Evaluate results
    open_count=$(echo "${nmap_output}" | grep -c "^[0-9].*open" || true)

    echo ""
    echo -e "${BOLD}--- Verdict ---${NC}"

    if [[ "${CONFIG_MODE}" == "public" ]]; then
        # Config A: SSH(22) and HTTP(80) should be open
        if echo "${nmap_output}" | grep -q "22/tcp.*open"; then
            print_vulnerable "SSH(22) is reachable from outside — Target for brute-force attacks"
        fi
        if echo "${nmap_output}" | grep -q "80/tcp.*open"; then
            print_vulnerable "HTTP(80) is directly reachable to EC2 from outside"
        fi
        if [[ ${open_count} -gt 2 ]]; then
            print_vulnerable "More ports open than expected (${open_count})"
        fi
    else
        # Config B: Only ALB's HTTP listener should be open
        if echo "${nmap_output}" | grep -q "22/tcp.*open"; then
            print_vulnerable "SSH(22) is visible from outside — This is abnormal for ALB configuration"
        else
            print_blocked "SSH(22) is unreachable from outside"
        fi
        if echo "${nmap_output}" | grep -q "80/tcp.*open"; then
            print_info "HTTP(80) is responded by ALB (as expected)"
        fi
        if echo "${nmap_output}" | grep -q "5432/tcp.*open"; then
            print_vulnerable "PostgreSQL(5432) is visible from outside — Critical misconfiguration"
        else
            print_blocked "PostgreSQL(5432) is unreachable from outside"
        fi
    fi

else
    # ---------------------------------------------------------------------------
    # If nmap is not available: Simple scan using bash /dev/tcp
    # ---------------------------------------------------------------------------
    echo -e "${YELLOW}[*] nmap not found. Running simple scan with bash /dev/tcp${NC}"
    echo ""

    scan_output=""

    for port in "${PORTS[@]}"; do
        # Attempt connection with 3-second timeout
        # /dev/tcp is a bash built-in. Success=port open, failure=closed or filtered
        if run_with_timeout 3 bash -c "echo >/dev/tcp/${ATTACK_TARGET}/${port}" 2>/dev/null; then
            line="${port}/tcp  open"
            echo -e "${RED}  ${line}${NC}"
            scan_output+="${line}"$'\n'
        else
            line="${port}/tcp  closed/filtered"
            echo -e "  ${line}"
            scan_output+="${line}"$'\n'
        fi
    done

    save_result "${RESULT_FILE}" "${scan_output}"

    echo ""
    echo -e "${BOLD}--- Verdict ---${NC}"

    if echo "${scan_output}" | grep -q "^22/tcp.*open"; then
        if [[ "${CONFIG_MODE}" == "public" ]]; then
            print_vulnerable "SSH(22) is reachable from outside"
        else
            print_vulnerable "SSH(22) is visible from outside — This is abnormal for ALB configuration"
        fi
    else
        print_blocked "SSH(22) is unreachable from outside"
    fi

    if echo "${scan_output}" | grep -q "^5432/tcp.*open"; then
        print_vulnerable "PostgreSQL(5432) is reachable from outside — Critical misconfiguration"
    else
        print_blocked "PostgreSQL(5432) is unreachable from outside"
    fi

    if echo "${scan_output}" | grep -q "^80/tcp.*open"; then
        if [[ "${CONFIG_MODE}" == "public" ]]; then
            print_vulnerable "HTTP(80) is directly reachable to EC2"
        else
            print_info "HTTP(80) is responded by ALB (as expected)"
        fi
    fi
fi

echo ""
log "Port scan complete"
