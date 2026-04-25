#!/usr/bin/env bash
# =============================================================================
# 02_ssh_probe.sh — SSH connection probe
# =============================================================================
# Purpose:
#   Attempt SSH connections against the target to verify SSH service exposure.
#   If an actual brute-force tool (hydra) is available, run a demo attack.
#
# Learning points:
#   - Config A (Public): SSH(22) is exposed to the internet. Banner info is retrievable.
#     Attackers can search for known vulnerabilities using version information.
#   - Config B (Private): EC2 has no Public IP, so SSH connections cannot be established.
#     ALB does not relay SSH, so connections to port 22 are completely blocked.
#
# Note:
#   Only run brute-force attacks in lab environments you manage.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "02: SSH Connection Probe (SSH Probe)"

RESULT_FILE="02_ssh_probe.txt"
result_text=""

# ---------------------------------------------------------------------------
# Step 1: SSH banner retrieval
# ---------------------------------------------------------------------------
# Retrieve the banner string sent at the beginning of an SSH connection.
# Banners often contain OpenSSH version and OS information.
# Attackers use this info to identify known CVEs (vulnerabilities).
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 1: Attempting SSH banner retrieval...${NC}"
echo -e "${BLUE}[*] Checking if SSH version and OS info can be obtained from the banner${NC}"
echo ""

# Read banner via TCP connection with 5-second timeout
# Uses nc (netcat). Standard on macOS.
banner=""
if require_tool nc; then
    banner=$(echo "" | nc -w 5 "${ATTACK_TARGET}" 22 2>&1) || true
fi

if [[ -n "${banner}" && ! "${banner}" =~ "Connection refused" && ! "${banner}" =~ "timed out" && ! "${banner}" =~ "No route" ]]; then
    echo -e "${RED}  Received banner: ${banner}${NC}"
    result_text+="SSH banner retrieval: Success"$'\n'
    result_text+="Banner content: ${banner}"$'\n'

    # Extract version info from banner
    if echo "${banner}" | grep -qi "OpenSSH"; then
        ssh_version=$(echo "${banner}" | grep -oi "OpenSSH_[0-9.p]*" || echo "unknown")
        print_vulnerable "SSH banner retrievable — Version: ${ssh_version}"
        print_info "Attackers search CVE databases with this version info"
        result_text+="SSH version: ${ssh_version}"$'\n'
        result_text+="Verdict: VULNERABLE — Banner info exposed externally"$'\n'
    fi
else
    echo -e "  Banner retrieval: Failed (connection refused or timeout)"
    result_text+="SSH banner retrieval: Failed"$'\n'
    result_text+="Verdict: BLOCKED — SSH port unreachable"$'\n'
    print_blocked "SSH banner unretrievable — Port 22 is unreachable from outside"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: SSH authentication probe
# ---------------------------------------------------------------------------
# Attempt authentication with an intentionally wrong password.
# Check SSH service reachability by whether the connection is established.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 2: SSH authentication probe (connection attempt with invalid password)${NC}"
echo -e "${BLUE}[*] Checking if SSH service reaches the authentication phase${NC}"
echo ""

# Attempt connection with ssh command
# -o ConnectTimeout=5: Connection timeout 5 seconds
# -o StrictHostKeyChecking=no: Skip host key verification (lab environment only)
# -o BatchMode=yes: Don't prompt for password input
# -o PasswordAuthentication=yes: Attempt password authentication
ssh_probe_output=$(ssh \
    -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes \
    -o LogLevel=VERBOSE \
    "testuser@${ATTACK_TARGET}" \
    exit 2>&1) || true

echo "${ssh_probe_output}" | tail -20

result_text+=$'\n'"--- SSH authentication probe ---"$'\n'
result_text+="${ssh_probe_output}"$'\n'

if echo "${ssh_probe_output}" | grep -qi "Permission denied\|Authentication"; then
    # Reached authentication phase = SSH service is exposed externally
    print_vulnerable "Reached SSH authentication phase — Brute-force attack is possible"
    result_text+="Verdict: VULNERABLE — SSH authentication can be attempted from outside"$'\n'
elif echo "${ssh_probe_output}" | grep -qi "Connection refused\|timed out\|No route\|Could not resolve"; then
    print_blocked "SSH connection cannot be established — Blocked at network level"
    result_text+="Verdict: BLOCKED — SSH unreachable"$'\n'
else
    print_info "SSH connection result is unclear (check network status)"
    result_text+="Verdict: UNKNOWN"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: Brute-force demo with Hydra (optional)
# ---------------------------------------------------------------------------
# Only run when hydra is available and Config A (Public).
# Demo with a small number of username/password combinations.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 3: Brute-force attack demo (hydra, optional)${NC}"
echo ""

if require_tool hydra; then
    # Only attempt for Config A when SSH is reachable
    if [[ "${CONFIG_MODE}" == "public" ]] && echo "${banner}" | grep -qi "SSH"; then
        echo -e "${YELLOW}[*] Running a small SSH brute-force attempt with hydra (for educational purposes)${NC}"

        # Temporary user and password lists
        # Real attacks use large dictionaries like rockyou.txt, but demo uses minimal
        USERS_FILE=$(mktemp)
        PASS_FILE=$(mktemp)

        # Cleanup trap
        trap 'rm -f "${USERS_FILE}" "${PASS_FILE}"' EXIT

        # Commonly targeted default usernames
        cat > "${USERS_FILE}" <<'USERLIST'
root
admin
ec2-user
ubuntu
test
USERLIST

        # Commonly targeted weak passwords
        cat > "${PASS_FILE}" <<'PASSLIST'
password
123456
admin
root
changeme
PASSLIST

        # -t 2: 2 simultaneous connections (conservative)
        # -f: Stop after finding one
        # -V: Show attempts
        hydra_output=$(hydra -L "${USERS_FILE}" -P "${PASS_FILE}" \
            -t 2 -f -V \
            "ssh://${ATTACK_TARGET}" 2>&1) || true

        echo "${hydra_output}" | tail -15
        result_text+=$'\n'"--- Hydra brute-force ---"$'\n'
        result_text+="${hydra_output}"$'\n'

        if echo "${hydra_output}" | grep -qi "valid password"; then
            print_vulnerable "Credentials discovered via brute-force — Immediate password change required"
        else
            print_info "No credentials found with this dictionary (expected if key-only auth)"
            print_vulnerable "However, the fact that SSH is exposed externally is itself a risk"
        fi
    else
        echo -e "${GREEN}  SSH is not exposed externally, so brute-force is unnecessary${NC}"
        result_text+="Hydra: Skipped since SSH is unreachable"$'\n'
        print_blocked "Brute-force attack itself cannot succeed with this configuration"
    fi
else
    echo -e "${YELLOW}  hydra not found. Install: brew install hydra${NC}"
    result_text+="Hydra: Skipped since not installed"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "SSH probe complete"
