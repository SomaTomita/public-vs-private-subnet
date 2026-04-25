#!/usr/bin/env bash
# =============================================================================
# 05_db_probe.sh — Direct database connection probe
# =============================================================================
# Purpose:
#   Verify if RDS (PostgreSQL) can be directly connected from outside (attacker machine).
#   Verify that the database is not exposed to the internet.
#
# Learning points:
#   - RDS is configured with publicly_accessible = false
#   - RDS is placed in a private subnet for both Config A/B
#   - DB SG only allows 5432 from App SG
#   - Direct connections from outside should be impossible
#   - However, there is a possibility of connecting to DB from EC2 via SSRF (indirect attack)
#
# Test contents:
#   1. DNS resolution of RDS endpoint
#   2. Direct TCP connection from outside (port 5432)
#   3. Connection attempt with psql client
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "05: Direct Database Connection Probe (DB Probe)"

RESULT_FILE="05_db_probe.txt"
result_text=""

# Parse RDS endpoint (hostname:port format)
RDS_HOST=$(parse_rds_host)
RDS_PORT=$(parse_rds_port)

echo -e "${BLUE}[*] RDS Endpoint: ${RDS_ENDPOINT}${NC}"
echo -e "${BLUE}[*] Host: ${RDS_HOST}${NC}"
echo -e "${BLUE}[*] Port: ${RDS_PORT}${NC}"
echo ""

result_text+="RDS Endpoint: ${RDS_ENDPOINT}"$'\n'
result_text+="Host: ${RDS_HOST}"$'\n'
result_text+="Port: ${RDS_PORT}"$'\n'$'\n'

# ---------------------------------------------------------------------------
# Step 1: DNS Resolution
# ---------------------------------------------------------------------------
# Check which IP the RDS endpoint DNS name resolves to.
# If it resolves to a private IP, it cannot be directly routed from outside.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 1: DNS Resolution Test${NC}"
echo -e "${BLUE}[*] Checking which IP address the RDS endpoint resolves to${NC}"
echo ""

dns_result=""
if require_tool nslookup; then
    dns_result=$(nslookup "${RDS_HOST}" 2>&1) || true
    echo "${dns_result}"
    result_text+="--- DNS Resolution ---"$'\n'
    result_text+="${dns_result}"$'\n'$'\n'

    # Resolved IP is in private IP range(10.x, 172.16-31.x, 192.168.x)check
    resolved_ip=$(echo "${dns_result}" | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -1)
    if [[ -z "${resolved_ip}" ]]; then
        resolved_ip=$(echo "${dns_result}" | grep "^Address:" | tail -1 | awk '{print $2}')
    fi

    if [[ -n "${resolved_ip}" ]]; then
        echo -e "  Resolved IP: ${resolved_ip}"
        result_text+="Resolved IP: ${resolved_ip}"$'\n'

        if echo "${resolved_ip}" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
            print_info "RDS resolves to private IP — Not routable from internet"
            result_text+="Verdict: Resolves to private IP (as expected)"$'\n'
        else
            print_vulnerable "RDS resolves to public IP — Possibly publicly_accessible=true"
            result_text+="Verdict: VULNERABLE — Resolves to public IP"$'\n'
        fi
    else
        echo -e "  DNS resolution: Failed (check network settings)"
        result_text+="DNS resolution: Failed"$'\n'
    fi
elif require_tool dig; then
    dns_result=$(dig +short "${RDS_HOST}" 2>&1) || true
    echo "  dig result: ${dns_result}"
    result_text+="--- DNS Resolution (dig) ---"$'\n'
    result_text+="${dns_result}"$'\n'$'\n'
elif require_tool host; then
    dns_result=$(host "${RDS_HOST}" 2>&1) || true
    echo "  host result: ${dns_result}"
    result_text+="--- DNS Resolution (host) ---"$'\n'
    result_text+="${dns_result}"$'\n'$'\n'
else
    echo -e "${YELLOW}  No DNS resolution tools found(nslookup/dig/host)${NC}"
    result_text+="DNS resolution: No tools"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: TCP Connection Test (port 5432)
# ---------------------------------------------------------------------------
# Check if PostgreSQL(5432) port is directly TCP-accessible from outside.
# Connection should timeout or be refused.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 2: TCP connection test (port ${RDS_PORT})${NC}"
echo -e "${BLUE}[*] Checking if RDS PostgreSQL port is directly reachable from outside${NC}"
echo ""

result_text+="--- TCP Connection Test ---"$'\n'

# Connection test with nc (netcat). Standard on macOS.
# -z: Scan mode (don't send data)
# -w 5: Timeout 5 seconds
# -G 5: TCP connection timeout 5sec(macOS nc-specific option)
echo -e "  nc -z -w 5 ${RDS_HOST} ${RDS_PORT} Running..."

if [[ "$(uname)" == "Darwin" ]]; then
    nc_cmd=(nc -z -w 5 -G 5 "${RDS_HOST}" "${RDS_PORT}")
else
    nc_cmd=(run_with_timeout 5 nc -z -w 5 "${RDS_HOST}" "${RDS_PORT}")
fi

if "${nc_cmd[@]}" 2>&1; then
    print_vulnerable "External TCP connection to RDS succeeded — Database is exposed"
    result_text+="TCP connection: Success — VULNERABLE"$'\n'
else
    print_blocked "External TCP connection to RDS failed — As expected"
    result_text+="TCP connection: Failed (blocked) — BLOCKED"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: PostgreSQL client connection attempt (optional)
# ---------------------------------------------------------------------------
# If psql command is available, attempt an actual PostgreSQL connection.
# The connection should not succeed.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 3: PostgreSQL client connection attempt (optional)${NC}"
echo ""

result_text+=$'\n'"--- PostgreSQL Connection Test ---"$'\n'

if require_tool psql; then
    echo -e "${BLUE}[*] Attempting connection with psql client...${NC}"

    # Attempting connection with default credentials
    # -c "SELECT 1": Execute test query after connection
    # connect_timeout=5: Connection timeout
    psql_output=$(PGPASSWORD="wrongpassword" psql \
        -h "${RDS_HOST}" \
        -p "${RDS_PORT}" \
        -U admin \
        -d postgres \
        -w \
        -c "SELECT 1" 2>&1) || true

    echo "${psql_output}"
    result_text+="${psql_output}"$'\n'

    if echo "${psql_output}" | grep -qi "password authentication failed\|no pg_hba.conf entry"; then
        # Connection itself succeeded (rejected at auth) — Port is exposed
        print_vulnerable "PostgreSQL connection established at TCP level — Rejected at auth, but port is exposed"
        result_text+="Verdict: VULNERABLE — Reachable at TCP level"$'\n'
    elif echo "${psql_output}" | grep -qi "could not connect\|Connection refused\|timed out\|timeout expired"; then
        # Connection itself failed — Port is blocked
        print_blocked "PostgreSQL connection rejected at network level — As expected"
        result_text+="Verdict: BLOCKED — Unreachable at network level"$'\n'
    elif echo "${psql_output}" | grep -qi "FATAL.*password"; then
        # Password authentication failed — Connection was established
        print_vulnerable "Reached PostgreSQL auth phase — Target for brute-force attacks"
        result_text+="Verdict: VULNERABLE — Reached auth phase"$'\n'
    else
        print_info "PostgreSQL connection result is unclear"
        result_text+="Verdict: UNKNOWN"$'\n'
    fi
else
    echo -e "${YELLOW}  psql client not found. Install: brew install postgresql${NC}"
    result_text+="PostgreSQL connection test: No tools"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 4: DB connection possibility via SSRF (warning)
# ---------------------------------------------------------------------------
# Even if direct connections are blocked, DB connection from EC2 via SSRF is possible.
# Record this as a warning.
# ---------------------------------------------------------------------------
echo -e "${BOLD}--- Indirect attack considerations ---${NC}"
echo ""

echo -e "${YELLOW}  [!] Even when direct external connections are blocked, the following attack paths remain:${NC}"
echo -e "      1. SSRF vulnerability -> EC2 has IAM role/credentials for DB connection"
echo -e "      2. Steal EC2's IAM credentials -> Access via RDS Proxy or alternative paths"
echo -e "      3. User data may contain DB connection strings"
echo ""
echo -e "${BLUE}  Mitigation: Manage DB credentials in Secrets Manager, not hardcoded in EC2 env vars${NC}"

result_text+=$'\n'"--- Indirect attack considerations ---"$'\n'
result_text+="Even when direct external connections are blocked, indirect attacks via SSRF are possible"$'\n'
result_text+="Mitigation: Secrets Manager + IAM auth + Principle of Least Privilege"$'\n'

echo ""

# ---------------------------------------------------------------------------
# Result Summary
# ---------------------------------------------------------------------------
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  DB Probe Summary (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "  Config A: RDS is protected with publicly_accessible=false"
    echo -e "  However, EC2 can connect to RDS via SG (required by app design)"
    echo -e "  If SSRF attack succeeds, DB access via EC2 becomes possible"
else
    echo -e "  Config B: RDS is similarly protected with publicly_accessible=false"
    echo -e "  ALB only forwards HTTP in this lab, and does not forward port 5432"
    echo -e "  Network layer isolation is more robust in Config B"
fi

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "DB probe complete"
