#!/usr/bin/env bash
# =============================================================================
# flow_logs_analyzer.sh — VPC Flow Logs analysis and visualization script
# =============================================================================
# Purpose:
#   Query VPC Flow Logs after attack execution and display network flows
#   in human-readable format. Generate ACCEPT/REJECT stats, port analysis,
#   and ASCII flow diagrams.
#
# Prerequisites:
#   - AWS CLI configured (aws configure)
#   - VPC Flow Logs are sent to CloudWatch Logs
#   - terraform apply completed
#
# Usage:
#   ./flow_logs_analyzer.sh                    # Analyze all flows from last 15 minutes
#   ./flow_logs_analyzer.sh --minutes 30       # Last 30 minutes
#   ./flow_logs_analyzer.sh --compare          # Compare Config A/B results
#   ./flow_logs_analyzer.sh --src-ip 1.2.3.4   # Filter by specific source IP
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

# =============================================================================
# Default settings
# =============================================================================
LOOKBACK_MINUTES=15
COMPARE_MODE=false
FILTER_SRC_IP=""
FILTER_DST_IP=""
FILTER_PORT=""
OUTPUT_DIR=""
AWS_REGION=""

# CloudWatch Logs group name (matches Terraform definition)
PROJECT_NAME=""
LOG_GROUP=""

# =============================================================================
# Parse arguments
# =============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --minutes)
                LOOKBACK_MINUTES="$2"
                shift 2
                ;;
            --compare)
                COMPARE_MODE=true
                shift
                ;;
            --src-ip)
                FILTER_SRC_IP="$2"
                shift 2
                ;;
            --dst-ip)
                FILTER_DST_IP="$2"
                shift 2
                ;;
            --port)
                FILTER_PORT="$2"
                shift 2
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Unknown argument: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
}

show_usage() {
    cat <<'USAGE'
Usage:
  ./flow_logs_analyzer.sh [Options]

Options:
  --minutes N       Analysis time range in minutes. Default: 15
  --compare         Compare saved Config A/B flow log results
  --src-ip IP       Filter by source IP
  --dst-ip IP       Filter by destination IP
  --port PORT       Filter by port number
  -h, --help        Show this help
USAGE
}

# =============================================================================
# Initialization
# =============================================================================
initialize() {
    init_config

    PROJECT_NAME=$(tf_output "project_name" 2>/dev/null || echo "sec-lab")
    if [[ -z "${PROJECT_NAME}" ]]; then
        PROJECT_NAME="sec-lab"
    fi
    LOG_GROUP="/vpc/${PROJECT_NAME}/flow-logs"

    # Retrieve additional info from Terraform output
    NAT_GW_EIP=$(tf_output "nat_gw_eip" 2>/dev/null || echo "")

    OUTPUT_DIR="${RESULTS_DIR}/flow-logs"
    mkdir -p "${OUTPUT_DIR}"

    # Retrieve AWS region
    AWS_REGION=$(tf_output "aws_region" 2>/dev/null || echo "ap-northeast-1")
    if [[ -z "${AWS_REGION}" ]]; then
        AWS_REGION="ap-northeast-1"
    fi

    echo -e "${BLUE}[*] CloudWatch Logs group: ${LOG_GROUP}${NC}"
    echo -e "${BLUE}[*] Analysis target: Last ${LOOKBACK_MINUTES} minutes${NC}"
    echo ""
}

# =============================================================================
# Spinner display (waiting for Flow Logs delay)
# =============================================================================
spinner() {
    local pid=$1
    local msg="${2:-Waiting...}"
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        local c="${chars:i%${#chars}:1}"
        printf "\r${YELLOW}  %s %s${NC}" "$c" "$msg"
        sleep 0.1
        ((i++))
    done
    printf "\r%*s\r" $((${#msg} + 6)) ""
}

# =============================================================================
# CloudWatch Logs Insights query execution
# =============================================================================
run_insights_query() {
    local query="$1"
    local description="$2"
    local start_time end_time query_id status results

    # Calculate time range in epoch seconds
    end_time=$(date +%s)
    start_time=$((end_time - LOOKBACK_MINUTES * 60))

    echo -e "${BLUE}[*] Executing query: ${description}${NC}"

    # Start query
    query_id=$(aws logs start-query \
        --log-group-name "${LOG_GROUP}" \
        --start-time "${start_time}" \
        --end-time "${end_time}" \
        --query-string "${query}" \
        --region "${AWS_REGION}" \
        --output text \
        --query 'queryId' 2>/dev/null) || {
        echo -e "${RED}[!] Failed to start query. Verify that Flow Logs are enabled.${NC}"
        return 1
    }

    # Wait for query completion (max 60 seconds)
    local wait_count=0
    local max_wait=60
    while [[ ${wait_count} -lt ${max_wait} ]]; do
        status=$(aws logs get-query-results \
            --query-id "${query_id}" \
            --region "${AWS_REGION}" \
            --query 'status' \
            --output text 2>/dev/null)

        if [[ "${status}" == "Complete" ]]; then
            break
        elif [[ "${status}" == "Failed" || "${status}" == "Cancelled" ]]; then
            echo -e "${RED}[!] Query failed: status=${status}${NC}"
            return 1
        fi

        printf "\r  ${YELLOW}⏳ Executing query... (%dsec)${NC}" "${wait_count}"
        sleep 1
        ((wait_count++))
    done
    printf "\r%60s\r" ""

    if [[ ${wait_count} -ge ${max_wait} ]]; then
        echo -e "${RED}[!] Query timed out (${max_wait}sec)${NC}"
        return 1
    fi

    # Retrieve results (JSON format)
    aws logs get-query-results \
        --query-id "${query_id}" \
        --region "${AWS_REGION}" \
        --output json 2>/dev/null

    return 0
}

# =============================================================================
# 1. ACCEPT vs REJECT Traffic Overview
# =============================================================================
analyze_accept_reject() {
    print_header "1. ACCEPT / REJECT Traffic Overview"

    local query
    query='stats count(*) as total by action
| sort action asc'

    local result
    result=$(run_insights_query "${query}" "ACCEPT/REJECT aggregation") || return 1

    # Parse results and display in table format
    echo ""
    echo -e "${BOLD}  Action    Count${NC}"
    echo "  ─────────────────────────"

    echo "${result}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('results', [])
for row in results:
    fields = {f['field']: f['value'] for f in row}
    action = fields.get('action', '?')
    total = fields.get('total', '0')
    marker = '\033[0;32m✓\033[0m' if action == 'ACCEPT' else '\033[0;31m✗\033[0m'
    print(f'  {marker} {action:<12} {total:>8}')
" 2>/dev/null || echo -e "${YELLOW}  (No data)${NC}"

    echo ""

    # Save results to file
    echo "${result}" > "${OUTPUT_DIR}/accept_reject_summary.json"
}

# =============================================================================
# 2. Traffic by Source IP (Top 10)
# =============================================================================
analyze_top_sources() {
    print_header "2. Traffic by Source IP (Top 10)"

    local query
    query='stats count(*) as total, sum(packets) as pkts, sum(bytes) as byts by srcAddr
| sort total desc
| limit 10'

    local result
    result=$(run_insights_query "${query}" "Source IP aggregation") || return 1

    echo ""
    printf "  ${BOLD}%-18s %8s %10s %12s${NC}\n" "Source IP" "Count" "Packets" "Bytes"
    echo "  ───────────────────────────────────────────────────"

    echo "${result}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('results', [])
for row in results:
    fields = {f['field']: f['value'] for f in row}
    src = fields.get('srcAddr', '?')
    total = fields.get('total', '0')
    pkts = fields.get('pkts', '0')
    byts = fields.get('byts', '0')
    # Color-code internal vs external IPs
    if src.startswith('10.0.'):
        color = '\033[0;36m'  # cyan = internal
    else:
        color = '\033[0;33m'  # yellow = external
    end = '\033[0m'
    print(f'  {color}{src:<18}{end} {total:>8} {pkts:>10} {byts:>12}')
" 2>/dev/null || echo -e "${YELLOW}  (No data)${NC}"

    echo ""
    echo -e "${CYAN}  Legend: ${CYAN}Cyan=Internal IP (10.0.x.x)${NC}, ${YELLOW}Yellow=External IP${NC}"

    echo "${result}" > "${OUTPUT_DIR}/top_sources.json"
}

# =============================================================================
# 3. Traffic Analysis by Port
# =============================================================================
analyze_by_port() {
    print_header "3. Traffic Analysis by Port"

    local query
    query='stats count(*) as total by dstPort, protocol, action
| sort total desc
| limit 20'

    local result
    result=$(run_insights_query "${query}" "Port aggregation") || return 1

    echo ""
    printf "  ${BOLD}%-8s %-10s %-10s %8s  %-20s${NC}\n" "Port" "Protocol" "Action" "Count" "Service"
    echo "  ───────────────────────────────────────────────────────────"

    echo "${result}" | python3 -c "
import json, sys

# Well-known port mappings
PORT_NAMES = {
    '22': 'SSH',
    '80': 'HTTP',
    '443': 'HTTPS',
    '5432': 'PostgreSQL',
    '8080': 'HTTP-Alt',
    '8443': 'HTTPS-Alt',
    '53': 'DNS',
    '123': 'NTP',
    '3389': 'RDP',
    '6379': 'Redis',
    '27017': 'MongoDB',
    '445': 'SMB',
    '139': 'NetBIOS',
    '25': 'SMTP',
}

PROTO_NAMES = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}

data = json.load(sys.stdin)
results = data.get('results', [])
for row in results:
    fields = {f['field']: f['value'] for f in row}
    port = fields.get('dstPort', '?')
    proto = fields.get('protocol', '?')
    action = fields.get('action', '?')
    total = fields.get('total', '0')

    proto_name = PROTO_NAMES.get(proto, f'proto:{proto}')
    svc_name = PORT_NAMES.get(port, '')

    if action == 'ACCEPT':
        color = '\033[0;32m'
    else:
        color = '\033[0;31m'
    end = '\033[0m'

    print(f'  {color}{port:<8} {proto_name:<10} {action:<10} {total:>8}{end}  {svc_name}')
" 2>/dev/null || echo -e "${YELLOW}  (No data)${NC}"

    echo "${result}" > "${OUTPUT_DIR}/port_analysis.json"
}

# =============================================================================
# 4. Time-series display of flows from specific IPs
# =============================================================================
analyze_filtered_flows() {
    local filter_clause=""

    if [[ -n "${FILTER_SRC_IP}" ]]; then
        filter_clause="${filter_clause} | filter srcAddr = '${FILTER_SRC_IP}'"
    fi
    if [[ -n "${FILTER_DST_IP}" ]]; then
        filter_clause="${filter_clause} | filter dstAddr = '${FILTER_DST_IP}'"
    fi
    if [[ -n "${FILTER_PORT}" ]]; then
        filter_clause="${filter_clause} | filter dstPort = ${FILTER_PORT}"
    fi

    # Skip if no filters specified
    if [[ -z "${filter_clause}" ]]; then
        return 0
    fi

    print_header "4. Filtered Flow Details"

    local desc=""
    [[ -n "${FILTER_SRC_IP}" ]] && desc="${desc} src=${FILTER_SRC_IP}"
    [[ -n "${FILTER_DST_IP}" ]] && desc="${desc} dst=${FILTER_DST_IP}"
    [[ -n "${FILTER_PORT}" ]] && desc="${desc} port=${FILTER_PORT}"
    echo -e "${BLUE}  Filter conditions:${desc}${NC}"
    echo ""

    local query
    query="fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, packets, bytes
${filter_clause}
| sort @timestamp asc
| limit 50"

    local result
    result=$(run_insights_query "${query}" "Filtered flows") || return 1

    echo ""
    printf "  ${BOLD}%-22s %-18s %-18s %-7s %-7s %-8s %6s${NC}\n" \
        "Timestamp" "Source" "Destination" "SrcPort" "DstPort" "Action" "Pkts"
    echo "  ──────────────────────────────────────────────────────────────────────────────────"

    echo "${result}" | python3 -c "
import json, sys

PROTO_NAMES = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}

data = json.load(sys.stdin)
results = data.get('results', [])
for row in results:
    fields = {f['field']: f['value'] for f in row}
    ts = fields.get('@timestamp', '?')[:22]
    src = fields.get('srcAddr', '?')
    dst = fields.get('dstAddr', '?')
    sp = fields.get('srcPort', '?')
    dp = fields.get('dstPort', '?')
    action = fields.get('action', '?')
    pkts = fields.get('packets', '0')

    if action == 'ACCEPT':
        color = '\033[0;32m'
    else:
        color = '\033[0;31m'
    end = '\033[0m'

    print(f'  {ts:<22} {src:<18} {dst:<18} {sp:<7} {dp:<7} {color}{action:<8}{end} {pkts:>6}')
" 2>/dev/null || echo -e "${YELLOW}  (No data)${NC}"

    echo "${result}" > "${OUTPUT_DIR}/filtered_flows.json"
}

# =============================================================================
# 5. ASCII Flow Diagram Generation
# =============================================================================
generate_ascii_flow_diagram() {
    print_header "5. ASCII Flow Diagram (generated from actual Flow Logs data)"

    # Retrieve all flows (unique Source->Destination pairs, Port, Action)
    local query
    query='stats count(*) as total, sum(packets) as pkts by srcAddr, dstAddr, dstPort, protocol, action
| sort total desc
| limit 30'

    local result
    result=$(run_insights_query "${query}" "Flow diagram data retrieval") || return 1

    echo ""
    echo -e "${BOLD}  Network Flow Diagram (based on VPC Flow Logs data)${NC}"
    echo ""

    # Draw ASCII flow diagram with Python
    echo "${result}" | python3 -c "
import json, sys

PROTO_NAMES = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
PORT_NAMES = {
    '22': 'SSH', '80': 'HTTP', '443': 'HTTPS',
    '5432': 'PostgreSQL', '8080': 'HTTP-Alt', '53': 'DNS',
}

data = json.load(sys.stdin)
results = data.get('results', [])

if not results:
    print('  (No flow data)')
    sys.exit(0)

for row in results:
    fields = {f['field']: f['value'] for f in row}
    src = fields.get('srcAddr', '?')
    dst = fields.get('dstAddr', '?')
    dp = fields.get('dstPort', '?')
    proto = fields.get('protocol', '?')
    action = fields.get('action', '?')
    total = fields.get('total', '0')
    pkts = fields.get('pkts', '0')

    proto_name = PROTO_NAMES.get(proto, f'P{proto}')
    port_name = PORT_NAMES.get(dp, '')
    port_label = f'{port_name}({dp})' if port_name else dp

    if action == 'ACCEPT':
        arrow = '\033[0;32m--' + proto_name + ':' + port_label + '-->\033[0m'
        marker = '\033[0;32m ACCEPT\033[0m'
        comment = ''
    else:
        arrow = '\033[0;31m--' + proto_name + ':' + port_label + '--X\033[0m'
        marker = '\033[0;31m REJECT\033[0m'
        comment = ' \033[0;31m<- Blocked by SG/NACL\033[0m'

    # Color based on whether source is internal IP
    if src.startswith('10.0.'):
        src_color = '\033[0;36m'
    else:
        src_color = '\033[0;33m'

    if dst.startswith('10.0.'):
        dst_color = '\033[0;36m'
    else:
        dst_color = '\033[0;33m'

    end = '\033[0m'

    print(f'  [{src_color}{src}{end}] {arrow} [{dst_color}{dst}:{dp}{end}]{marker}  ({total} items/{pkts}pkts){comment}')
" 2>/dev/null || echo -e "${YELLOW}  (No data)${NC}"

    echo ""
    echo -e "${CYAN}  Legend: ${GREEN}Green=ACCEPT${NC}, ${RED}Red=REJECT${NC}, ${CYAN}Cyan=Internal IP${NC}, ${YELLOW}Yellow=External IP${NC}"

    echo "${result}" > "${OUTPUT_DIR}/flow_diagram_data.json"
}

# =============================================================================
# 6. SG/NACL Block Correlation Analysis
# =============================================================================
analyze_blocked_traffic() {
    print_header "6. Security Group/NACL Block Analysis"

    local query
    query='filter action = "REJECT"
| stats count(*) as blocked by srcAddr, dstAddr, dstPort, protocol
| sort blocked desc
| limit 15'

    local result
    result=$(run_insights_query "${query}" "REJECT flow analysis") || return 1

    echo ""
    echo -e "${BOLD}  Blocked Traffic List (REJECT)${NC}"
    echo ""

    local has_data
    has_data=$(echo "${result}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(len(data.get('results', [])))
" 2>/dev/null || echo "0")

    if [[ "${has_data}" == "0" ]]; then
        echo -e "${GREEN}  ✓ No REJECTED flows${NC}"
        echo ""
        return 0
    fi

    printf "  ${BOLD}%-18s %-18s %-8s %-8s %8s  %-30s${NC}\n" \
        "Source" "Destination" "Port" "Proto" "Count" "Estimated block reason"
    echo "  ─────────────────────────────────────────────────────────────────────────────────"

    echo "${result}" | python3 -c "
import json, sys

PROTO_NAMES = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}

# SG/NACL block estimation rules
def estimate_block_reason(src, dst, port, proto):
    port = str(port)
    # External->Internal SSH
    if not src.startswith('10.0.') and port == '22':
        if dst.startswith('10.0.10.') or dst.startswith('10.0.11.'):
            return 'App SG: SSH denied (Private Subnet)'
        return 'App SG: SSH allowed only from my_ip'
    # External->Direct RDS port access
    if not src.startswith('10.0.') and port == '5432':
        return 'DB SG: Allowed only from App SG'
    # External->Internal arbitrary port
    if not src.startswith('10.0.') and dst.startswith('10.0.10.'):
        return 'App SG: Only Port 80 from ALB SG allowed'
    if not src.startswith('10.0.') and dst.startswith('10.0.20.'):
        return 'DB SG: No external access allowed'
    # Port scan (non-standard ports)
    if port not in ('22', '80', '443', '5432') and not src.startswith('10.0.'):
        return 'SG: Blocking non-permitted ports'
    return 'Blocked by SG/NACL rules'

data = json.load(sys.stdin)
results = data.get('results', [])
for row in results:
    fields = {f['field']: f['value'] for f in row}
    src = fields.get('srcAddr', '?')
    dst = fields.get('dstAddr', '?')
    port = fields.get('dstPort', '?')
    proto = fields.get('protocol', '?')
    blocked = fields.get('blocked', '0')

    proto_name = PROTO_NAMES.get(proto, f'P{proto}')
    reason = estimate_block_reason(src, dst, port, proto)

    print(f'  \033[0;31m{src:<18} {dst:<18} {port:<8} {proto_name:<8} {blocked:>8}  {reason}\033[0m')
" 2>/dev/null

    echo "${result}" > "${OUTPUT_DIR}/blocked_traffic.json"
}

# =============================================================================
# 7. NAT Gateway Translation Visualization (Config B only)
# =============================================================================
analyze_nat_translation() {
    if [[ "${CONFIG_MODE}" != "private" ]]; then
        return 0
    fi
    if [[ -z "${NAT_GW_EIP}" ]]; then
        return 0
    fi

    print_header "7. NAT Gateway Address Translation Visualization"

    echo -e "${BLUE}  NAT Gateway EIP: ${NAT_GW_EIP}${NC}"
    echo ""

    # Outbound traffic from EC2 (private) to external destinations
    local query
    query="filter srcAddr like '10.0.10.' or srcAddr like '10.0.11.'
| filter not (dstAddr like '10.0.')
| stats count(*) as total by srcAddr, dstAddr, dstPort
| sort total desc
| limit 10"

    local result
    result=$(run_insights_query "${query}" "Outbound traffic via NAT") || return 1

    echo -e "${BOLD}  Private EC2 → NAT Gateway → Internet (address translation)${NC}"
    echo ""
    echo "  ┌──────────────────────────────────────────────────────────────┐"
    echo "  │  EC2 (Private IP)  →  NAT Gateway  →  Internet       │"
    echo "  │  10.0.10.x:ephemeral   ${NAT_GW_EIP}:ephemeral   dst:port  │"
    echo "  └──────────────────────────────────────────────────────────────┘"
    echo ""

    echo "${result}" | python3 -c "
import json, sys

nat_eip = '${NAT_GW_EIP}'

data = json.load(sys.stdin)
results = data.get('results', [])

if not results:
    print('  (No outbound traffic)')
    sys.exit(0)

for row in results:
    fields = {f['field']: f['value'] for f in row}
    src = fields.get('srcAddr', '?')
    dst = fields.get('dstAddr', '?')
    dp = fields.get('dstPort', '?')
    total = fields.get('total', '0')

    print(f'  [{src}] --(private)--> [NAT GW: {nat_eip}] --(public)--> [{dst}:{dp}]  ({total} items)')
" 2>/dev/null

    echo "${result}" > "${OUTPUT_DIR}/nat_translation.json"
}

# =============================================================================
# 8. Traffic Volume Statistics Summary
# =============================================================================
analyze_traffic_stats() {
    print_header "8. Traffic Volume Statistics Summary"

    local query
    query='stats sum(packets) as totalPkts, sum(bytes) as totalBytes, count(*) as flowCount by action
| sort action asc'

    local result
    result=$(run_insights_query "${query}" "Traffic statistics") || return 1

    echo ""
    echo "${result}" | python3 -c "
import json, sys

def fmt_bytes(b):
    b = int(b)
    if b >= 1073741824:
        return f'{b/1073741824:.1f} GB'
    elif b >= 1048576:
        return f'{b/1048576:.1f} MB'
    elif b >= 1024:
        return f'{b/1024:.1f} KB'
    return f'{b} B'

data = json.load(sys.stdin)
results = data.get('results', [])

total_flows = 0
total_pkts = 0
total_bytes = 0

print(f'  {chr(0x250c)}{chr(0x2500)*58}{chr(0x2510)}')
print(f'  {chr(0x2502)} {\"Action\":<10} {\"Flows\":>10} {\"Packets\":>12} {\"Data Volume\":>14}   {chr(0x2502)}')
print(f'  {chr(0x251c)}{chr(0x2500)*58}{chr(0x2524)}')

for row in results:
    fields = {f['field']: f['value'] for f in row}
    action = fields.get('action', '?')
    flows = int(fields.get('flowCount', '0'))
    pkts = int(fields.get('totalPkts', '0'))
    byts = int(fields.get('totalBytes', '0'))
    total_flows += flows
    total_pkts += pkts
    total_bytes += byts

    marker = '\033[0;32m' if action == 'ACCEPT' else '\033[0;31m'
    end = '\033[0m'
    print(f'  {chr(0x2502)} {marker}{action:<10}{end} {flows:>10,} {pkts:>12,} {fmt_bytes(byts):>14}   {chr(0x2502)}')

print(f'  {chr(0x251c)}{chr(0x2500)*58}{chr(0x2524)}')
print(f'  {chr(0x2502)} {\"Total\":<10} {total_flows:>10,} {total_pkts:>12,} {fmt_bytes(total_bytes):>14}   {chr(0x2502)}')
print(f'  {chr(0x2514)}{chr(0x2500)*58}{chr(0x2518)}')
" 2>/dev/null || echo -e "${YELLOW}  (No data)${NC}"

    echo "${result}" > "${OUTPUT_DIR}/traffic_stats.json"
}

# =============================================================================
# 9. Config A / Config B Comparison Mode
# =============================================================================
compare_configs() {
    print_header "9. Config A (Public) vs Config B (Private) Flow Log Comparison"

    local dir_a="${RESULTS_BASE}/configA/flow-logs"
    local dir_b="${RESULTS_BASE}/configB/flow-logs"

    if [[ ! -d "${dir_a}" || ! -d "${dir_b}" ]]; then
        echo -e "${YELLOW}[!] Both Config results are needed for comparison${NC}"
        echo -e "${YELLOW}    Config A results: ${dir_a}${NC}"
        echo -e "${YELLOW}    Config B results: ${dir_b}${NC}"
        echo ""
        echo "  Usage:"
        echo "    1. terraform apply with config_mode=public -> run attacks -> run this script"
        echo "    2. terraform apply with config_mode=private -> run attacks -> run this script"
        echo "    3. ./flow_logs_analyzer.sh --compare"
        return 1
    fi

    python3 -c "
import json, sys, os

dir_a = '${dir_a}'
dir_b = '${dir_b}'

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None

# ACCEPT/REJECT comparison
print()
print('  ┌─────────────────────────────────────────────────────────┐')
print('  │        Config A (Public)   vs   Config B (Private)      │')
print('  └─────────────────────────────────────────────────────────┘')
print()

a_stats = load_json(os.path.join(dir_a, 'accept_reject_summary.json'))
b_stats = load_json(os.path.join(dir_b, 'accept_reject_summary.json'))

def extract_action_counts(data):
    counts = {'ACCEPT': 0, 'REJECT': 0}
    if not data:
        return counts
    for row in data.get('results', []):
        fields = {f['field']: f['value'] for f in row}
        action = fields.get('action', '')
        total = int(fields.get('total', '0'))
        if action in counts:
            counts[action] = total
    return counts

a_counts = extract_action_counts(a_stats)
b_counts = extract_action_counts(b_stats)

print(f'  {\"\":<12} {\"Config A\":>12} {\"Config B\":>12} {\"Diff\":>12}')
print(f'  {\"─\"*50}')
for action in ['ACCEPT', 'REJECT']:
    a = a_counts[action]
    b = b_counts[action]
    diff = b - a
    sign = '+' if diff > 0 else ''
    color = '\033[0;32m' if action == 'ACCEPT' else '\033[0;31m'
    end = '\033[0m'
    print(f'  {color}{action:<12}{end} {a:>12,} {b:>12,} {sign}{diff:>11,}')

# Block analysis comparison
a_blocked = load_json(os.path.join(dir_a, 'blocked_traffic.json'))
b_blocked = load_json(os.path.join(dir_b, 'blocked_traffic.json'))

a_block_count = len((a_blocked or {}).get('results', []))
b_block_count = len((b_blocked or {}).get('results', []))

print()
print(f'  Block pattern count:')
print(f'    Config A: {a_block_count} patterns')
print(f'    Config B: {b_block_count} patterns')

if b_block_count > a_block_count:
    diff = b_block_count - a_block_count
    print(f'    → \033[0;32mConfig B has {diff} more block patterns (more robust)\033[0m')
elif a_block_count > b_block_count:
    print(f'    → \033[0;31mConfig A has more blocks (unexpected state)\033[0m')
else:
    print(f'    → Equal number of blocks')

print()
print('  ┌─────────────────────────────────────────────────────────┐')
print('  │ Security Assessment Summary                                │')
print('  ├─────────────────────────────────────────────────────────┤')
print('  │                                                         │')
print('  │  Config A (Public):                                     │')
print('  │    - EC2 has Public IP directly assigned                │')
print('  │    - SG-only defense (single defense layer)             │')
print('  │    - EC2 IP directly exposed to port scans              │')
print('  │    - SSRF can reach IMDS directly                       │')
print('  │                                                         │')
print('  │  Config B (Private):                                    │')
print('  │    - EC2 isolated in Private Subnet                     │')
print('  │    - ALB -> App SG dual defense                         │')
print('  │    - Attacker only sees ALB DNS (EC2 IP hidden)         │')
print('  │    - Source IP anonymized via NAT Gateway outbound      │')
print('  │                                                         │')
print('  └─────────────────────────────────────────────────────────┘')
" 2>/dev/null
}

# =============================================================================
# Main execution
# =============================================================================
main() {
    parse_args "$@"

    if [[ "${COMPARE_MODE}" == true ]]; then
        # Comparison mode still needs init_config (for RESULTS_BASE path config)
        # Simple initialization since terraform can't be both configs simultaneously
        RESULTS_BASE="${PROJECT_ROOT}/results"
        compare_configs
        exit $?
    fi

    initialize

    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║      VPC Flow Logs Analysis Report                          ║${NC}"
    echo -e "${BOLD}${CYAN}║      Config: ${CONFIG_LABEL}${NC}"
    echo -e "${BOLD}${CYAN}║      Period: Last ${LOOKBACK_MINUTES} minutes                   ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Execute all analysis sections sequentially
    analyze_accept_reject
    analyze_top_sources
    analyze_by_port
    analyze_filtered_flows
    generate_ascii_flow_diagram
    analyze_blocked_traffic
    analyze_nat_translation
    analyze_traffic_stats

    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}[✓] Analysis complete. Results saved to ${OUTPUT_DIR}${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  Saved files:"
    ls -1 "${OUTPUT_DIR}"/*.json 2>/dev/null | while read -r f; do
        echo "    - ${f}"
    done
}

main "$@"
