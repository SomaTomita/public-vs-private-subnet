#!/usr/bin/env bash
# =============================================================================
# compare_results.sh — Config A vs Config B Result Comparison
# =============================================================================
# Purpose:
#   Read result files from configA/ and configB/,
#   output a side-by-side comparison table for each attack.
#
# Usage:
#   1. terraform apply with config_mode=public -> run_all_attacks.sh
#   2. terraform apply with config_mode=private -> run_all_attacks.sh
#   3. Run compare_results.sh to compare
#
# Output:
#   - Display verdict (VULNERABLE / BLOCKED) side-by-side for each test
#   - Quantitative comparison of overall score and security improvements
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

DIR_A="${RESULTS_BASE}/configA"
DIR_B="${RESULTS_BASE}/configB"

# ---------------------------------------------------------------------------
# Check result directory existence
# ---------------------------------------------------------------------------
print_header "Security Lab — Config A vs Config B Comparison Report"

echo -e "${BLUE}[*] Checking result directories${NC}"

has_a=false
has_b=false

if [[ -d "${DIR_A}" ]] && ls "${DIR_A}"/*.txt &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} Config A results: ${DIR_A}"
    has_a=true
else
    echo -e "  ${YELLOW}[--]${NC} Config A results not found: ${DIR_A}"
fi

if [[ -d "${DIR_B}" ]] && ls "${DIR_B}"/*.txt &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} Config B results: ${DIR_B}"
    has_b=true
else
    echo -e "  ${YELLOW}[--]${NC} Config B results not found: ${DIR_B}"
fi

if ! $has_a && ! $has_b; then
    echo -e "${RED}[!] No result files found. Please run run_all_attacks.sh first.${NC}"
    exit 1
fi

if ! $has_a || ! $has_b; then
    echo ""
    echo -e "${YELLOW}[!] Only one config's results are available. Run attacks with both configs before comparing.${NC}"
    echo -e "${YELLOW}    1. terraform apply with config_mode='public' -> ./run_all_attacks.sh${NC}"
    echo -e "${YELLOW}    2. terraform apply with config_mode='private' -> ./run_all_attacks.sh${NC}"
    echo -e "${YELLOW}    3. ./compare_results.sh${NC}"

    if $has_a; then
        echo ""
        echo -e "${BLUE}[*] Showing Config A results only:${NC}"
        for f in "${DIR_A}"/*.txt; do
            echo ""
            echo -e "${BOLD}--- $(basename "${f}") ---${NC}"
            cat "${f}"
        done
    fi
    if $has_b; then
        echo ""
        echo -e "${BLUE}[*] Showing Config B results only:${NC}"
        for f in "${DIR_B}"/*.txt; do
            echo ""
            echo -e "${BOLD}--- $(basename "${f}") ---${NC}"
            cat "${f}"
        done
    fi
    exit 0
fi

echo ""

# ---------------------------------------------------------------------------
# Helper: Extract verdict from result file
# ---------------------------------------------------------------------------
# Count occurrences of severity-tagged and plain VULNERABLE/BLOCKED in result file
extract_verdict() {
    local file="$1"
    if [[ -f "${file}" ]]; then
        local vuln_count blocked_count critical_count
        critical_count=$(grep -ci "CRITICAL" "${file}" 2>/dev/null || echo "0")
        vuln_count=$(grep -ci "VULNERABLE" "${file}" 2>/dev/null || echo "0")
        blocked_count=$(grep -ci "BLOCKED" "${file}" 2>/dev/null || echo "0")

        if [[ ${critical_count} -gt 0 ]]; then
            echo "CRITICAL"
        elif [[ ${vuln_count} -gt 0 ]]; then
            echo "VULNERABLE"
        elif [[ ${blocked_count} -gt 0 ]]; then
            echo "BLOCKED"
        else
            echo "N/A"
        fi
    else
        echo "Not executed"
    fi
}

# Colored verdict display
colored_verdict() {
    local verdict="$1"
    case "${verdict}" in
        CRITICAL)   echo -e "${RED}${BOLD}CRITICAL${NC}" ;;
        VULNERABLE) echo -e "${RED}VULNERABLE${NC}" ;;
        BLOCKED)    echo -e "${GREEN}BLOCKED${NC}" ;;
        *)          echo -e "${YELLOW}${verdict}${NC}" ;;
    esac
}

# ---------------------------------------------------------------------------
# Output comparison table
# ---------------------------------------------------------------------------
echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}${CYAN}│           AWS Security Lab — Attack Result Comparison Report                           │${NC}"
echo -e "${BOLD}${CYAN}│           Config A (Public) vs Config B (Private)                           │${NC}"
echo -e "${BOLD}${CYAN}├──────────────────────────────────────────────────────────────────────────────┤${NC}"

# Test definitions
declare -A TEST_NAMES=(
    ["00_reconnaissance"]="00: Reconnaissance"
    ["01_portscan"]="01: Port Scan"
    ["02_ssh_probe"]="02: SSH Probe"
    ["03_web_scan"]="03: Web Scan"
    ["04_ssrf_metadata"]="04: SSRF/IMDS Attack"
    ["05_db_probe"]="05: DB Direct Connection"
    ["06_outbound_check"]="06: Outbound Communication"
    ["07_full_kill_chain"]="07: Full Kill Chain"
    ["08_post_exploitation"]="08: Post-Exploitation"
    ["09_internal_recon"]="09: Internal Recon"
    ["10_ssrf_internal_recon"]="10: SSRF Internal Recon"
    ["11_iam_privilege_escalation"]="11: IAM Privilege Escalation"
    ["12_alb_attacks"]="12: ALB-Specific Attacks"
    ["13_outbound_c2"]="13: C2 Channel Test"
    ["14_ssrf_to_rds"]="14: SSRF → RDS Attack"
    ["15_iam_blast_radius"]="15: IAM Blast Radius"
    ["16_data_exfiltration"]="16: Data Exfiltration"
    ["17_persistence_check"]="17: Persistence Mechanisms"
    ["18_detection_evasion"]="18: Detection Evasion"
    ["19_quantitative_metrics"]="19: Quantitative Metrics"
)

# Test order
TESTS=("00_reconnaissance" "01_portscan" "02_ssh_probe" "03_web_scan" "04_ssrf_metadata" "05_db_probe" "06_outbound_check" "07_full_kill_chain" "08_post_exploitation" "09_internal_recon" "10_ssrf_internal_recon" "11_iam_privilege_escalation" "12_alb_attacks" "13_outbound_c2" "14_ssrf_to_rds" "15_iam_blast_radius" "16_data_exfiltration" "17_persistence_check" "18_detection_evasion" "19_quantitative_metrics")

# Counters
a_vuln=0
a_blocked=0
b_vuln=0
b_blocked=0

printf "${BOLD}${CYAN}│${NC} %-24s │ %-20s │ %-20s ${BOLD}${CYAN}│${NC}\n" \
    "Test Name" "Config A (Public)" "Config B (Private)"
echo -e "${BOLD}${CYAN}├──────────────────────────────────────────────────────────────────────────────┤${NC}"

for test_id in "${TESTS[@]}"; do
    test_name="${TEST_NAMES[${test_id}]}"
    file_a="${DIR_A}/${test_id}.txt"
    file_b="${DIR_B}/${test_id}.txt"

    verdict_a=$(extract_verdict "${file_a}")
    verdict_b=$(extract_verdict "${file_b}")

    # 12 is N/A for Config A (no ALB) — exclude from score calculation
    if [[ "${test_id}" == "12_alb_attacks" && "${verdict_a}" == "Not executed" ]]; then
        verdict_a="N/A"
    fi

    # Count (exclude N/A from score; treat CRITICAL as VULNERABLE)
    [[ "${verdict_a}" == "VULNERABLE" || "${verdict_a}" == "CRITICAL" ]] && ((a_vuln++)) || true
    [[ "${verdict_a}" == "BLOCKED" ]] && ((a_blocked++)) || true
    [[ "${verdict_b}" == "VULNERABLE" || "${verdict_b}" == "CRITICAL" ]] && ((b_vuln++)) || true
    [[ "${verdict_b}" == "BLOCKED" ]] && ((b_blocked++)) || true

    # Colored display
    colored_a=$(colored_verdict "${verdict_a}")
    colored_b=$(colored_verdict "${verdict_b}")

    # Improvement indicator
    improvement=""
    if [[ "${verdict_a}" == "VULNERABLE" && "${verdict_b}" == "BLOCKED" ]] || \
       [[ "${verdict_a}" == "CRITICAL" && "${verdict_b}" == "BLOCKED" ]]; then
        improvement=" ✓ Improved"
    elif [[ "${verdict_a}" == "CRITICAL" && "${verdict_b}" == "VULNERABLE" ]]; then
        improvement=" ~ Partially improved"
    elif [[ "${verdict_a}" == "VULNERABLE" && "${verdict_b}" == "VULNERABLE" ]] || \
         [[ "${verdict_a}" == "CRITICAL" && "${verdict_b}" == "CRITICAL" ]]; then
        improvement=" ! Not improved"
    fi

    printf "${BOLD}${CYAN}│${NC} %-24s │ %-31b │ %-31b${improvement}${BOLD}${CYAN}│${NC}\n" \
        "${test_name}" "${colored_a}" "${colored_b}"
done

echo -e "${BOLD}${CYAN}├──────────────────────────────────────────────────────────────────────────────┤${NC}"

# ---------------------------------------------------------------------------
# Score Summary
# ---------------------------------------------------------------------------
a_total=$((a_vuln + a_blocked))
b_total=$((b_vuln + b_blocked))

# Prevent division by zero
a_score=0
b_score=0
[[ ${a_total} -gt 0 ]] && a_score=$(( (a_blocked * 100) / a_total ))
[[ ${b_total} -gt 0 ]] && b_score=$(( (b_blocked * 100) / b_total ))

printf "${BOLD}${CYAN}│${NC} %-24s │ %-20s │ %-20s ${BOLD}${CYAN}│${NC}\n" \
    "Vulnerable Items" "${a_vuln}" "${b_vuln}"
printf "${BOLD}${CYAN}│${NC} %-24s │ %-20s │ %-20s ${BOLD}${CYAN}│${NC}\n" \
    "Blocked Items" "${a_blocked}" "${b_blocked}"
printf "${BOLD}${CYAN}│${NC} %-24s │ %-20s │ %-20s ${BOLD}${CYAN}│${NC}\n" \
    "Security Score" "${a_score}%" "${b_score}%"

echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────────────────────────┘${NC}"

echo ""

# ---------------------------------------------------------------------------
# Detailed Analysis of Improvements
# ---------------------------------------------------------------------------
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Detailed Analysis${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Port scan comparison
echo -e "${BOLD}[01] Port scan comparison:${NC}"
if [[ -f "${DIR_A}/01_portscan.txt" && -f "${DIR_B}/01_portscan.txt" ]]; then
    a_open=$(grep -c "open" "${DIR_A}/01_portscan.txt" 2>/dev/null || echo "0")
    b_open=$(grep -c "open" "${DIR_B}/01_portscan.txt" 2>/dev/null || echo "0")
    echo -e "  Config A: ${a_open} ports open  →  Config B: ${b_open} ports open"
    if [[ ${b_open} -lt ${a_open} ]]; then
        echo -e "  ${GREEN}Improved: Externally exposed ports decreased from ${a_open} to ${b_open}${NC}"
    fi
fi
echo ""

# SSH comparison
echo -e "${BOLD}[02] SSH exposure comparison:${NC}"
verdict_a=$(extract_verdict "${DIR_A}/02_ssh_probe.txt")
verdict_b=$(extract_verdict "${DIR_B}/02_ssh_probe.txt")
if [[ "${verdict_a}" == "VULNERABLE" && "${verdict_b}" == "BLOCKED" ]]; then
    echo -e "  ${GREEN}Improved: SSH is completely hidden from outside${NC}"
    echo -e "  Config A: SSH(22) directly exposed to internet -> Risk of brute-force attacks"
    echo -e "  Config B: EC2 has no Public IP + ALB does not forward SSH -> SSH unreachable"
else
    echo -e "  Config A: $(colored_verdict "${verdict_a}")   Config B: $(colored_verdict "${verdict_b}")"
fi
echo ""

# SSRF comparison
echo -e "${BOLD}[04] SSRF/IMDS attack comparison:${NC}"
verdict_a=$(extract_verdict "${DIR_A}/04_ssrf_metadata.txt")
verdict_b=$(extract_verdict "${DIR_B}/04_ssrf_metadata.txt")
if [[ "${verdict_a}" == "VULNERABLE" && "${verdict_b}" == "VULNERABLE" ]]; then
    echo -e "  ${YELLOW}Warning: SSRF attack succeeded in both Config A and Config B${NC}"
    echo -e "  Network architecture changes alone cannot prevent SSRF"
    echo -e "  ${BOLD}Additional countermeasures required:${NC}"
    echo -e "    1. Enforce IMDSv2 (http_tokens = 'required')"
    echo -e "    2. Remove the /fetch endpoint"
    echo -e "    3. Block metadata IP request patterns with WAF"
else
    echo -e "  Config A: $(colored_verdict "${verdict_a}")   Config B: $(colored_verdict "${verdict_b}")"
fi
echo ""

# Outbound comparison
echo -e "${BOLD}[06] Outbound communication comparison:${NC}"
a_ip=$(grep -oE 'Outbound IP: [0-9.]+' "${DIR_A}/06_outbound_check.txt" 2>/dev/null | head -1 | awk '{print $3}' || echo "N/A")
b_ip=$(grep -oE 'Outbound IP: [0-9.]+' "${DIR_B}/06_outbound_check.txt" 2>/dev/null | head -1 | awk '{print $3}' || echo "N/A")
echo -e "  Config A Outbound IP: ${a_ip} (EC2 Public IP = direct IGW)"
echo -e "  Config B Outbound IP: ${b_ip} (NAT Gateway EIP)"
if [[ "${a_ip}" != "${b_ip}" && "${a_ip}" != "N/A" && "${b_ip}" != "N/A" ]]; then
    echo -e "  ${GREEN}In Config B, traffic is consolidated through NAT Gateway, making monitoring easier${NC}"
fi
echo ""

# SSRF → RDS comparison
echo -e "${BOLD}[14] SSRF → RDS Attack comparison:${NC}"
verdict_a=$(extract_verdict "${DIR_A}/14_ssrf_to_rds.txt")
verdict_b=$(extract_verdict "${DIR_B}/14_ssrf_to_rds.txt")
if [[ ("${verdict_a}" == "VULNERABLE" || "${verdict_a}" == "CRITICAL") && \
      ("${verdict_b}" == "VULNERABLE" || "${verdict_b}" == "CRITICAL") ]]; then
    echo -e "  ${YELLOW}Warning: SSRF→RDS attack succeeded in both configs${NC}"
    echo -e "  Private subnet blocks external DB access but SSRF from app server bypasses this"
    echo -e "  ${BOLD}Fix: Remove SSRF vulnerability, enforce IMDSv2, restrict app→RDS SG rules${NC}"
else
    echo -e "  Config A: $(colored_verdict "${verdict_a}")   Config B: $(colored_verdict "${verdict_b}")"
fi
echo ""

# IAM Blast Radius comparison
echo -e "${BOLD}[15] IAM Blast Radius comparison:${NC}"
verdict_a=$(extract_verdict "${DIR_A}/15_iam_blast_radius.txt")
verdict_b=$(extract_verdict "${DIR_B}/15_iam_blast_radius.txt")
if [[ ("${verdict_a}" == "VULNERABLE" || "${verdict_a}" == "CRITICAL") && \
      ("${verdict_b}" == "VULNERABLE" || "${verdict_b}" == "CRITICAL") ]]; then
    echo -e "  ${YELLOW}Warning: IAM blast radius is identical in both configs${NC}"
    echo -e "  IAM credentials operate via AWS control plane (API), independent of VPC topology"
    echo -e "  ${BOLD}Fix: Least-privilege IAM, SCPs, aws:SourceVpc conditions, GuardDuty${NC}"
else
    echo -e "  Config A: $(colored_verdict "${verdict_a}")   Config B: $(colored_verdict "${verdict_b}")"
fi
echo ""

# ---------------------------------------------------------------------------
# Overall Assessment
# ---------------------------------------------------------------------------
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Overall Assessment${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

improvement_count=0
for test_id in "${TESTS[@]}"; do
    va=$(extract_verdict "${DIR_A}/${test_id}.txt")
    vb=$(extract_verdict "${DIR_B}/${test_id}.txt")
    [[ "${va}" == "VULNERABLE" && "${vb}" == "BLOCKED" ]] && ((improvement_count++)) || true
done

still_vuln=0
for test_id in "${TESTS[@]}"; do
    vb=$(extract_verdict "${DIR_B}/${test_id}.txt")
    [[ "${vb}" == "VULNERABLE" ]] && ((still_vuln++)) || true
done

echo -e "  Items improved from Config A -> Config B: ${GREEN}${improvement_count}${NC}"
echo -e "  Vulnerabilities remaining in Config B: ${RED}${still_vuln}${NC}"
echo ""

echo -e "${BOLD}  Layer-by-Layer Analysis:${NC}"
echo ""
echo -e "  ${GREEN}■ Network Boundary (Private Subnet effectiveness)${NC}"
echo -e "    Port scan, SSH probe, outbound path"
echo -e "    -> Private Subnet + ALB reduces the attack surface"
echo ""
echo -e "  ${RED}■ Application Layer (not mitigated by Private Subnet)${NC}"
echo -e "    Web scan, SSRF/IMDS, SSRF internal recon"
echo -e "    -> Requires WAF, IMDSv2 enforcement, and secure coding"
echo ""
echo -e "  ${RED}■ AWS API Layer (not mitigated by Private Subnet)${NC}"
echo -e "    IAM privilege escalation, post-exploitation"
echo -e "    -> Requires least-privilege IAM, SCPs, aws:SourceVpc conditions, GuardDuty"
echo ""
echo -e "  ${YELLOW}■ ALB Proxy Layer (new attack surface in Config B)${NC}"
echo -e "    Host header injection, HTTP method tampering"
echo -e "    -> Requires AWS WAF, host-based routing, HTTPS enforcement"
echo ""
echo -e "  ${RED}■ Outbound (not mitigated by Private Subnet)${NC}"
echo -e "    C2 channels, data exfiltration"
echo -e "    -> Requires VPC Network Firewall, DNS Firewall, egress SG restrictions"
echo ""

if [[ ${still_vuln} -gt 0 ]]; then
    echo -e "${BOLD}  Conclusion:${NC}"
    echo -e "${YELLOW}  Private Subnet is effective for network boundary defense,${NC}"
    echo -e "${YELLOW}  but application, IAM, and outbound layer vulnerabilities remain.${NC}"
    echo -e "${YELLOW}  Network isolation is necessary but not sufficient.${NC}"
else
    echo -e "${GREEN}  All attacks were blocked in Config B.${NC}"
fi

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
report_file="${RESULTS_BASE}/comparison_report.txt"

{
    echo "======================================"
    echo "Security Lab — Comparison Report"
    echo "Generated at: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "======================================"
    echo ""
    echo "Config A security score: ${a_score}% (Vulnerable: ${a_vuln}, Blocked: ${a_blocked})"
    echo "Config B security score: ${b_score}% (Vulnerable: ${b_vuln}, Blocked: ${b_blocked})"
    echo ""
    echo "Improved items: ${improvement_count}"
    echo "Remaining vulnerabilities: ${still_vuln}"
    echo ""
    for test_id in "${TESTS[@]}"; do
        test_name="${TEST_NAMES[${test_id}]}"
        va=$(extract_verdict "${DIR_A}/${test_id}.txt")
        vb=$(extract_verdict "${DIR_B}/${test_id}.txt")
        printf "%-24s  A: %-12s  B: %-12s\n" "${test_name}" "${va}" "${vb}"
    done
} > "${report_file}"

echo -e "${BLUE}[*] Comparison report saved: ${report_file}${NC}"
echo ""

log "Comparison report generation complete"
