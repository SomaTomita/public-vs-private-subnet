#!/usr/bin/env bash
# =============================================================================
# run_all_attacks.sh — Orchestrator for all attack scripts
# =============================================================================
# Purpose:
#   Execute all attack scripts sequentially and summarize results.
#   Auto-detect current config_mode from Terraform output,
#   and save results to the appropriate directory.
#
# Usage:
#   # Test with Config A (Public)
#   cd terraform && terraform apply -var="config_mode=public"
#   cd ../scripts && ./run_all_attacks.sh
#
#   # Test with Config B (Private)
#   cd terraform && terraform apply -var="config_mode=private"
#   cd ../scripts && ./run_all_attacks.sh
#
#   # Compare after both are complete
#   ./compare_results.sh
#
# Options:
#   --skip-slow    Skip time-consuming scans like nmap
#   --only N       Execute only the script with the specified number (e.g., --only 04)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
SKIP_SLOW=false
ONLY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-slow)
            SKIP_SLOW=true
            shift
            ;;
        --only)
            ONLY="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--skip-slow] [--only NN]"
            echo ""
            echo "Options:"
            echo "  --skip-slow    Skip time-consuming scans like nmap"
            echo "  --only NN      Execute only the script with the specified number (e.g., --only 04)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------
init_config

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║         AWS Security Lab — Attack Script Execution            ║${NC}"
echo -e "${BOLD}${CYAN}║         ${CONFIG_LABEL}$(printf '%*s' $((35 - ${#CONFIG_LABEL})) '')║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}[!] This script is for educational purposes only.${NC}"
echo -e "${YELLOW}[!] Only run this in lab environments that you manage.${NC}"
echo ""

# Target reachability check
echo -e "${BLUE}[*] Verifying attack target reachability...${NC}"
if curl -sS -o /dev/null -w "%{http_code}" -m 10 "http://${ATTACK_TARGET}/" 2>/dev/null | grep -qE "^[23]"; then
    echo -e "${GREEN}[OK] http://${ATTACK_TARGET}/ is reachable${NC}"
else
    echo -e "${YELLOW}[!] http://${ATTACK_TARGET}/ is unreachable.${NC}"
    echo -e "${YELLOW}    The application may still be starting up.${NC}"
    echo -e "${YELLOW}    If you just ran terraform apply, wait 1-2 minutes and try again.${NC}"
    echo ""
    read -rp "Continue? (y/N): " confirm
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Script list
# ---------------------------------------------------------------------------
declare -A SCRIPTS=(
    ["00"]="00_reconnaissance.sh"
    ["01"]="01_portscan.sh"
    ["02"]="02_ssh_probe.sh"
    ["03"]="03_web_scan.sh"
    ["04"]="04_ssrf_metadata.sh"
    ["05"]="05_db_probe.sh"
    ["06"]="06_outbound_check.sh"
    ["07"]="07_full_kill_chain.sh"
    ["08"]="08_post_exploitation.sh"
    ["09"]="09_internal_recon.sh"
    ["10"]="10_ssrf_internal_recon.sh"
    ["11"]="11_iam_privilege_escalation.sh"
    ["12"]="12_alb_attacks.sh"
    ["13"]="13_outbound_c2.sh"
    ["14"]="14_ssrf_to_rds.sh"
    ["15"]="15_iam_blast_radius.sh"
    ["16"]="16_data_exfiltration.sh"
    ["17"]="17_persistence_check.sh"
    ["18"]="18_detection_evasion.sh"
    ["19"]="19_quantitative_metrics.sh"
)

# Execution order (recon -> scan -> attack -> kill chain -> post-exploitation -> internal recon -> advanced attacks)
ORDER=("00" "01" "02" "03" "04" "05" "06" "07" "08" "09" "10" "11" "12" "13" "14" "15" "16" "17" "18" "19")

# ---------------------------------------------------------------------------
# Start execution
# ---------------------------------------------------------------------------
start_time=$(date +%s)
total=0
success=0
failed=0

# Summary file
SUMMARY_FILE="${RESULTS_DIR}/00_summary.txt"
{
    echo "======================================"
    echo "Attack Execution Summary"
    echo "Config: ${CONFIG_LABEL}"
    echo "Target: ${ATTACK_TARGET}"
    echo "Executed at: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "======================================"
    echo ""
} > "${SUMMARY_FILE}"

for num in "${ORDER[@]}"; do
    script="${SCRIPTS[${num}]}"
    script_path="${SCRIPT_DIR}/${script}"

    # If --only is specified, execute only the matching script
    if [[ -n "${ONLY}" && "${num}" != "${ONLY}" ]]; then
        continue
    fi

    # Skip ALB attacks in Config A (no ALB exists)
    if [[ "${num}" == "12" && "${CONFIG_MODE}" == "public" ]]; then
        echo -e "${YELLOW}[SKIP] ${script} (no ALB in Config A)${NC}"
        echo "SKIP: ${script} (no ALB in Config A)" >> "${SUMMARY_FILE}"
        continue
    fi

    # --skip-slow skip port scan
    if $SKIP_SLOW && [[ "${num}" == "01" ]]; then
        echo -e "${YELLOW}[SKIP] ${script} (--skip-slow)${NC}"
        echo "SKIP: ${script} (--skip-slow)" >> "${SUMMARY_FILE}"
        continue
    fi

    # Verify script exists
    if [[ ! -f "${script_path}" ]]; then
        echo -e "${RED}[!] Script not found: ${script_path}${NC}"
        echo "ERROR: ${script} (not found)" >> "${SUMMARY_FILE}"
        ((failed++)) || true
        continue
    fi

    # Execute
    ((total++)) || true
    echo -e "${BOLD}${CYAN}[${num}/${#ORDER[@]}] Executing ${script}...${NC}"
    echo ""

    script_start=$(date +%s)

    if bash "${script_path}"; then
        script_end=$(date +%s)
        elapsed=$((script_end - script_start))
        echo ""
        echo -e "${GREEN}[OK] ${script} completed (${elapsed}sec)${NC}"
        echo "OK: ${script} (${elapsed}sec)" >> "${SUMMARY_FILE}"
        ((success++)) || true
    else
        script_end=$(date +%s)
        elapsed=$((script_end - script_start))
        echo ""
        echo -e "${RED}[FAIL] ${script} ended with error (${elapsed}sec)${NC}"
        echo "FAIL: ${script} (${elapsed}sec)" >> "${SUMMARY_FILE}"
        ((failed++)) || true
    fi

    echo ""
    echo -e "${CYAN}──────────────────────────────────────────────────────${NC}"
    echo ""
done

# ---------------------------------------------------------------------------
# Execution complete summary
# ---------------------------------------------------------------------------
end_time=$(date +%s)
total_elapsed=$((end_time - start_time))

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║                    Execution Complete Summary                     ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Config:          ${CONFIG_LABEL}"
echo -e "  Target:          ${ATTACK_TARGET}"
echo -e "  Results saved:   ${RESULTS_DIR}"
echo -e "  Tests executed:  ${total}"
echo -e "  Success:         ${GREEN}${success}${NC}"
echo -e "  Failed:          ${RED}${failed}${NC}"
echo -e "  Total time:      ${total_elapsed}sec"
echo ""

# Append to summary file
{
    echo ""
    echo "======================================"
    echo "Execution Results"
    echo "Tests: ${total}, Success: ${success}, Failed: ${failed}"
    echo "Total time: ${total_elapsed}sec"
    echo "======================================"
} >> "${SUMMARY_FILE}"

echo -e "${BLUE}[*] Summary saved: ${SUMMARY_FILE}${NC}"
echo ""

# List result files
echo -e "${BOLD}Saved result files:${NC}"
ls -la "${RESULTS_DIR}/"*.txt 2>/dev/null || echo "  (None)"
echo ""

# ---------------------------------------------------------------------------
# Next Steps
# ---------------------------------------------------------------------------
if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Next Steps${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Config A (Public) attacks are complete."
    echo -e "  Next, run the same attacks with Config B (Private):"
    echo ""
    echo -e "  ${BOLD}cd ../terraform${NC}"
    echo -e "  ${BOLD}terraform apply -var='config_mode=private'${NC}"
    echo -e "  ${BOLD}cd ../scripts${NC}"
    echo -e "  ${BOLD}./run_all_attacks.sh${NC}"
    echo ""
    echo -e "  After both are complete, run comparison:"
    echo -e "  ${BOLD}./compare_results.sh${NC}"
elif [[ "${CONFIG_MODE}" == "private" ]]; then
    # After Config B is complete, check if Config A results also exist
    if [[ -d "${RESULTS_BASE}/configA" ]] && ls "${RESULTS_BASE}/configA"/*.txt &>/dev/null; then
        echo -e "${GREEN}[*] Results from both Config A and Config B exist. Comparison report can be generated.${NC}"
        echo ""
        echo -e "  ${BOLD}./compare_results.sh${NC}"
    else
        echo -e "${YELLOW}[*] Config A results not found. Please run attacks with Config A first.${NC}"
    fi
fi

echo ""
log "All attack scripts execution complete"
