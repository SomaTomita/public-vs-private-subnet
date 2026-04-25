#!/usr/bin/env bash
# =============================================================================
# 03_web_scan.sh — Web application scan
# =============================================================================
# Purpose:
#   Perform information gathering and security scanning of the web application.
#   Check HTTP response headers, endpoint enumeration, and presence of security headers.
#
# Learning points:
#   - Config A: EC2 responds directly. Server headers are more likely to leak version info.
#   - Config B: ALB mediates responses. ALB can add security headers.
#     The "Server" header differs (direct EC2 vs via ALB).
#
# Tools used:
#   - curl (required — standard on macOS)
#   - nuclei (optional — vulnerability scanner)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "03: Web Application Scan (Web Scan)"

RESULT_FILE="03_web_scan.txt"
result_text=""

TARGET_URL="http://${ATTACK_TARGET}"

echo -e "${BLUE}[*] Target URL: ${TARGET_URL}${NC}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: HTTP response header analysis
# ---------------------------------------------------------------------------
# Check the following from response headers:
#   - Server: Server software and version (information leak)
#   - X-Powered-By: Application framework (information leak)
#   - Presence of security headers (defense status)
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 1: HTTP response header analysis${NC}"
echo -e "${BLUE}[*] Checking server info and security settings from response headers${NC}"
echo ""

headers=$(curl -sS -I -m 10 "${TARGET_URL}" 2>&1) || true

echo "${headers}"
result_text+="--- HTTP Headers (/) ---"$'\n'
result_text+="${headers}"$'\n'$'\n'

echo ""
echo -e "${BOLD}--- Header analysis ---${NC}"

# Server header: Check for version info leak
server_header=$(echo "${headers}" | grep -i "^server:" || echo "")
if [[ -n "${server_header}" ]]; then
    echo -e "  Server: ${server_header}"
    # Vulnerable if detailed version info is included
    if echo "${server_header}" | grep -qiE "[0-9]+\.[0-9]+"; then
        print_vulnerable "Version info leaked in Server header"
    else
        print_info "Server header present (version info is minimal)"
    fi
    result_text+="Server header: ${server_header}"$'\n'
else
    print_blocked "Server header is hidden"
    result_text+="Server header: hidden"$'\n'
fi

# Check for presence of security headers
# Missing each header makes specific attacks more likely to succeed
declare -A SECURITY_HEADERS=(
    ["X-Content-Type-Options"]="Prevents MIME sniffing"
    ["X-Frame-Options"]="Prevents clickjacking"
    ["Strict-Transport-Security"]="Enforces HTTPS (HSTS)"
    ["Content-Security-Policy"]="Prevents XSS/injection (CSP)"
    ["X-XSS-Protection"]="XSS filter (legacy)"
    ["Referrer-Policy"]="Controls referrer information"
)

echo ""
echo -e "${BOLD}--- Security header check ---${NC}"
result_text+=$'\n'"--- Security Headers ---"$'\n'

missing_count=0
for header in "${!SECURITY_HEADERS[@]}"; do
    desc="${SECURITY_HEADERS[${header}]}"
    if echo "${headers}" | grep -qi "^${header}:"; then
        echo -e "  ${GREEN}[OK]${NC} ${header} — ${desc}"
        result_text+="[OK] ${header}: configured"$'\n'
    else
        echo -e "  ${RED}[NG]${NC} ${header} — ${desc}"
        result_text+="[NG] ${header}: not configured"$'\n'
        ((missing_count++)) || true
    fi
done

if [[ ${missing_count} -gt 3 ]]; then
    print_vulnerable "${missing_count} security headers missing — Basic web defenses are lacking"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Endpoint discovery
# ---------------------------------------------------------------------------
# Access known endpoints to check which features are exposed externally.
# Specifically check for the /fetch endpoint which has an SSRF vulnerability.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 2: Endpoint discovery${NC}"
echo ""

ENDPOINTS=("/" "/health" "/info" "/fetch" "/admin" "/api" "/.env" "/robots.txt" "/.git/config")
result_text+=$'\n'"--- Endpoint discovery ---"$'\n'

for endpoint in "${ENDPOINTS[@]}"; do
    # -o /dev/null: Discard body
    # -w to get only the HTTP status code
    status_code=$(curl -sS -o /dev/null -w "%{http_code}" -m 5 "${TARGET_URL}${endpoint}" 2>/dev/null) || status_code="000"

    case "${status_code}" in
        200)
            echo -e "  ${RED}${status_code}${NC}  ${endpoint}"
            result_text+="${status_code}  ${endpoint}"$'\n'
            # Particularly dangerous endpoints
            if [[ "${endpoint}" == "/fetch" ]]; then
                print_vulnerable "/fetch endpoint exposed — SSRF attack possible"
            fi
            if [[ "${endpoint}" == "/.env" ]]; then
                print_vulnerable "/.env is public — Environment variables (secrets) leaked"
            fi
            if [[ "${endpoint}" == "/.git/config" ]]; then
                print_vulnerable "/.git/config is public — Source code leaked"
            fi
            ;;
        301|302)
            echo -e "  ${YELLOW}${status_code}${NC}  ${endpoint} (redirect)"
            result_text+="${status_code}  ${endpoint} (redirect)"$'\n'
            ;;
        400)
            echo -e "  ${YELLOW}${status_code}${NC}  ${endpoint} (Bad Request — endpoint exists)"
            result_text+="${status_code}  ${endpoint}"$'\n'
            ;;
        403)
            echo -e "  ${GREEN}${status_code}${NC}  ${endpoint} (access denied)"
            result_text+="${status_code}  ${endpoint} (Forbidden)"$'\n'
            ;;
        404)
            echo -e "  ${NC}${status_code}  ${endpoint} (Not Found)${NC}"
            result_text+="${status_code}  ${endpoint}"$'\n'
            ;;
        000)
            echo -e "  ${NC}000  ${endpoint} (connection failed)${NC}"
            result_text+="000  ${endpoint} (connection failed)"$'\n'
            ;;
        *)
            echo -e "  ${YELLOW}${status_code}${NC}  ${endpoint}"
            result_text+="${status_code}  ${endpoint}"$'\n'
            ;;
    esac
done

echo ""

# ---------------------------------------------------------------------------
# Step 3: Collect internal info from /info endpoint
# ---------------------------------------------------------------------------
# /info returns internal hostname and Private IP.
# Valuable info for attackers to infer internal network structure.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 3: Collecting internal info from /info endpoint${NC}"
echo ""

info_response=$(curl -sS -m 5 "${TARGET_URL}/info" 2>&1) || info_response="Connection failed"

echo "  Response: ${info_response}"
result_text+=$'\n'"--- /info response ---"$'\n'
result_text+="${info_response}"$'\n'

if echo "${info_response}" | grep -q "private_ip"; then
    print_vulnerable "/info leaks internal IP address — Can be used to infer network structure"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 4: Vulnerability scan with nuclei (optional)
# ---------------------------------------------------------------------------
# nuclei is a vulnerability scanner from ProjectDiscovery.
# Template-based efficient detection of known vulnerabilities.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 4: nuclei vulnerability scan (optional)${NC}"
echo ""

if require_tool nuclei; then
    echo -e "${BLUE}[*] Running scan with nuclei...${NC}"

    nuclei_output=$(nuclei -u "${TARGET_URL}" \
        -severity critical,high,medium \
        -silent \
        -timeout 10 \
        -retries 1 \
        -no-color 2>&1) || true

    if [[ -n "${nuclei_output}" ]]; then
        echo "${nuclei_output}"
        result_text+=$'\n'"--- nuclei scan results ---"$'\n'
        result_text+="${nuclei_output}"$'\n'

        finding_count=$(echo "${nuclei_output}" | grep -c "" || true)
        print_vulnerable "nuclei detected ${finding_count} vulnerabilities"
    else
        echo -e "  nuclei: No critical vulnerabilities detected"
        result_text+="nuclei: No findings"$'\n'
    fi
else
    echo -e "${YELLOW}  nuclei not found. Install: brew install nuclei${NC}"
    result_text+="nuclei: Skipped since not installed"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 5: Record Config A vs Config B differences
# ---------------------------------------------------------------------------
echo -e "${BOLD}--- Configuration-specific analysis ---${NC}"
result_text+=$'\n'"--- Configuration-specific analysis ---"$'\n'

if [[ "${CONFIG_MODE}" == "public" ]]; then
    print_vulnerable "EC2 responds directly to HTTP — No WAF/ALB filtering"
    print_vulnerable "Attacker knows EC2's IP directly — Target for DDoS attacks"
    print_info "Switching to Config B will have ALB mediate requests and hide EC2's IP"
    result_text+="Config A: Direct EC2 response, no WAF/filtering"$'\n'
else
    print_info "ALB mediates HTTP requests (EC2's IP is not public)"
    print_blocked "EC2 has no Public IP, so direct access is impossible"
    print_info "Adding WAF rules to ALB can further strengthen defenses"
    result_text+="Config B: Via ALB, EC2's IP is not public"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "Web scan complete"
