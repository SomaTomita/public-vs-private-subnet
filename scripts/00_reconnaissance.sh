#!/usr/bin/env bash
# =============================================================================
# 00_reconnaissance.sh — Reconnaissance phase: How attackers discover targets
# =============================================================================
# Purpose:
#   Reproduce the process of "discovering a target" from an attacker's perspective.
#   Attackers don't know the IP or DNS name from the start.
#   Experience how "discoverability" changes between Public and Private Subnets.
#
# How real attackers discover targets:
#   1. Shodan / Censys: Databases from scanning the entire internet. Servers with Public IPs get indexed
#   2. DNS enumeration: Brute-force discovery of subdomains for a domain
#   3. Certificate Transparency logs: Discover domains from SSL certificate issuance records
#   4. AWS-specific: Scan EC2 IP ranges (public info), guess S3 bucket names
#   5. OSINT: Credential/config file leaks on GitHub, etc.
#
# Config A vs B difference:
#   Config A: EC2 is assigned a Public IP
#     -> Shodan/Censys crawlers automatically scan and index it
#     -> Discoverable by scanning AWS EC2 IP ranges (public info)
#     -> Appears on Shodan within hours to days of EC2 launch
#
#   Config B: EC2 has no Public IP
#     -> EC2 itself is invisible from the internet (IP doesn't exist)
#     -> ALB DNS name (*.elb.amazonaws.com) is random and hard to guess
#     -> Only discoverable via DNS enumeration if a custom domain is configured
#     -> Even if ALB is found, the EC2 IP behind it is hidden
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "00: Reconnaissance Phase — How attackers discover targets"

RESULT_FILE="00_reconnaissance.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"

# =============================================================================
# Step 1: Collect IP/DNS information about the target (attacker's first step)
# =============================================================================
echo -e "${BOLD}--- Step 1: Target IP/DNS resolution ---${NC}"
echo ""

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "${BLUE}[*] Config A: Target is EC2 Public IP (${ATTACK_TARGET})${NC}"
    echo ""

    # Reverse DNS for Public IP
    echo -e "${BLUE}[*] Checking reverse DNS (PTR)...${NC}"
    ptr_result=$(dig -x "${ATTACK_TARGET}" +short 2>/dev/null || echo "none")
    echo "  PTR: ${ptr_result}"

    # Check if IP belongs to AWS EC2 IP range
    # AWS publishes their IP ranges: https://ip-ranges.amazonaws.com/ip-ranges.json
    echo ""
    echo -e "${BLUE}[*] Checking if this IP belongs to AWS EC2 IP range...${NC}"
    echo "  -> EC2 Public IPs have reverse DNS pointing to ec2.ap-northeast-1.compute.amazonaws.com"
    echo "  -> Attackers can immediately identify this as an AWS EC2 instance"
    if echo "${ptr_result}" | grep -q "amazonaws.com"; then
        print_vulnerable "Reverse DNS reveals this is an AWS EC2 instance"
        result_text+="PTR_RECORD: ${ptr_result} -> Identified as AWS EC2\n"
    else
        result_text+="PTR_RECORD: ${ptr_result}\n"
    fi

    echo ""
    echo -e "${YELLOW}[!] Real attacker behavior:${NC}"
    echo "  1. Search Shodan for this IP -> Open ports, banners, OS are displayed"
    echo "  2. Search Censys for this IP -> TLS certificates, HTTP headers are displayed"
    echo "  3. Bulk-scan AWS EC2 IP ranges (public info) and discover this IP"
    echo "  4. EC2 is captured by Shodan crawlers within hours of launch"
    result_text+="DISCOVERY: Public IP gets indexed in external scan DBs (Shodan/Censys)\n"

else
    echo -e "${BLUE}[*] Config B: Target is ALB DNS name (${ATTACK_TARGET})${NC}"
    echo ""

    # Resolve ALB DNS name
    echo -e "${BLUE}[*] Resolving ALB DNS name...${NC}"
    alb_ips=$(dig +short "${ATTACK_TARGET}" 2>/dev/null || echo "unresolvable")
    echo "  ALB IPs: ${alb_ips}"
    result_text+="ALB_DNS: ${ATTACK_TARGET}\n"
    result_text+="ALB_IPS: ${alb_ips}\n"

    echo ""
    echo -e "${BLUE}[*] Can EC2's Private IP be inferred from ALB's IP?${NC}"
    echo "  -> Impossible. ALB is an L7 proxy that separates communication with the backend EC2"
    echo "  -> EC2's Private IP (${APP_PRIVATE_IP}) is completely invisible from outside"
    print_blocked "EC2's Private IP cannot be discovered externally"
    result_text+="EC2_DISCOVERY: Impossible — Private IP only (${APP_PRIVATE_IP})\n"

    echo ""
    echo -e "${YELLOW}[!] Real attacker behavior:${NC}"
    echo "  1. *.elb.amazonaws.com DNS names are random -> Brute-force discovery is impractical"
    echo "  2. If a custom domain is configured, it can be found via DNS enumeration (subfinder, etc.)"
    echo "  3. Even if found, only ALB's IP is visible. EC2 itself is unreachable"
    echo "  4. Shodan indexes ALB IPs (AWS-managed), but not the EC2"
    result_text+="DISCOVERY: ALB DNS name is random. EC2 is not indexed on Shodan, etc.\n"
fi

# =============================================================================
# Step 2: Information gathering via Shodan API (simulation)
# =============================================================================
echo ""
echo -e "${BOLD}--- Step 2: Information gathering via Shodan/Censys (simulation) ---${NC}"
echo ""

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "${BLUE}[*] Expected results when searching ${ATTACK_TARGET} on Shodan:${NC}"
    echo ""

    # Simple check if ports are actually open (instead of nmap)
    declare -A port_results
    for port in 22 80 443 5432 8080; do
        if (echo >/dev/tcp/"${ATTACK_TARGET}"/"${port}") 2>/dev/null; then
            port_results[$port]="open"
        else
            port_results[$port]="closed/filtered"
        fi
    done

    echo "  IP: ${ATTACK_TARGET}"
    echo "  Organization: Amazon.com (AWS)"
    echo "  Ports:"
    for port in 22 80 443 5432 8080; do
        status="${port_results[$port]:-closed/filtered}"
        if [[ "$status" == "open" ]]; then
            echo -e "    ${RED}${port}/tcp  open${NC}"
        else
            echo -e "    ${GREEN}${port}/tcp  ${status}${NC}"
        fi
    done

    # HTTP banner retrieval
    echo ""
    echo -e "${BLUE}[*] Retrieving HTTP banner...${NC}"
    http_banner=$(curl -sI "http://${ATTACK_TARGET}" --connect-timeout 5 2>/dev/null | head -10 || echo "Connection failed")
    echo "${http_banner}"
    result_text+="HTTP_BANNER:\n${http_banner}\n"

    # SSH banner retrieval (if port 22 is open)
    if [[ "${port_results[22]:-}" == "open" ]]; then
        echo ""
        echo -e "${BLUE}[*] Retrieving SSH banner...${NC}"
        ssh_banner=$(echo "" | nc -w 3 "${ATTACK_TARGET}" 22 2>/dev/null | head -1 || echo "Retrieval failed")
        echo "  SSH Banner: ${ssh_banner}"
        print_vulnerable "Server OS/version can be inferred from SSH banner"
        result_text+="SSH_BANNER: ${ssh_banner}\n"
    fi

    echo ""
    print_vulnerable "Open ports, banners, and OS info are revealed just by searching Shodan"
    result_text+="SHODAN_EXPOSURE: High — All public ports and banners are indexed\n"

else
    echo -e "${BLUE}[*] Expected results when searching ALB (${ATTACK_TARGET}) on Shodan:${NC}"
    echo ""

    # ALB HTTP banner retrieval
    http_banner=$(curl -sI "http://${ATTACK_TARGET}" --connect-timeout 5 2>/dev/null | head -10 || echo "Connection failed")
    echo "  ALB IPs: ${alb_ips}"
    echo "  Organization: Amazon.com (AWS - Elastic Load Balancing)"
    echo "  Ports:"
    echo -e "    ${YELLOW}80/tcp   open  (ALB listener)${NC}"
    echo -e "    ${GREEN}22/tcp   N/A   (ALB does not support SSH)${NC}"
    echo -e "    ${GREEN}5432/tcp N/A   (ALB does not support PostgreSQL)${NC}"
    echo ""
    echo "  HTTP Headers:"
    echo "${http_banner}" | grep -i "^server:" || echo "  Server: awselb/2.0"
    echo ""
    print_blocked "Only ALB info is indexed on Shodan. EC2 OS/banners/ports are invisible"
    result_text+="HTTP_BANNER:\n${http_banner}\n"
    result_text+="SHODAN_EXPOSURE: Low — ALB info only. EC2 is invisible\n"
fi

# =============================================================================
# Step 3: AWS-specific reconnaissance
# =============================================================================
echo ""
echo -e "${BOLD}--- Step 3: AWS-specific reconnaissance techniques ---${NC}"
echo ""

echo -e "${BLUE}[*] Additional techniques attackers use to discover AWS resources:${NC}"
echo ""
echo "  a) AWS public IP range info:"
echo "     https://ip-ranges.amazonaws.com/ip-ranges.json"
echo "     -> IP ranges for EC2, ELB, CloudFront, etc. are all publicly available"
echo "     -> Attackers use this list to target-scan only AWS resources"
echo ""
echo "  b) S3 bucket name guessing:"
echo "     -> If bucket names are predictable (e.g., company-backup), direct access attempts"
echo "     -> This is completely independent of subnet placement"
echo ""
echo "  c) Credential leaks on GitHub:"
echo "     -> Check if .env, terraform.tfvars, AWS CLI config files are committed"
echo "     -> With leaked credentials, all resources are accessible regardless of subnet"

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo ""
    echo -e "${RED}[!] Config A specific risks:${NC}"
    echo "  -> EC2's Public IP is included in AWS's public IP range"
    echo "  -> Discoverable in minutes by bulk-scanning AWS EC2 IP ranges with masscan, etc."
    echo "  -> Example: masscan 13.112.0.0/14 -p80,22,443 --rate 100000"
    result_text+="AWS_RECON: EC2 Public IP is discoverable via AWS IP range scanning\n"
else
    echo ""
    echo -e "${GREEN}[*] Config B specific defenses:${NC}"
    echo "  -> EC2 has no Public IP, so it cannot be discovered via IP range scanning"
    echo "  -> ALB IPs are AWS-managed and change dynamically, making it hard to associate with a specific EC2"
    result_text+="AWS_RECON: EC2 has no Public IP. Not discoverable via IP range scanning\n"
fi

# =============================================================================
# Step 4: Attack Surface summary
# =============================================================================
echo ""
echo -e "${BOLD}--- Step 4: Attack Surface summary ---${NC}"
echo ""

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "${RED}┌─────────────────────────────────────────────────┐${NC}"
    echo -e "${RED}│  Config A: Attack Surface = Large                │${NC}"
    echo -e "${RED}│                                                 │${NC}"
    echo -e "${RED}│  Discovery methods:                             │${NC}"
    echo -e "${RED}│    V Instantly found via Shodan/Censys search   │${NC}"
    echo -e "${RED}│    V Found via AWS IP range scanning            │${NC}"
    echo -e "${RED}│    V Identified as AWS EC2 via reverse DNS      │${NC}"
    echo -e "${RED}│                                                 │${NC}"
    echo -e "${RED}│  Exposed information:                           │${NC}"
    echo -e "${RED}│    V Public IP (permanently associated)         │${NC}"
    echo -e "${RED}│    V List of open ports                         │${NC}"
    echo -e "${RED}│    V SSH banner (OS/version)                    │${NC}"
    echo -e "${RED}│    V HTTP headers (web server type)             │${NC}"
    echo -e "${RED}└─────────────────────────────────────────────────┘${NC}"
    result_text+="ATTACK_SURFACE: Large — Public IP + all ports + banner info exposed\n"
else
    echo -e "${GREEN}┌─────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│  Config B: Attack Surface = Small               │${NC}"
    echo -e "${GREEN}│                                                 │${NC}"
    echo -e "${GREEN}│  Discovery methods:                             │${NC}"
    echo -e "${GREEN}│    ~ Only via DNS enumeration if custom domain  │${NC}"
    echo -e "${GREEN}│    X EC2 not discoverable via IP range scan     │${NC}"
    echo -e "${GREEN}│    X ALB DNS name is random, hard to guess      │${NC}"
    echo -e "${GREEN}│                                                 │${NC}"
    echo -e "${GREEN}│  Exposed information:                           │${NC}"
    echo -e "${GREEN}│    ~ ALB IP (dynamic, unrelated to EC2)         │${NC}"
    echo -e "${GREEN}│    ~ HTTP port only                             │${NC}"
    echo -e "${GREEN}│    X EC2 OS/version info is hidden              │${NC}"
    echo -e "${GREEN}│    X SSH port does not exist externally         │${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────┘${NC}"
    result_text+="ATTACK_SURFACE: Small — ALB HTTP only. EC2 info is hidden\n"
fi

# =============================================================================
# Save results
# =============================================================================
echo ""
save_result "${RESULT_FILE}" "$(echo -e "${result_text}")"
echo ""
echo -e "${BOLD}Reconnaissance phase complete. Next step: 01_portscan.sh${NC}"
