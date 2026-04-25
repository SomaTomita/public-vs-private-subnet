#!/usr/bin/env bash
# =============================================================================
# 06_outbound_check.sh — EC2 outbound communication check
# =============================================================================
# Purpose:
#   Log in to EC2 instance via SSH or SSM and check which path
#   outbound communication takes.
#
# Learning points:
#   - Config A (Public): EC2 goes directly to the internet via IGW.
#     External IP is EC2's Public IP.If an attacker plants C2 (Command & Control) server
#     communication, unrestricted external communication is possible.
#   - Config B (Private): EC2 goes to the internet via NAT Gateway.
#     External IP is NAT Gateway's EIP.Connection tracking is possible at NAT GW.
#     Additionally, suspicious traffic is easier to detect with VPC flow logs.
#
# Execution method:
#   - Config A: Log in to EC2 using SSH key
#   - Config B: Send commands to EC2 via SSM Session Manager
#     (If SSM is not configured, check outbound IP via SSRF)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "06: Outbound Communication Check (Outbound Check)"

RESULT_FILE="06_outbound_check.txt"
result_text=""

echo -e "${BLUE}[*] Checking EC2 instance outbound communication path${NC}"
echo -e "${BLUE}[*] Connecting to external IP check service to get EC2's outbound IP address${NC}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Check outbound IP via SSRF
# ---------------------------------------------------------------------------
# Use /fetch endpoint to make EC2 access an external IP check service.
# This method works for both Config A/B (as long as the app is running).
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 1: Checking external IP via SSRF${NC}"
echo -e "${BLUE}[*] Using /fetch?url=https://checkip.amazonaws.com${NC}"
echo ""

TARGET_URL="http://${ATTACK_TARGET}"
result_text+="--- Outbound IP check via SSRF ---"$'\n'

# Trying multiple IP check services (fallback if one is down)
IP_CHECK_URLS=(
    "https://checkip.amazonaws.com"
    "https://api.ipify.org"
    "https://ifconfig.me/ip"
)

outbound_ip=""
for check_url in "${IP_CHECK_URLS[@]}"; do
    response=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${check_url}" 2>/dev/null) || response=""

    # Check if response is in IP address format
    if echo "${response}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
        outbound_ip=$(echo "${response}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo -e "  ${check_url}"
        echo -e "  → Outbound IP: ${BOLD}${outbound_ip}${NC}"
        result_text+="Service: ${check_url}"$'\n'
        result_text+="Outbound IP: ${outbound_ip}"$'\n'
        break
    fi
done

if [[ -z "${outbound_ip}" ]]; then
    echo -e "${YELLOW}  Failed to check outbound IP via SSRF${NC}"
    echo -e "${YELLOW}  /fetch endpoint may be unavailable or external connections may be blocked${NC}"
    result_text+="Via SSRF: IP check failed"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Check outbound IP via SSH (Config A only)
# ---------------------------------------------------------------------------
# In Config A, EC2 has a Public IP so direct login via SSH key is possible.
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 2: Direct verification via SSH/SSM${NC}"
echo ""

result_text+=$'\n'"--- Verification via SSH/SSM ---"$'\n'

if [[ "${CONFIG_MODE}" == "public" && -n "${APP_PUBLIC_IP}" ]]; then
    echo -e "${BLUE}[*] Config A: Connecting to EC2 via SSH to check outbound IP${NC}"

    if [[ -f "${SSH_KEY_FILE}" ]]; then
        # Running curl on EC2 via SSH
        # -o StrictHostKeyChecking=no: Skipping host key verification for lab environment
        ssh_outbound=$(ssh \
            -i "${SSH_KEY_FILE}" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 \
            -o LogLevel=ERROR \
            "ec2-user@${APP_PUBLIC_IP}" \
            "curl -s https://checkip.amazonaws.com 2>/dev/null || echo 'failed'" \
            2>/dev/null) || ssh_outbound=""

        if echo "${ssh_outbound}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
            ssh_ip=$(echo "${ssh_outbound}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            echo -e "  Outbound IP via SSH: ${BOLD}${ssh_ip}${NC}"
            result_text+="Outbound IP via SSH: ${ssh_ip}"$'\n'

            # In Config A, outbound IP should match Public IP (via IGW)
            if [[ "${ssh_ip}" == "${APP_PUBLIC_IP}" ]]; then
                print_info "Outbound IP = EC2 Public IP (direct via IGW)"
                result_text+="Verdict: Direct via IGW (EC2 Public IP = Outbound IP)"$'\n'
            else
                print_info "Outbound IP differs from Public IP (NAT/Proxy is involved)"
                result_text+="Verdict: Possibly via NAT/Proxy"$'\n'
            fi
        else
            echo -e "${YELLOW}  SSH verification failed: ${ssh_outbound}${NC}"
            result_text+="Via SSH: Verification failed"$'\n'
        fi

        echo ""

        # Also verify the routing table
        echo -e "${BLUE}[*] Checking EC2 routing table:${NC}"
        route_info=$(ssh \
            -i "${SSH_KEY_FILE}" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 \
            -o LogLevel=ERROR \
            "ec2-user@${APP_PUBLIC_IP}" \
            "ip route 2>/dev/null || route -n 2>/dev/null || echo 'route command not available'" \
            2>/dev/null) || route_info=""

        echo "${route_info}"
        result_text+=$'\n'"--- Routing table ---"$'\n'
        result_text+="${route_info}"$'\n'
    else
        echo -e "${YELLOW}  SSH key file not found: ${SSH_KEY_FILE}${NC}"
        result_text+="SSH: No key file"$'\n'
    fi
else
    echo -e "${BLUE}[*] Config B: Direct SSH connection impossible since EC2 has no Public IP${NC}"
    echo -e "${BLUE}[*] Attempting verification via SSM Session Manager...${NC}"
    result_text+="Config B: Direct SSH impossible (no Public IP)"$'\n'

    # Checking if SSM is available
    if require_tool aws; then
        # Retrieve EC2 instance ID (via SSRF)
        instance_id=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null) || instance_id=""

        if [[ -n "${instance_id}" ]] && echo "${instance_id}" | grep -q "^i-"; then
            echo -e "  Instance ID: ${instance_id}"
            echo -e "${BLUE}[*] Checking outbound IP with aws ssm send-command...${NC}"

            # SSM send-command  remote command execution
            ssm_output=$(aws ssm send-command \
                --instance-ids "${instance_id}" \
                --document-name "AWS-RunShellScript" \
                --parameters '{"commands":["curl -s https://checkip.amazonaws.com"]}' \
                --output text \
                --query "Command.CommandId" \
                2>&1) || ssm_output=""

            if [[ -n "${ssm_output}" ]] && ! echo "${ssm_output}" | grep -qi "error\|invalid"; then
                echo -e "  SSM command sent successfully. CommandId: ${ssm_output}"
                echo -e "${YELLOW}  Retrieving results may take a few seconds...${NC}"

                # Wait a moment before retrieving results
                sleep 5

                ssm_result=$(aws ssm get-command-invocation \
                    --command-id "${ssm_output}" \
                    --instance-id "${instance_id}" \
                    --query "StandardOutputContent" \
                    --output text \
                    2>&1) || ssm_result=""

                if echo "${ssm_result}" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
                    ssm_ip=$(echo "${ssm_result}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                    echo -e "  Via SSM Outbound IP: ${BOLD}${ssm_ip}${NC}"
                    result_text+="Via SSM Outbound IP: ${ssm_ip}"$'\n'
                fi
            else
                echo -e "${YELLOW}  SSM command send failed: ${ssm_output}${NC}"
                echo -e "${YELLOW}  SSM Agent may not be configured${NC}"
                result_text+="SSM: Command send failed"$'\n'
            fi
        else
            echo -e "${YELLOW}  Failed to retrieve Instance ID${NC}"
            result_text+="SSM: Failed to retrieve Instance ID"$'\n'
        fi
    else
        echo -e "${YELLOW}  AWS CLI not installed. Skipping SSM verification${NC}"
        result_text+="SSM: AWS CLI not installed"$'\n'
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: Compare with NAT Gateway IP (Config B only)
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Step 3: Outbound IP path analysis${NC}"
echo ""

result_text+=$'\n'"--- Path analysis ---"$'\n'

NAT_GW_EIP=$(tf_output "nat_gw_eip")

if [[ "${CONFIG_MODE}" == "private" && -n "${NAT_GW_EIP}" ]]; then
    echo -e "  NAT Gateway EIP: ${NAT_GW_EIP}"
    result_text+="NAT Gateway EIP: ${NAT_GW_EIP}"$'\n'

    if [[ -n "${outbound_ip}" && "${outbound_ip}" == "${NAT_GW_EIP}" ]]; then
        print_info "Outbound IP = NAT Gateway EIP (NAT routing confirmed)"
        result_text+="Verdict: Via NAT Gateway (confirmed)"$'\n'
    elif [[ -n "${outbound_ip}" ]]; then
        print_info "Outbound IP (${outbound_ip}) != NAT GW EIP (${NAT_GW_EIP})"
        result_text+="Verdict: Outbound IP does not match NAT GW EIP"$'\n'
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Result Summary
# ---------------------------------------------------------------------------
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Outbound Communication Summary (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "  ${RED}Config A risks:${NC}"
    echo -e "    - EC2's Public IP is used directly as outbound IP"
    echo -e "    - If attacker compromises EC2, C2 server communication is unrestricted"
    echo -e "    - Filtering outbound traffic is difficult"
    echo -e "    - Tracking via VPC flow logs is possible but not consolidated to a single IP"
    print_vulnerable "External communication from EC2 is unrestricted via direct IGW"
else
    echo -e "  ${GREEN}Config B defenses:${NC}"
    echo -e "    - EC2's outbound traffic is consolidated through NAT Gateway"
    echo -e "    - NAT GW IP is fixed, making traffic destination control and monitoring easy"
    echo -e "    - VPC flow logs can centrally monitor traffic through NAT GW"
    echo -e "    - Network Firewall can be added in the future for filtering"
    print_blocked "Outbound traffic can be centrally managed via NAT GW"
fi

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "Outbound communication check complete"
