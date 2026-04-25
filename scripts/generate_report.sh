#!/usr/bin/env bash
# =============================================================================
# generate_report.sh — Professional Security Assessment Report Generator
# =============================================================================
# Purpose:
#   Generate a comprehensive security assessment report in Markdown format
#   by reading attack results from both Config A and Config B.
#   Includes MITRE ATT&CK mapping, CWE references, and executive summary.
#
# Usage:
#   ./generate_report.sh
#
# Prerequisites:
#   - Run all attacks with Config A: run_all_attacks.sh
#   - Run all attacks with Config B: run_all_attacks.sh
#   - Both results/configA/ and results/configB/ must exist
#
# Output:
#   - results/security_assessment_report.md (Markdown report)
#   - results/security_assessment_report.json (structured data)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_BASE="${PROJECT_ROOT}/results"
DIR_A="${RESULTS_BASE}/configA"
DIR_B="${RESULTS_BASE}/configB"
REPORT_MD="${RESULTS_BASE}/security_assessment_report.md"
REPORT_JSON="${RESULTS_BASE}/security_assessment_report.json"

# ---------------------------------------------------------------------------
# Color definitions (minimal — terminal status messages only)
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Step 1: Validate prerequisites
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Checking result directories...${NC}"

has_a=false
has_b=false

if [[ -d "${DIR_A}" ]] && ls "${DIR_A}"/*.txt &>/dev/null 2>&1; then
    echo -e "  ${GREEN}[OK]${NC} Config A results found: ${DIR_A}"
    has_a=true
else
    echo -e "  ${YELLOW}[--]${NC} Config A results not found: ${DIR_A}"
fi

if [[ -d "${DIR_B}" ]] && ls "${DIR_B}"/*.txt &>/dev/null 2>&1; then
    echo -e "  ${GREEN}[OK]${NC} Config B results found: ${DIR_B}"
    has_b=true
else
    echo -e "  ${YELLOW}[--]${NC} Config B results not found: ${DIR_B}"
fi

if ! $has_a && ! $has_b; then
    echo -e "${RED}[!] No result files found. Please run run_all_attacks.sh first.${NC}"
    exit 1
fi

if ! $has_a || ! $has_b; then
    echo -e "${YELLOW}[!] Only one config's results are available. Generating partial report with warnings.${NC}"
fi

mkdir -p "${RESULTS_BASE}"

# ---------------------------------------------------------------------------
# Step 2: Extract all verdicts
# Bash 3.2 compatible: no associative arrays. Verdicts are stored by Python
# and the comparison table is built inline in the loop below.
# ---------------------------------------------------------------------------
extract_verdict() {
    local file="$1"
    if [[ -f "${file}" ]]; then
        local critical_count vuln_count blocked_count
        critical_count=$(grep -ci "CRITICAL" "${file}" 2>/dev/null; true)
        vuln_count=$(grep -ci "VULNERABLE" "${file}" 2>/dev/null; true)
        blocked_count=$(grep -ci "BLOCKED" "${file}" 2>/dev/null; true)
        # Trim to first word in case grep emits extra output on some platforms
        critical_count="${critical_count%%[^0-9]*}"
        vuln_count="${vuln_count%%[^0-9]*}"
        blocked_count="${blocked_count%%[^0-9]*}"
        critical_count="${critical_count:-0}"
        vuln_count="${vuln_count:-0}"
        blocked_count="${blocked_count:-0}"
        if [[ ${critical_count} -gt 0 ]]; then echo "CRITICAL"
        elif [[ ${vuln_count} -gt 0 ]]; then echo "VULNERABLE"
        elif [[ ${blocked_count} -gt 0 ]]; then echo "BLOCKED"
        else echo "N/A"
        fi
    else
        echo "Not executed"
    fi
}

# Human-readable name for a test_id (bash 3.2 compatible via case)
test_display_name() {
    local id="$1"
    case "${id}" in
        00_reconnaissance)           echo "Reconnaissance" ;;
        01_portscan)                 echo "Port Scan" ;;
        02_ssh_probe)                echo "SSH Probe" ;;
        03_web_scan)                 echo "Web Scan" ;;
        04_ssrf_metadata)            echo "SSRF / IMDS Attack" ;;
        05_db_probe)                 echo "DB Direct Connection" ;;
        06_outbound_check)           echo "Outbound Communication" ;;
        07_full_kill_chain)          echo "Full Kill Chain" ;;
        08_post_exploitation)        echo "Post-Exploitation" ;;
        09_internal_recon)           echo "Internal Recon" ;;
        10_ssrf_internal_recon)      echo "SSRF Internal Recon" ;;
        11_iam_privilege_escalation) echo "IAM Privilege Escalation" ;;
        12_alb_attacks)              echo "ALB-Specific Attacks" ;;
        13_outbound_c2)              echo "C2 Channel Test" ;;
        14_ssrf_to_rds)              echo "SSRF to RDS Attack" ;;
        15_iam_blast_radius)         echo "IAM Blast Radius" ;;
        16_data_exfiltration)        echo "Data Exfiltration" ;;
        17_persistence_check)        echo "Persistence Mechanisms" ;;
        18_detection_evasion)        echo "Detection Evasion" ;;
        19_quantitative_metrics)     echo "Quantitative Metrics" ;;
        *)                           echo "${id}" ;;
    esac
}

format_risk() {
    local id="$1"
    case "${id}" in
        04_ssrf_metadata)            echo "SSRF via /fetch endpoint exposes IMDS credentials to any attacker" ;;
        07_full_kill_chain)          echo "End-to-end kill chain (SSRF to credentials to lateral movement) succeeded" ;;
        11_iam_privilege_escalation) echo "Overly permissive IAM role allows privilege escalation to full account access" ;;
        15_iam_blast_radius)         echo "Stolen IAM credentials provide broad blast radius across AWS services" ;;
        14_ssrf_to_rds)              echo "SSRF from application layer reaches private RDS bypassing network controls" ;;
        16_data_exfiltration)        echo "Data exfiltration via HTTP/DNS succeeds without egress filtering" ;;
        13_outbound_c2)              echo "Outbound C2 channel established -- no egress controls block callback" ;;
        17_persistence_check)        echo "Attacker can create persistent backdoor accounts / access keys" ;;
        08_post_exploitation)        echo "Post-exploitation enumeration succeeds via stolen cloud credentials" ;;
        00_reconnaissance)           echo "Public infrastructure is directly scannable and enumerable" ;;
        01_portscan)                 echo "Open port exposure increases attack surface for direct exploitation" ;;
        02_ssh_probe)                echo "SSH port exposed directly to internet enables brute-force attacks" ;;
        *)                           echo "Security control gap identified in $(test_display_name "${id}")" ;;
    esac
}

TESTS="00_reconnaissance 01_portscan 02_ssh_probe 03_web_scan 04_ssrf_metadata 05_db_probe 06_outbound_check 07_full_kill_chain 08_post_exploitation 09_internal_recon 10_ssrf_internal_recon 11_iam_privilege_escalation 12_alb_attacks 13_outbound_c2 14_ssrf_to_rds 15_iam_blast_radius 16_data_exfiltration 17_persistence_check 18_detection_evasion 19_quantitative_metrics"

# Collect counters and build per-test verdict data stored in a temp file
# so the comparison table loop can read them without associative arrays.
VERDICT_TMP="$(mktemp /tmp/verdict_data.XXXXXX)"
trap 'rm -f "${VERDICT_TMP}"' EXIT

a_critical=0; a_vuln=0; a_blocked=0; a_na=0
b_critical=0; b_vuln=0; b_blocked=0; b_na=0

for test_id in ${TESTS}; do
    va=$(extract_verdict "${DIR_A}/${test_id}.txt")
    vb=$(extract_verdict "${DIR_B}/${test_id}.txt")

    # 12_alb_attacks is N/A for Config A (no ALB present)
    if [[ "${test_id}" = "12_alb_attacks" && "${va}" = "Not executed" ]]; then
        va="N/A"
    fi

    # Store verdicts as shell variable assignments in temp file
    printf 'va_%s="%s"\nvb_%s="%s"\n' \
        "${test_id}" "${va}" "${test_id}" "${vb}" >> "${VERDICT_TMP}"

    case "${va}" in
        CRITICAL)    a_critical=$((a_critical + 1)) ;;
        VULNERABLE)  a_vuln=$((a_vuln + 1)) ;;
        BLOCKED)     a_blocked=$((a_blocked + 1)) ;;
        *)           a_na=$((a_na + 1)) ;;
    esac

    case "${vb}" in
        CRITICAL)    b_critical=$((b_critical + 1)) ;;
        VULNERABLE)  b_vuln=$((b_vuln + 1)) ;;
        BLOCKED)     b_blocked=$((b_blocked + 1)) ;;
        *)           b_na=$((b_na + 1)) ;;
    esac
done

# Source the stored verdicts so we can access them later
# shellcheck source=/dev/null
. "${VERDICT_TMP}"

# Security score: blocked / (critical + vulnerable + blocked) * 100
a_scored=$((a_critical + a_vuln + a_blocked))
b_scored=$((b_critical + b_vuln + b_blocked))
a_score=0; b_score=0
[ ${a_scored} -gt 0 ] && a_score=$(( (a_blocked * 100) / a_scored ))
[ ${b_scored} -gt 0 ] && b_score=$(( (b_blocked * 100) / b_scored ))

# Top risks: CRITICAL first, then VULNERABLE, up to 3 entries
top_risks=""
top_count=0
for test_id in ${TESTS}; do
    [ ${top_count} -ge 3 ] && break
    va_val=$(eval echo "\${va_${test_id}}")
    vb_val=$(eval echo "\${vb_${test_id}}")
    if [ "${va_val}" = "CRITICAL" ] || [ "${vb_val}" = "CRITICAL" ]; then
        top_risks="${top_risks} ${test_id}"
        top_count=$((top_count + 1))
    fi
done
for test_id in ${TESTS}; do
    [ ${top_count} -ge 3 ] && break
    # skip if already in list
    case " ${top_risks} " in *" ${test_id} "*) continue ;; esac
    va_val=$(eval echo "\${va_${test_id}}")
    vb_val=$(eval echo "\${vb_${test_id}}")
    if [ "${va_val}" = "VULNERABLE" ] || [ "${vb_val}" = "VULNERABLE" ]; then
        top_risks="${top_risks} ${test_id}"
        top_count=$((top_count + 1))
    fi
done

risk1="No significant risks detected"
risk2=""
risk3=""
risk_idx=0
for r in ${top_risks}; do
    risk_idx=$((risk_idx + 1))
    case ${risk_idx} in
        1) risk1="$(format_risk "${r}")" ;;
        2) risk2="$(format_risk "${r}")" ;;
        3) risk3="$(format_risk "${r}")" ;;
    esac
done

# ---------------------------------------------------------------------------
# Step 3: Build partial-report warning block
# ---------------------------------------------------------------------------
partial_warning=""
if ! $has_a; then
    partial_warning='> **WARNING:** Config A (Public subnet) results are missing. This is a partial report based on Config B only.

'
fi
if ! $has_b; then
    partial_warning='> **WARNING:** Config B (Private subnet) results are missing. This is a partial report based on Config A only.

'
fi

# ---------------------------------------------------------------------------
# Step 4: Generate Markdown report
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Generating Markdown report...${NC}"

ASSESSMENT_DATE="$(date '+%Y-%m-%d')"
GENERATED_AT="$(date '+%Y-%m-%d %H:%M:%S UTC')"

# ---- Static header + executive summary ----
cat > "${REPORT_MD}" <<HEREDOC
# Security Assessment Report: AWS Public vs Private Subnet Architecture

${partial_warning}> **Generated:** ${GENERATED_AT}
> **Classification:** Internal / Lab Use Only

---

## Executive Summary

**Assessment Date:** ${ASSESSMENT_DATE}
**Assessment Type:** Gray Box Penetration Test
**Target:** AWS VPC infrastructure with two configurations
**Assessor:** Automated Security Lab (scripts 00-19)

### Key Findings

| Severity | Config A (Public) | Config B (Private) |
|----------|------------------|--------------------|
| CRITICAL | ${a_critical} | ${b_critical} |
| VULNERABLE | ${a_vuln} | ${b_vuln} |
| BLOCKED | ${a_blocked} | ${b_blocked} |
| N/A / Not executed | ${a_na} | ${b_na} |

**Overall Security Score:**
- Config A: ${a_score}/100 (${a_blocked} of ${a_scored} evaluated tests blocked)
- Config B: ${b_score}/100 (${b_blocked} of ${b_scored} evaluated tests blocked)

**Top 3 Risks:**
1. ${risk1}
HEREDOC

[ -n "${risk2}" ] && printf '2. %s\n' "${risk2}" >> "${REPORT_MD}"
[ -n "${risk3}" ] && printf '3. %s\n' "${risk3}" >> "${REPORT_MD}"

# ---- Methodology section (static — single-quoted heredoc, no interpolation) ----
cat >> "${REPORT_MD}" <<'HEREDOC'

---

## 1. Assessment Methodology

### 1.1 Scope

- **Config A (Public):** EC2 instance directly exposed to internet with a public IP address. Security groups allow inbound HTTP(S) and optionally SSH from any source.
- **Config B (Private):** EC2 instance placed in a private subnet behind an Application Load Balancer (ALB). Outbound internet access is via a NAT Gateway. No public IP assigned to the EC2.

### 1.2 Tools Used

| Tool | Purpose |
|------|---------|
| Custom bash scripts (00-19) | Automated attack simulation across MITRE ATT&CK tactics |
| curl | HTTP endpoint probing, SSRF exploitation, header injection |
| AWS CLI | IAM credential validation, cloud resource enumeration |
| nmap / nc | Port scanning and service discovery (where available) |
| python3 | JSON parsing, report generation |

### 1.3 MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name | Scripts |
|--------|-------------|----------------|---------|
| Reconnaissance | T1595 | Active Scanning | 00, 01 |
| Initial Access | T1190 | Exploit Public-Facing Application | 03, 04, 12 |
| Credential Access | T1552.005 | Cloud Instance Metadata API | 04, 07, 10 |
| Privilege Escalation | T1078.004 | Valid Accounts: Cloud Accounts | 11, 15 |
| Discovery | T1046 | Network Service Discovery | 01, 02, 05, 09, 10 |
| Discovery | T1580 | Cloud Infrastructure Discovery | 07, 10, 15 |
| Lateral Movement | T1021 | Remote Services | 14 |
| Collection | T1530 | Data from Cloud Storage | 11, 15 |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | 13, 16 |
| Command and Control | T1071.001 | Application Layer Protocol | 13 |
| Persistence | T1136.003 | Create Account: Cloud Account | 17 |
| Defense Evasion | T1562.007 | Impair Defenses: Cloud Firewall | 17 |

---

## 2. Findings Detail

### Finding F-001: SSRF to IMDS Credential Theft

**Severity:** CRITICAL
**CWE:** CWE-918 (Server-Side Request Forgery)
**MITRE ATT&CK:** T1552.005 — Cloud Instance Metadata API
**Scripts:** 04, 07, 10
**Affected configs:** Config A and Config B (network architecture does not mitigate)

**Description:**
The vulnerable application exposes a `/fetch` endpoint that proxies arbitrary URLs without validation. An attacker can direct this endpoint at the EC2 Instance Metadata Service (IMDS) at `169.254.169.254` to retrieve the attached IAM role name and its temporary credentials (`AccessKeyId`, `SecretAccessKey`, `Token`). Because IMDS is accessed from within the EC2 instance (via the application), network perimeter controls (private subnet, ALB) have no effect — the request originates from a trusted internal host.

**Attack chain:**
```
Attacker  ->  ALB / EC2 public IP
          ->  GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
          ->  Returns IAM role name
          ->  GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
          ->  Returns AccessKeyId + SecretAccessKey + Token
          ->  Attacker uses credentials via AWS CLI / SDK from any IP worldwide
```

**Impact:**
Full AWS account compromise. The IAM role attached to EC2 typically has broad permissions (S3 read/write, EC2 describe, RDS access, CloudWatch logs). Stolen credentials operate via the AWS control plane and are valid from any IP address.

**Remediation:**
1. Enforce IMDSv2 in Terraform: `metadata_options { http_tokens = "required" http_endpoint = "enabled" }` — IMDSv2 requires a session-oriented PUT token that SSRF via GET cannot obtain.
2. Remove or restrict the `/fetch` endpoint; implement strict URL allowlisting if the feature is necessary.
3. Add AWS WAF rule blocking requests containing `169.254.169.254` in any parameter.
4. Apply least-privilege IAM: the EC2 role should only have the minimum permissions required by the application.

---

### Finding F-002: Overly Permissive IAM Role (Blast Radius)

**Severity:** CRITICAL
**CWE:** CWE-250 (Execution with Unnecessary Privileges)
**MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts; T1580 — Cloud Infrastructure Discovery
**Scripts:** 11, 15
**Affected configs:** Config A and Config B

**Description:**
The IAM role attached to the EC2 instance is granted broad permissions that exceed application requirements. Once temporary credentials are stolen (see F-001), an attacker can enumerate and access S3 buckets, describe EC2/RDS infrastructure, read CloudWatch logs, and potentially create new IAM users or access keys for persistent access.

**Impact:**
Data exfiltration from S3, full infrastructure enumeration, potential for persistent backdoor creation, and lateral movement to other AWS services outside VPC scope.

**Remediation:**
1. Apply least-privilege IAM: create a custom policy granting only the specific actions and resources the application needs.
2. Use IAM Access Analyzer to identify overly-permissive policies.
3. Apply Service Control Policies (SCPs) at the AWS Organization level to enforce maximum permission boundaries.
4. Add `aws:SourceVpc` or `aws:SourceVpce` conditions to restrict where credentials can be used from.
5. Enable AWS GuardDuty to detect anomalous credential usage (unusual API calls, calls from unexpected IPs).

---

### Finding F-003: No Egress Filtering (Data Exfiltration / C2)

**Severity:** HIGH
**CWE:** CWE-284 (Improper Access Control)
**MITRE ATT&CK:** T1048 — Exfiltration Over Alternative Protocol; T1071.001 — Application Layer Protocol
**Scripts:** 06, 13, 16
**Affected configs:** Config A and Config B

**Description:**
Neither configuration implements outbound traffic filtering. Egress security groups allow unrestricted outbound internet access. An attacker who has code execution on the EC2 (or exploits SSRF) can exfiltrate sensitive data via HTTP(S), DNS, or ICMP tunnels, and establish reverse C2 channels back to attacker-controlled infrastructure.

**Impact:**
Sensitive data (credentials, database content, S3 objects) can be exfiltrated over any protocol. Reverse shells and C2 frameworks can be established from the compromised instance.

**Remediation:**
1. Restrict egress security group rules to only required destinations and ports (e.g., 443 to specific AWS service CIDRs).
2. Deploy VPC Network Firewall with domain-based egress rules to allowlist approved destinations.
3. Enable Route 53 Resolver DNS Firewall to block DNS queries to known-malicious or uncategorized domains.
4. Create S3 VPC Endpoint with resource-based policy to restrict S3 access to approved buckets only.
5. Consider deploying an egress proxy (e.g., Squid with TLS inspection) for application-layer visibility.

---

### Finding F-004: Direct Infrastructure Exposure (Config A Only)

**Severity:** HIGH
**CWE:** CWE-693 (Protection Mechanism Failure)
**MITRE ATT&CK:** T1595 — Active Scanning; T1190 — Exploit Public-Facing Application
**Scripts:** 00, 01, 02, 03
**Affected configs:** Config A only (mitigated by private subnet in Config B)

**Description:**
In Config A, the EC2 instance has a public IP address and is directly routable from the internet. Port scanning reveals all open ports (HTTP, SSH, application ports). SSH is directly accessible, enabling brute-force or credential-stuffing attacks. Web scanning exposes application structure, version information, and potential vulnerability endpoints.

**Impact:**
Larger attack surface for exploitation. SSH exposure enables direct brute-force attacks. Information leakage from web scan results helps attackers target specific vulnerabilities.

**Remediation (achieved by Config B):**
1. Place EC2 in a private subnet with no public IP (implemented in Config B).
2. Route external HTTP(S) traffic through ALB only.
3. Enforce SSH access via AWS Systems Manager Session Manager (no port 22 required).
4. Restrict security group inbound rules to ALB security group ID only.

---

### Finding F-005: Sensitive Information Disclosure via /info Endpoint

**Severity:** MEDIUM
**CWE:** CWE-200 (Exposure of Sensitive Information to Unauthorized Actor)
**MITRE ATT&CK:** T1595 — Active Scanning
**Scripts:** 03, 09
**Affected configs:** Config A and Config B

**Description:**
The application's `/info` or debug endpoints expose instance metadata, environment variables, internal IP addresses, and potentially application configuration. This information aids attackers in targeting subsequent attacks.

**Remediation:**
1. Disable debug endpoints in production environments.
2. Implement environment-specific configuration (`APP_ENV=production` disables `/info`).
3. If health check endpoints are required, restrict content to status code only.

---

### Finding F-006: No TLS / HTTPS Enforcement

**Severity:** MEDIUM
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)
**MITRE ATT&CK:** T1040 — Network Sniffing
**Scripts:** 03, 12
**Affected configs:** Config A and Config B

**Description:**
Application traffic is served over HTTP without TLS encryption. In Config A, this affects direct EC2 communication. In Config B, the ALB listener is HTTP-only. Credentials, session tokens, and sensitive data are transmitted in cleartext.

**Remediation:**
1. Add HTTPS listener to ALB with ACM certificate.
2. Add HTTP-to-HTTPS redirect rule on the ALB.
3. Enforce HSTS headers in the application.
4. Use AWS Certificate Manager (ACM) for free, auto-renewing certificates.

---

### Finding F-007: Secrets in EC2 User Data

**Severity:** MEDIUM
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
**MITRE ATT&CK:** T1552 — Unsecured Credentials
**Scripts:** 08
**Affected configs:** Config A and Config B

**Description:**
If application secrets (database passwords, API keys) are passed via EC2 user data, they are stored in plaintext and accessible to any identity that can call `ec2:DescribeInstanceAttribute`. IMDS also exposes user data without authentication under IMDSv1.

**Remediation:**
1. Store secrets in AWS Secrets Manager or SSM Parameter Store (SecureString).
2. Grant the EC2 IAM role `secretsmanager:GetSecretValue` permission for specific secret ARNs only.
3. Never pass secrets via user data, environment variables baked into AMIs, or CloudFormation parameters in plaintext.

HEREDOC

# ---- Section 3: Comparison matrix header (dynamic vars needed for scores) ----
cat >> "${REPORT_MD}" <<HEREDOC
---

## 3. Config A vs Config B Comparison

### 3.1 Attack Results by Test

| # | Test Name | Config A (Public) | Config B (Private) | Improvement |
|---|-----------|------------------|--------------------|-------------|
HEREDOC

# Build comparison rows dynamically
for test_id in ${TESTS}; do
    num="${test_id%%_*}"
    name="$(test_display_name "${test_id}")"
    va_val=$(eval echo "\${va_${test_id}}")
    vb_val=$(eval echo "\${vb_${test_id}}")

    improvement="--"
    if [ "${va_val}" = "CRITICAL" ] || [ "${va_val}" = "VULNERABLE" ]; then
        if [ "${vb_val}" = "BLOCKED" ]; then
            improvement="YES -- private subnet effective"
        elif [ "${vb_val}" = "CRITICAL" ] || [ "${vb_val}" = "VULNERABLE" ]; then
            improvement="NO -- app/IAM layer issue"
        fi
    elif [ "${va_val}" = "BLOCKED" ] && [ "${vb_val}" = "BLOCKED" ]; then
        improvement="N/A -- already blocked"
    elif [ "${va_val}" = "N/A" ]; then
        improvement="N/A -- not applicable"
    fi

    printf '| %s | %s | %s | %s | %s |\n' \
        "${num}" "${name}" "${va_val}" "${vb_val}" "${improvement}" >> "${REPORT_MD}"
done

# Score summary and layer analysis (dynamic)
cat >> "${REPORT_MD}" <<HEREDOC

**Score summary:**
- Config A security score: **${a_score}/100** (${a_blocked} blocked / ${a_scored} evaluated)
- Config B security score: **${b_score}/100** (${b_blocked} blocked / ${b_scored} evaluated)

### 3.2 Layer Analysis

| Security Layer | Config A | Config B | Private Subnet Effective? |
|----------------|----------|----------|--------------------------|
| Network Boundary (direct port exposure, SSH) | VULNERABLE | BLOCKED | YES |
| Web Application (SSRF, injection, scanning) | VULNERABLE | VULNERABLE | NO |
| AWS Credentials / IMDS | VULNERABLE | VULNERABLE | NO |
| IAM Blast Radius | VULNERABLE | VULNERABLE | NO |
| Lateral Movement (SSRF to RDS) | VULNERABLE | VULNERABLE | NO |
| Data Exfiltration / Egress | VULNERABLE | VULNERABLE | NO |
| Outbound C2 | VULNERABLE | VULNERABLE | NO |
| ALB-Specific Attacks | N/A | MEDIUM | NEW SURFACE |
| Detection / Visibility | LOW | MEDIUM | MIXED |

**Key insight:** Private subnet architecture effectively reduces the **network boundary** attack surface (ports, SSH, direct IP targeting) but does not mitigate **application-layer** (SSRF, injection) or **AWS control-plane** (IAM, credentials) vulnerabilities. Defense-in-depth requires addressing all layers independently.

HEREDOC

# ---- Remediation roadmap (static) ----
cat >> "${REPORT_MD}" <<'HEREDOC'
---

## 4. Remediation Roadmap

### Immediate Actions (Week 1) -- Zero / Low Cost

| Action | Addresses | Effort | Est. Cost |
|--------|-----------|--------|-----------|
| Enforce IMDSv2 (`http_tokens = "required"`) | F-001 CRITICAL | Low (1 Terraform line) | $0 |
| Remove or restrict `/fetch` endpoint | F-001 CRITICAL | Low (app code change) | $0 |
| Apply least-privilege IAM role policy | F-002 CRITICAL | Medium (policy authoring) | $0 |
| Restrict egress security group rules | F-003 HIGH | Low (SG rule update) | $0 |
| Disable debug/info endpoints in production | F-005 MEDIUM | Low (env config) | $0 |

### Short-Term Actions (Month 1) -- Low Cost

| Action | Addresses | Effort | Est. Cost |
|--------|-----------|--------|-----------|
| Enable AWS GuardDuty | F-002, detection | Low (1-click enable) | ~$2-5/mo |
| Deploy AWS WAF on ALB (block metadata IP patterns) | F-001, F-004 | Medium | ~$5-20/mo |
| Add HTTPS listener to ALB with ACM certificate | F-006 | Low | $0 (ACM free) |
| Migrate secrets to AWS Secrets Manager | F-007 | Medium | ~$0.40/secret/mo |
| Enable AWS CloudTrail for all regions | Forensics | Low | ~$2/mo |
| Enable VPC Flow Logs (if not already active) | Detection | Low | ~$1-3/mo |

### Medium-Term Actions (Quarter 1) -- Moderate Cost

| Action | Addresses | Effort | Est. Cost |
|--------|-----------|--------|-----------|
| Deploy VPC Network Firewall (egress domain filtering) | F-003 HIGH | High (architecture change) | ~$300/mo |
| Route 53 Resolver DNS Firewall | F-003 (DNS exfil) | Medium | ~$2/mo |
| S3 VPC Endpoint + bucket policy restricting source VPC | F-003, F-002 | Medium | $0 |
| AWS Systems Manager Session Manager (replace SSH) | F-004 | Medium | $0 |
| IAM Access Analyzer -- continuous policy analysis | F-002 | Low | $0 |
| Enable AWS Security Hub (CIS benchmark) | All | Low | ~$2-5/mo |

### Long-Term / Strategic

| Action | Addresses | Effort | Est. Cost |
|--------|-----------|--------|-----------|
| Implement Service Control Policies (SCPs) at Org level | F-002 | High | $0 |
| Adopt AWS PrivateLink for all service-to-service comms | F-003 | High | Variable |
| Container/ECS migration with task-level IAM roles | F-001, F-002 | Very High | Variable |
| Runtime security (Falco or Amazon Inspector) | All | High | ~$20-100/mo |

HEREDOC

# ---- Appendices (static) ----
cat >> "${REPORT_MD}" <<'HEREDOC'
---

## Appendix A: CWE Reference

| CWE ID | Name | Findings |
|--------|------|---------|
| CWE-918 | Server-Side Request Forgery (SSRF) | F-001 |
| CWE-522 | Insufficiently Protected Credentials | F-001 (IMDSv1) |
| CWE-250 | Execution with Unnecessary Privileges | F-002 |
| CWE-284 | Improper Access Control | F-003 |
| CWE-693 | Protection Mechanism Failure | F-003, F-004 |
| CWE-200 | Exposure of Sensitive Information | F-005 |
| CWE-319 | Cleartext Transmission of Sensitive Information | F-006 |
| CWE-312 | Cleartext Storage of Sensitive Information | F-007 |

---

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| ALB | Application Load Balancer -- AWS managed L7 load balancer |
| IMDS | Instance Metadata Service -- EC2 endpoint at 169.254.169.254 providing instance info and IAM credentials |
| IMDSv2 | IMDS version 2 -- session-oriented, requires PUT token before GET, mitigates SSRF-based credential theft |
| NAT Gateway | AWS managed outbound-only internet gateway for private subnets |
| SSRF | Server-Side Request Forgery -- attacker tricks server into making HTTP requests to internal resources |
| IAM | Identity and Access Management -- AWS permission system |
| SCP | Service Control Policy -- AWS Organizations guardrail applied to entire accounts/OUs |
| VPC | Virtual Private Cloud -- isolated network environment in AWS |
| WAF | Web Application Firewall -- filters malicious HTTP requests |
| GuardDuty | AWS threat detection service using ML and threat intelligence |

---

## Appendix C: Test Script Reference

| Script | Name | Primary MITRE Tactic |
|--------|------|---------------------|
| 00_reconnaissance.sh | Reconnaissance | T1595 Active Scanning |
| 01_portscan.sh | Port Scan | T1046 Network Service Discovery |
| 02_ssh_probe.sh | SSH Probe | T1110 Brute Force |
| 03_web_scan.sh | Web Scan | T1190 Exploit Public-Facing App |
| 04_ssrf_metadata.sh | SSRF / IMDS | T1552.005 Cloud Metadata API |
| 05_db_probe.sh | DB Direct Connection | T1046 Network Service Discovery |
| 06_outbound_check.sh | Outbound Communication | T1048 Exfiltration |
| 07_full_kill_chain.sh | Full Kill Chain | Multiple |
| 08_post_exploitation.sh | Post-Exploitation | T1580 Cloud Infrastructure Discovery |
| 09_internal_recon.sh | Internal Recon | T1046 Network Service Discovery |
| 10_ssrf_internal_recon.sh | SSRF Internal Recon | T1580 Cloud Infrastructure Discovery |
| 11_iam_privilege_escalation.sh | IAM Privilege Escalation | T1078.004 Valid Cloud Accounts |
| 12_alb_attacks.sh | ALB-Specific Attacks | T1190 Exploit Public-Facing App |
| 13_outbound_c2.sh | C2 Channel Test | T1071.001 Application Layer Protocol |
| 14_ssrf_to_rds.sh | SSRF to RDS | T1021 Remote Services |
| 15_iam_blast_radius.sh | IAM Blast Radius | T1530 Data from Cloud Storage |
| 16_data_exfiltration.sh | Data Exfiltration | T1048 Exfiltration |
| 17_persistence_check.sh | Persistence Mechanisms | T1136.003 Create Cloud Account |
| 18_detection_evasion.sh | Detection Evasion | T1562.007 Impair Cloud Firewall |
| 19_quantitative_metrics.sh | Quantitative Metrics | N/A (measurement) |

---

*Report generated by `scripts/generate_report.sh` -- AWS Public vs Private Subnet Security Lab*
HEREDOC

# ---------------------------------------------------------------------------
# Step 7: Generate JSON report via Python
# ---------------------------------------------------------------------------
echo -e "${BLUE}[*] Generating JSON report...${NC}"

python3 << PYEOF > "${REPORT_JSON}"
import json
import os
import re
from datetime import datetime, timezone

dir_a = "${DIR_A}"
dir_b = "${DIR_B}"

tests = [
    ("00", "00_reconnaissance",           "Reconnaissance",              "T1595",     "Reconnaissance"),
    ("01", "01_portscan",                 "Port Scan",                   "T1046",     "Discovery"),
    ("02", "02_ssh_probe",                "SSH Probe",                   "T1110",     "Credential Access"),
    ("03", "03_web_scan",                 "Web Scan",                    "T1190",     "Initial Access"),
    ("04", "04_ssrf_metadata",            "SSRF / IMDS Attack",          "T1552.005", "Credential Access"),
    ("05", "05_db_probe",                 "DB Direct Connection",        "T1046",     "Discovery"),
    ("06", "06_outbound_check",           "Outbound Communication",      "T1048",     "Exfiltration"),
    ("07", "07_full_kill_chain",          "Full Kill Chain",             "T1190",     "Initial Access"),
    ("08", "08_post_exploitation",        "Post-Exploitation",           "T1580",     "Discovery"),
    ("09", "09_internal_recon",           "Internal Recon",              "T1046",     "Discovery"),
    ("10", "10_ssrf_internal_recon",      "SSRF Internal Recon",         "T1580",     "Discovery"),
    ("11", "11_iam_privilege_escalation", "IAM Privilege Escalation",    "T1078.004", "Privilege Escalation"),
    ("12", "12_alb_attacks",              "ALB-Specific Attacks",        "T1190",     "Initial Access"),
    ("13", "13_outbound_c2",              "C2 Channel Test",             "T1071.001", "Command and Control"),
    ("14", "14_ssrf_to_rds",              "SSRF to RDS Attack",          "T1021",     "Lateral Movement"),
    ("15", "15_iam_blast_radius",         "IAM Blast Radius",            "T1530",     "Collection"),
    ("16", "16_data_exfiltration",        "Data Exfiltration",           "T1048",     "Exfiltration"),
    ("17", "17_persistence_check",        "Persistence Mechanisms",      "T1136.003", "Persistence"),
    ("18", "18_detection_evasion",        "Detection Evasion",           "T1562.007", "Defense Evasion"),
    ("19", "19_quantitative_metrics",     "Quantitative Metrics",        "N/A",       "Measurement"),
]

def extract_verdict(filepath):
    if not os.path.isfile(filepath):
        return "Not executed"
    try:
        content = open(filepath, "r", errors="replace").read()
        if re.search(r"CRITICAL", content, re.IGNORECASE):
            return "CRITICAL"
        if re.search(r"VULNERABLE", content, re.IGNORECASE):
            return "VULNERABLE"
        if re.search(r"BLOCKED", content, re.IGNORECASE):
            return "BLOCKED"
        return "N/A"
    except Exception:
        return "Not executed"

def tally(v, s):
    if v == "CRITICAL":
        s["critical"] += 1
    elif v == "VULNERABLE":
        s["vulnerable"] += 1
    elif v == "BLOCKED":
        s["blocked"] += 1
    else:
        s["na"] += 1

def calc_score(s):
    total = s["critical"] + s["vulnerable"] + s["blocked"]
    if total == 0:
        return 0
    return round((s["blocked"] / total) * 100)

test_results = []
summary_a = {"critical": 0, "vulnerable": 0, "blocked": 0, "na": 0}
summary_b = {"critical": 0, "vulnerable": 0, "blocked": 0, "na": 0}

for num, test_id, name, mitre, tactic in tests:
    fa = os.path.join(dir_a, test_id + ".txt")
    fb = os.path.join(dir_b, test_id + ".txt")
    va = extract_verdict(fa)
    vb = extract_verdict(fb)

    if test_id == "12_alb_attacks" and va == "Not executed":
        va = "N/A"

    tally(va, summary_a)
    tally(vb, summary_b)

    improvement = "unknown"
    if va in ("CRITICAL", "VULNERABLE") and vb == "BLOCKED":
        improvement = "improved"
    elif va in ("CRITICAL", "VULNERABLE") and vb in ("CRITICAL", "VULNERABLE"):
        improvement = "not_improved"
    elif va == "BLOCKED" and vb == "BLOCKED":
        improvement = "already_blocked"
    elif va == "N/A":
        improvement = "not_applicable"

    test_results.append({
        "id": num,
        "test_id": test_id,
        "name": name,
        "mitre": mitre,
        "tactic": tactic,
        "config_a": va,
        "config_b": vb,
        "improvement": improvement,
    })

findings = [
    {
        "id": "F-001",
        "title": "SSRF via /fetch endpoint exposes IMDS credentials",
        "severity": "CRITICAL",
        "cwe": "CWE-918",
        "mitre": "T1552.005",
        "config_a": "CRITICAL",
        "config_b": "CRITICAL",
        "description": "The /fetch endpoint proxies arbitrary URLs without validation, enabling SSRF to the EC2 IMDS at 169.254.169.254. Stolen IAM credentials are valid from any IP and provide full AWS account access.",
        "remediation": "Enforce IMDSv2, remove /fetch endpoint, add WAF rule for metadata IP patterns, apply least-privilege IAM.",
    },
    {
        "id": "F-002",
        "title": "Overly permissive IAM role allows full account enumeration and access",
        "severity": "CRITICAL",
        "cwe": "CWE-250",
        "mitre": "T1078.004",
        "config_a": "CRITICAL",
        "config_b": "CRITICAL",
        "description": "The IAM role attached to EC2 grants excessive permissions. Once credentials are stolen via SSRF, attackers can enumerate and access S3, EC2, RDS, CloudWatch, and potentially create backdoor accounts.",
        "remediation": "Apply least-privilege IAM policy, use IAM Access Analyzer, add aws:SourceVpc conditions, enable GuardDuty.",
    },
    {
        "id": "F-003",
        "title": "No egress filtering enables data exfiltration and C2 channels",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "mitre": "T1048",
        "config_a": "VULNERABLE",
        "config_b": "VULNERABLE",
        "description": "Both configurations allow unrestricted outbound internet access. Attackers can exfiltrate data via HTTP/DNS and establish reverse C2 channels.",
        "remediation": "Restrict egress SG rules, deploy VPC Network Firewall with domain filtering, enable Route 53 DNS Firewall.",
    },
    {
        "id": "F-004",
        "title": "Direct EC2 exposure in Config A increases attack surface",
        "severity": "HIGH",
        "cwe": "CWE-693",
        "mitre": "T1595",
        "config_a": "VULNERABLE",
        "config_b": "BLOCKED",
        "description": "Config A places EC2 directly on the internet with a public IP. All ports are directly scannable. SSH is exposed to brute-force attacks.",
        "remediation": "Use private subnet with ALB (implemented in Config B). Replace SSH with Systems Manager Session Manager.",
    },
    {
        "id": "F-005",
        "title": "Sensitive information disclosure via debug endpoints",
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "mitre": "T1595",
        "config_a": "VULNERABLE",
        "config_b": "VULNERABLE",
        "description": "Application debug/info endpoints expose internal IPs, environment variables, and configuration data aiding attacker reconnaissance.",
        "remediation": "Disable debug endpoints in production; restrict health check responses to status codes only.",
    },
    {
        "id": "F-006",
        "title": "No TLS enforcement -- cleartext HTTP transmission",
        "severity": "MEDIUM",
        "cwe": "CWE-319",
        "mitre": "T1040",
        "config_a": "VULNERABLE",
        "config_b": "VULNERABLE",
        "description": "Application is served over HTTP without TLS. Credentials and session tokens are transmitted in cleartext.",
        "remediation": "Add HTTPS ALB listener with ACM certificate; enforce HTTP-to-HTTPS redirect; add HSTS headers.",
    },
    {
        "id": "F-007",
        "title": "Secrets transmitted via EC2 user data",
        "severity": "MEDIUM",
        "cwe": "CWE-312",
        "mitre": "T1552",
        "config_a": "VULNERABLE",
        "config_b": "VULNERABLE",
        "description": "Application secrets passed via EC2 user data are stored in plaintext and accessible via IMDS or DescribeInstanceAttribute API calls.",
        "remediation": "Use AWS Secrets Manager or SSM Parameter Store SecureString. Never pass secrets via user data.",
    },
]

mitre_mapping = [
    {"tactic": "Reconnaissance",       "technique_id": "T1595",     "technique_name": "Active Scanning",                       "scripts": ["00", "01"]},
    {"tactic": "Initial Access",       "technique_id": "T1190",     "technique_name": "Exploit Public-Facing Application",      "scripts": ["03", "04", "12"]},
    {"tactic": "Credential Access",    "technique_id": "T1552.005", "technique_name": "Cloud Instance Metadata API",            "scripts": ["04", "07", "10"]},
    {"tactic": "Privilege Escalation", "technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts",         "scripts": ["11", "15"]},
    {"tactic": "Discovery",            "technique_id": "T1046",     "technique_name": "Network Service Discovery",              "scripts": ["01", "02", "05", "09", "10"]},
    {"tactic": "Discovery",            "technique_id": "T1580",     "technique_name": "Cloud Infrastructure Discovery",         "scripts": ["07", "10", "15"]},
    {"tactic": "Lateral Movement",     "technique_id": "T1021",     "technique_name": "Remote Services",                       "scripts": ["14"]},
    {"tactic": "Collection",           "technique_id": "T1530",     "technique_name": "Data from Cloud Storage",                "scripts": ["11", "15"]},
    {"tactic": "Exfiltration",         "technique_id": "T1048",     "technique_name": "Exfiltration Over Alternative Protocol", "scripts": ["13", "16"]},
    {"tactic": "Command and Control",  "technique_id": "T1071.001", "technique_name": "Application Layer Protocol",             "scripts": ["13"]},
    {"tactic": "Persistence",          "technique_id": "T1136.003", "technique_name": "Create Account: Cloud Account",          "scripts": ["17"]},
    {"tactic": "Defense Evasion",      "technique_id": "T1562.007", "technique_name": "Impair Defenses: Cloud Firewall",        "scripts": ["17"]},
]

remediation_roadmap = [
    {"phase": "immediate", "horizon": "Week 1",    "action": "Enforce IMDSv2",                      "finding": "F-001", "effort": "low",    "cost": "0"},
    {"phase": "immediate", "horizon": "Week 1",    "action": "Remove /fetch endpoint",              "finding": "F-001", "effort": "low",    "cost": "0"},
    {"phase": "immediate", "horizon": "Week 1",    "action": "Apply least-privilege IAM policy",    "finding": "F-002", "effort": "medium", "cost": "0"},
    {"phase": "immediate", "horizon": "Week 1",    "action": "Restrict egress security group",      "finding": "F-003", "effort": "low",    "cost": "0"},
    {"phase": "short",     "horizon": "Month 1",   "action": "Enable GuardDuty",                    "finding": "F-002", "effort": "low",    "cost": "2-5/mo"},
    {"phase": "short",     "horizon": "Month 1",   "action": "Deploy AWS WAF on ALB",               "finding": "F-001", "effort": "medium", "cost": "5-20/mo"},
    {"phase": "short",     "horizon": "Month 1",   "action": "Add HTTPS ALB listener (ACM)",        "finding": "F-006", "effort": "low",    "cost": "0"},
    {"phase": "short",     "horizon": "Month 1",   "action": "Migrate secrets to Secrets Manager",  "finding": "F-007", "effort": "medium", "cost": "0.40/secret/mo"},
    {"phase": "medium",    "horizon": "Quarter 1", "action": "VPC Network Firewall egress rules",   "finding": "F-003", "effort": "high",   "cost": "~300/mo"},
    {"phase": "medium",    "horizon": "Quarter 1", "action": "Route 53 DNS Firewall",               "finding": "F-003", "effort": "medium", "cost": "~2/mo"},
    {"phase": "medium",    "horizon": "Quarter 1", "action": "S3 VPC Endpoint + bucket policy",     "finding": "F-003", "effort": "medium", "cost": "0"},
]

report = {
    "report_metadata": {
        "title": "AWS Public vs Private Subnet Security Assessment",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "type": "Gray Box Penetration Test",
        "scripts_executed": 20,
        "configs_compared": ["Config A (Public)", "Config B (Private)"],
    },
    "summary": {
        "config_a": {
            "label": "Config A (Public subnet, EC2 with public IP)",
            "critical":   summary_a["critical"],
            "vulnerable": summary_a["vulnerable"],
            "blocked":    summary_a["blocked"],
            "na":         summary_a["na"],
            "score":      calc_score(summary_a),
        },
        "config_b": {
            "label": "Config B (Private subnet, EC2 behind ALB + NAT Gateway)",
            "critical":   summary_b["critical"],
            "vulnerable": summary_b["vulnerable"],
            "blocked":    summary_b["blocked"],
            "na":         summary_b["na"],
            "score":      calc_score(summary_b),
        },
    },
    "findings": findings,
    "test_results": test_results,
    "mitre_mapping": mitre_mapping,
    "remediation_roadmap": remediation_roadmap,
}

print(json.dumps(report, indent=2))
PYEOF

# ---------------------------------------------------------------------------
# Step 8: Print summary to terminal
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}[*] Report generated successfully:${NC}"
echo -e "  Markdown : ${REPORT_MD}"
echo -e "  JSON     : ${REPORT_JSON}"
echo ""
echo -e "  Config A findings: ${a_critical} CRITICAL, ${a_vuln} VULNERABLE, ${a_blocked} BLOCKED  (score: ${a_score}/100)"
echo -e "  Config B findings: ${b_critical} CRITICAL, ${b_vuln} VULNERABLE, ${b_blocked} BLOCKED  (score: ${b_score}/100)"
echo ""

if ! $has_a || ! $has_b; then
    echo -e "${YELLOW}[!] Partial report -- run attacks on both configs for a complete assessment.${NC}"
    echo -e "${YELLOW}    1. terraform apply -var config_mode=public  -> ./run_all_attacks.sh${NC}"
    echo -e "${YELLOW}    2. terraform apply -var config_mode=private -> ./run_all_attacks.sh${NC}"
    echo -e "${YELLOW}    3. ./generate_report.sh${NC}"
    echo ""
fi
