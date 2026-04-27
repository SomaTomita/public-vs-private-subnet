# AWS Public vs Private Subnet Security Lab

A hands-on lab environment where you simply toggle the Terraform variable `config_mode` between `"public"` and `"private"` to experience how attack results differ against the same application.

> **WARNING**: For educational purposes only. This lab contains intentionally vulnerable applications. Always run `terraform destroy` when finished.

## Prerequisites

- AWS CLI (authenticated)
- Terraform >= 1.0
- bash >= 4.0 (macOS: `brew install bash`), curl, nmap, python3
- Your global IP (`curl ifconfig.me`)

## Quick Start

```bash
# 1. Setup
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: set my_ip, db_password, budget_email

# 2. Deploy Config A (Public — insecure configuration)
terraform init
terraform apply -var="config_mode=public"

# 3. Run attack scripts
cd ../scripts
./run_all_attacks.sh

# 4. Switch to Config B (Private — production-grade)
cd ../terraform
terraform apply -var="config_mode=private"

# 5. Re-run the same attacks
cd ../scripts
./run_all_attacks.sh

# 6. Generate comparison report
./compare_results.sh

# 7. Cleanup (required)
cd ../terraform
terraform destroy
```

## Command Reference

### Terraform

```bash
# Initialize
terraform init

# Deploy with Public configuration
terraform apply -var="config_mode=public"

# Switch to Private configuration
terraform apply -var="config_mode=private"

# Check current configuration
terraform output config_mode
terraform output architecture_summary
terraform output access_url

# Access information
terraform output ssh_command        # SSH connection command
terraform output attack_target      # Target IP/DNS for attacks
terraform output rds_endpoint       # RDS endpoint
terraform output estimated_hourly_cost

# Destroy environment (always run after lab)
terraform destroy
```

### Attack Scripts

```bash
cd scripts

# Run all scripts at once
./run_all_attacks.sh

# Skip slow scans
./run_all_attacks.sh --skip-slow

# Run specific attack only (by number)
./run_all_attacks.sh --only 04

# Individual execution
./00_reconnaissance.sh     # Reconnaissance (OSINT, DNS)
./01_portscan.sh           # Port scan
./02_ssh_probe.sh          # SSH brute-force probe
./03_web_scan.sh           # Web scan
./04_ssrf_metadata.sh      # SSRF to retrieve EC2 metadata
./05_db_probe.sh           # Direct DB connection attempt
./06_outbound_check.sh     # Outbound communication check
./07_full_kill_chain.sh    # Full kill chain (recon → exploit → lateral movement)
./08_post_exploitation.sh  # Post-exploitation activity simulation
./09_internal_recon.sh     # Internal network reconnaissance
./10_ssrf_internal_recon.sh   # SSRF-based VPC internal recon
./11_iam_privilege_escalation.sh # IAM credential abuse / privilege escalation
./12_alb_attacks.sh           # ALB-specific attacks (Config B only)
./13_outbound_c2.sh           # Outbound C2 channel verification
./14_ssrf_to_rds.sh           # SSRF-based RDS database attack
./15_iam_blast_radius.sh      # Comprehensive IAM blast radius mapping
./16_data_exfiltration.sh     # Data exfiltration channel analysis
./17_persistence_check.sh     # Persistence mechanism feasibility analysis
./18_detection_evasion.sh     # Detection & visibility analysis
./19_quantitative_metrics.sh  # Quantitative security metrics collection

# Config A vs B comparison report
./compare_results.sh

# VPC Flow Logs analysis
./flow_logs_analyzer.sh

# Attack flow trace visualization
./trace_attack_flow.sh

# Professional security assessment report
./generate_report.sh
```

### SSH Connection

```bash
# Public configuration (key filename follows project_name variable)
ssh -i terraform/$(cd terraform && terraform output -raw project_name)-key.pem ec2-user@$(cd terraform && terraform output -raw app_public_ip)

# Or use the pre-built command from Terraform output
eval "$(cd terraform && terraform output -raw ssh_command)"

# Private configuration (via SSM Session Manager)
aws ssm start-session --target $(cd terraform && terraform output -raw app_instance_id)
```

### Vulnerable App Operations

```bash
TARGET=$(cd terraform && terraform output -raw attack_target)

# Health check
curl http://$TARGET/health

# Server info
curl http://$TARGET/info

# SSRF (example: retrieve EC2 metadata)
curl "http://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/"
```

## Viewing Results

Attack results are automatically saved to the `results/` directory.

```
results/
  configA/     # Attack results with Public configuration
  configB/     # Attack results with Private configuration
```

Use `compare_results.sh` to compare VULNERABLE / BLOCKED verdicts side-by-side across both configurations.

## Variables

| Variable            | Required | Default          | Description                                    |
| ------------------- | -------- | ---------------- | ---------------------------------------------- |
| `config_mode`       | Yes      | —                | `"public"` or `"private"`                      |
| `my_ip`             | Yes      | —                | Your global IP (CIDR format: `x.x.x.x/32`)    |
| `db_password`       | Yes      | —                | RDS master password                            |
| `budget_email`      | Yes      | —                | Budget alert notification email                |
| `aws_region`        | No       | `ap-northeast-1` | AWS region                                     |
| `instance_type`     | No       | `t2.micro`       | EC2 instance type                              |
| `db_instance_class` | No       | `db.t3.micro`    | RDS instance class                             |
| `budget_limit`      | No       | `5`              | Monthly budget alert threshold (USD)           |

## Cost Estimate

| Configuration       | Estimated Cost                                  |
| ------------------- | ----------------------------------------------- |
| Config A (Public)   | ~$0.03–0.05/hr (EC2 + RDS, varies by region)   |
| Config B (Private)  | ~$0.13–0.17/hr (EC2 + RDS + NAT GW + ALB)      |

For Free Tier eligible accounts, EC2 and RDS fall within the free tier (Config A is effectively ~$0/hr). NAT Gateway (~$0.062/hr in ap-northeast-1) and ALB (~$0.024/hr) are the primary cost drivers. Costs vary by region; us-east-1 is ~20-30% cheaper.

## Development

### Setup

```bash
make setup   # Install pre-commit + formatters/linters
```

### Code Formatting & Linting

```bash
make fmt       # Format + lint all files (Terraform, Shell, Python, Markdown)
make fmt-check # CI check (fails if there are diffs)
make lint      # Lint only (shellcheck, ruff)
```

Individual targets:

```bash
make fmt-tf    # terraform fmt
make fmt-sh    # shfmt (shell script formatting)
make fmt-py    # ruff format (Python)
make fmt-md    # markdownlint --fix
```

Pre-commit hooks also run automatically on `git commit`.

## Documentation

- [docs/hands-on-plan.md](docs/hands-on-plan.md) — Hands-on learning plan details
- [architecture.md](architecture.md) — Architecture explanation & diagrams
- [docs/design-decisions.md](docs/design-decisions.md) — Design decision log
- [docs/packet-flow-trace.md](docs/packet-flow-trace.md) — Packet flow analysis
