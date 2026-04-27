##############################
# Access URLs
##############################

output "access_url" {
  description = "URL to access the application"
  value       = local.is_public ? "http://${aws_instance.app.public_ip}" : "http://${try(aws_lb.main[0].dns_name, "")}"
}

output "config_mode" {
  description = "Current config mode"
  value       = var.config_mode
}

output "architecture_summary" {
  description = "Current architecture description"
  value = local.is_public ? (
    "Config A: Internet -> IGW -> EC2 (Public IP: ${aws_instance.app.public_ip}, HTTP:80 public, SSH:22 limited to my_ip)"
    ) : (
    "Config B: Internet -> IGW -> ALB:80 (${try(aws_lb.main[0].dns_name, "")}) -> EC2 (Private IP: ${aws_instance.app.private_ip})"
  )
}

output "project_name" {
  description = "Project name used for resource naming"
  value       = var.project_name
}

##############################
# Network Info
##############################

output "app_public_ip" {
  description = "App Server Public IP (null in private mode)"
  value       = local.is_public ? aws_instance.app.public_ip : null
}

output "app_private_ip" {
  description = "App Server Private IP"
  value       = aws_instance.app.private_ip
}

output "alb_dns_name" {
  description = "ALB DNS name (null in public mode)"
  value       = try(aws_lb.main[0].dns_name, null)
}

output "nat_gw_eip" {
  description = "NAT Gateway EIP (null in public mode)"
  value       = try(aws_eip.nat[0].public_ip, null)
}

output "app_instance_id" {
  description = "EC2 instance ID (for SSM Session Manager)"
  value       = aws_instance.app.id
}

output "aws_region" {
  description = "AWS region"
  value       = var.aws_region
}

##############################
# SSH
##############################

output "ssh_command" {
  description = "SSH command to connect to App Server"
  value = local.is_public ? (
    "ssh -i ${var.project_name}-key.pem ec2-user@${aws_instance.app.public_ip}"
    ) : (
    "# Private mode: use SSM Session Manager\naws ssm start-session --target ${aws_instance.app.id}"
  )
}

output "ssh_key_file" {
  description = "Path to SSH private key"
  value       = local_sensitive_file.private_key.filename
}

##############################
# Database
##############################

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
}

##############################
# Attack Targets (for scripts)
##############################

output "attack_target" {
  description = "Target for attack scripts"
  value       = local.is_public ? aws_instance.app.public_ip : try(aws_lb.main[0].dns_name, "")
}

##############################
# Cost Estimate
##############################

output "estimated_hourly_cost" {
  description = "Rough hourly cost estimate for current config"
  value = local.is_public ? (
    "~$0.03-0.05/hr (EC2 + RDS only, varies by region)"
    ) : (
    "~$0.13-0.17/hr (EC2 + RDS + NAT GW + ALB, varies by region)"
  )
}
