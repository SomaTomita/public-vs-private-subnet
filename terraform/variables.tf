##############################
# Core
##############################

variable "config_mode" {
  description = "public = EC2 directly exposed, private = ALB + Private Subnet"
  type        = string

  validation {
    condition     = contains(["public", "private"], var.config_mode)
    error_message = "config_mode must be 'public' or 'private'."
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "sec-lab"
}

##############################
# Network
##############################

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", var.vpc_cidr))
    error_message = "Must be valid IPv4 CIDR notation."
  }
}

variable "azs" {
  description = "Availability Zones (2 required for ALB/RDS). Auto-detected from region if empty."
  type        = list(string)
  default     = []
}

##############################
# Compute
##############################

variable "instance_type" {
  description = "EC2 instance type (t2.micro = Free Tier)"
  type        = string
  default     = "t2.micro"
}

variable "db_instance_class" {
  description = "RDS instance class (db.t3.micro = Free Tier eligible with Single-AZ)"
  type        = string
  default     = "db.t3.micro"
}

variable "db_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.db_password) >= 8 && var.db_password != "CHANGE_ME_before_apply"
    error_message = "db_password must be at least 8 characters and must not be the placeholder value."
  }
}

##############################
# Access Control
##############################

variable "my_ip" {
  description = "Your public IP for SSH access (CIDR, e.g. 203.0.113.50/32)"
  type        = string

  validation {
    condition     = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", var.my_ip))
    error_message = "Must be valid IPv4 CIDR (e.g. 1.2.3.4/32)."
  }
}

##############################
# Budget
##############################

variable "budget_limit" {
  description = "Monthly budget alert threshold (USD)"
  type        = number
  default     = 5
}

variable "budget_email" {
  description = "Email for budget alerts"
  type        = string

  validation {
    condition     = can(regex("^[^@]+@[^@]+\\.[^@]+$", var.budget_email))
    error_message = "budget_email must be a valid email address."
  }
}
