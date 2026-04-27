##############################
# App Server Security Group
##############################

resource "aws_security_group" "app" {
  name_prefix = "${var.project_name}-app-"
  description = "App Server SG - rules change with config_mode"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project_name}-app-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# Egress: always allow all outbound
resource "aws_vpc_security_group_egress_rule" "app_all_out" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# --- Public mode: internet-facing HTTP + SSH from my_ip ---

resource "aws_vpc_security_group_ingress_rule" "app_http_public" {
  count             = local.is_public ? 1 : 0
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "HTTP from internet (public mode)"
}

resource "aws_vpc_security_group_ingress_rule" "app_ssh_public" {
  count             = local.is_public ? 1 : 0
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = var.my_ip
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH from my IP (public mode)"
}

# --- Private mode: ALB SG only ---

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  count                        = local.is_private ? 1 : 0
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.alb[0].id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
  description                  = "HTTP from ALB only (private mode)"
}

resource "aws_vpc_security_group_ingress_rule" "app_ssh_from_bastion" {
  count             = local.is_private ? 1 : 0
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = var.my_ip
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH from my IP via SSM (private mode, no direct access)"
}

##############################
# ALB Security Group (private mode only)
##############################

resource "aws_security_group" "alb" {
  count       = local.is_private ? 1 : 0
  name_prefix = "${var.project_name}-alb-"
  description = "ALB SG - HTTP from internet"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project_name}-alb-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  count             = local.is_private ? 1 : 0
  security_group_id = aws_security_group.alb[0].id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "HTTP from internet"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  count                        = local.is_private ? 1 : 0
  security_group_id            = aws_security_group.alb[0].id
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
  description                  = "To App Server only"
}

##############################
# DB Security Group (config_mode independent)
##############################

resource "aws_security_group" "db" {
  name_prefix = "${var.project_name}-db-"
  description = "RDS SG - PostgreSQL from App SG only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project_name}-db-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL from App Server SG"
}

resource "aws_vpc_security_group_egress_rule" "db_ephemeral" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 1024
  to_port                      = 65535
  ip_protocol                  = "tcp"
  description                  = "Ephemeral ports to App SG (return traffic)"
}
