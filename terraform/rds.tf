##############################
# RDS (config_mode INDEPENDENT - always exists)
##############################

resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet-group"
  subnet_ids = aws_subnet.db[*].id

  tags = { Name = "${var.project_name}-db-subnet-group" }
}

resource "aws_db_instance" "main" {
  identifier     = "${var.project_name}-postgres"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  publicly_accessible = false

  auto_minor_version_upgrade = true
  allocated_storage          = 20
  storage_type               = "gp2"

  db_name  = "labdb"
  username = "admin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]

  # Test environment: fast teardown
  skip_final_snapshot     = true
  deletion_protection     = false
  backup_retention_period = 0

  # Single-AZ for cost saving
  multi_az = false

  tags = { Name = "${var.project_name}-postgres" }
}
