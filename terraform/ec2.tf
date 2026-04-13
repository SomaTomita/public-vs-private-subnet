##############################
# AMI Lookup (Amazon Linux 2023)
##############################

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

##############################
# SSH Key Pair
##############################

resource "tls_private_key" "lab" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "lab" {
  key_name   = "${var.project_name}-key"
  public_key = tls_private_key.lab.public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.lab.private_key_pem
  filename        = "${path.module}/${var.project_name}-key.pem"
  file_permission = "0400"
}

##############################
# App Server EC2
##############################

resource "aws_instance" "app" {
  ami           = data.aws_ami.al2023.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.lab.key_name

  # Public mode: Public Subnet + Public IP
  # Private mode: App Private Subnet + No Public IP
  subnet_id                   = local.is_public ? aws_subnet.public[0].id : aws_subnet.app[0].id
  associate_public_ip_address = local.is_public

  vpc_security_group_ids = [aws_security_group.app.id]

  iam_instance_profile = aws_iam_instance_profile.app.name

  # IMDSv1 enabled initially (for SSRF demo), toggled to v2 in Phase 4
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # IMDSv1 allowed (intentionally vulnerable)
  }

  user_data = templatefile("${path.module}/templates/user_data.sh.tpl", {
    app_port = 80
  })

  tags = {
    Name       = "${var.project_name}-app-${var.config_mode}"
    ConfigMode = var.config_mode
  }
}
