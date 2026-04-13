##############################
# NAT Gateway (private mode only, single AZ for cost saving)
##############################

resource "aws_eip" "nat" {
  count  = local.is_private ? 1 : 0
  domain = "vpc"

  tags = { Name = "${var.project_name}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  count         = local.is_private ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = { Name = "${var.project_name}-nat-gw" }

  depends_on = [aws_internet_gateway.main]
}
