##############################
# AZ Lookup (auto-detect from region)
##############################

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

##############################
# VPC
##############################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project_name}-vpc" }
}

##############################
# Subnets
##############################

resource "aws_subnet" "public" {
  count             = length(local.public_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.public_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = { Name = "${var.project_name}-public-${count.index + 1}" }
}

resource "aws_subnet" "app" {
  count             = length(local.app_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.app_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = { Name = "${var.project_name}-app-${count.index + 1}" }
}

resource "aws_subnet" "db" {
  count             = length(local.db_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.db_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = { Name = "${var.project_name}-db-${count.index + 1}" }
}

##############################
# Internet Gateway
##############################

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.project_name}-igw" }
}

##############################
# S3 Gateway Endpoint (free)
##############################

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.aws_region}.s3"

  tags = { Name = "${var.project_name}-s3-endpoint" }
}

resource "aws_vpc_endpoint_route_table_association" "s3_public" {
  route_table_id  = aws_route_table.public.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}

resource "aws_vpc_endpoint_route_table_association" "s3_private" {
  route_table_id  = aws_route_table.private.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}
