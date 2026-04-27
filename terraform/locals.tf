locals {
  is_public  = var.config_mode == "public"
  is_private = var.config_mode == "private"

  # AZs: use explicit var if provided, otherwise auto-detect from region
  azs = length(var.azs) > 0 ? var.azs : slice(data.aws_availability_zones.available.names, 0, 2)

  # Subnet CIDRs (non-contiguous: 1,3 / 10,11 / 20,21)
  public_subnet_cidrs = ["10.0.1.0/24", "10.0.3.0/24"]
  app_subnet_cidrs    = ["10.0.10.0/24", "10.0.11.0/24"]
  db_subnet_cidrs     = ["10.0.20.0/24", "10.0.21.0/24"]
}
