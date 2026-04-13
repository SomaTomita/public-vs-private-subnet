locals {
  is_public  = var.config_mode == "public"
  is_private = var.config_mode == "private"

  # Subnet CIDRs (non-contiguous: 1,3 / 10,11 / 20,21)
  public_subnet_cidrs = ["10.0.1.0/24", "10.0.3.0/24"]
  app_subnet_cidrs    = ["10.0.10.0/24", "10.0.11.0/24"]
  db_subnet_cidrs     = ["10.0.20.0/24", "10.0.21.0/24"]
}
