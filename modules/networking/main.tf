# ==============================================================================
# MÓDULO: NETWORKING — main.tf
# Recursos: VPC, Subnets, IGW, Security Groups, VPC Flow Logs → S3
# Costo: GRATIS (VPC, subnets, SGs, IGW no tienen costo)
# ==============================================================================

# ----------------------------------------------------------------
# VPC Principal del SOC
# ----------------------------------------------------------------
resource "aws_vpc" "soc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-vpc"
  })
}

# ----------------------------------------------------------------
# Internet Gateway (necesario para subred pública)
# ----------------------------------------------------------------
resource "aws_internet_gateway" "soc" {
  vpc_id = aws_vpc.soc.id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-igw"
  })
}

# ----------------------------------------------------------------
# Subred Pública (para recursos con IP pública si se necesitan)
# ----------------------------------------------------------------
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.soc.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false # Sin IPs públicas automáticas por seguridad

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-subnet-public-a"
    Tier = "Public"
  })
}

# ----------------------------------------------------------------
# Subred Privada (para recursos internos del SOC)
# ----------------------------------------------------------------
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.soc.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = "${var.aws_region}a"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-subnet-private-a"
    Tier = "Private"
  })
}

# ----------------------------------------------------------------
# Route Table Pública
# ----------------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.soc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.soc.id
  }

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-rt-public"
  })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Route Table Privada (sin salida a internet — más segura)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.soc.id

  # Sin ruta 0.0.0.0/0 → subred completamente privada
  # NOTA: Si Lambda necesita acceso a internet desde subred privada,
  # descomentar el NAT Gateway (genera ~$32/mes de costo)

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-rt-private"
  })
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# ----------------------------------------------------------------
# Security Groups
# ----------------------------------------------------------------

# SG: Lambda/SOAR (permite salida para llamadas a AWS APIs)
resource "aws_security_group" "lambda" {
  name        = "${var.project_name}-sg-lambda"
  description = "Security group para funciones Lambda del SOAR — solo salida"
  vpc_id      = aws_vpc.soc.id

  egress {
    description = "HTTPS hacia AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-sg-lambda"
    Purpose = "SOAR-Lambda"
  })
}

# SG: Aislamiento — Completamente bloqueado (0 reglas ingress/egress)
# Se asigna a instancias comprometidas para aislarlas de la red
resource "aws_security_group" "isolation" {
  name        = "${var.project_name}-sg-isolation"
  description = "CUARENTENA: Instancias comprometidas — SIN acceso de red"
  vpc_id      = aws_vpc.soc.id

  # Sin reglas de ingress ni egress = tráfico completamente bloqueado
  # Esto es INTENCIONAL: es el SG de aislamiento del SOAR

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-sg-isolation"
    Purpose = "EC2-Quarantine"
    Warning = "ISOLATION-SG-DO-NOT-MODIFY"
  })
}

# ----------------------------------------------------------------
# VPC Flow Logs → S3 (gratis, dentro del free tier de S3)
# Captura todo el tráfico de red de la VPC para análisis SIEM
# ----------------------------------------------------------------
resource "aws_flow_log" "soc" {
  vpc_id               = aws_vpc.soc.id
  traffic_type         = "ALL" # Captura tráfico ACCEPTED y REJECTED
  log_destination_type = "s3"
  log_destination      = "${var.logs_s3_bucket_arn}/vpc-flow-logs/"

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flowdirection} $${log-status}"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-vpc-flow-logs"
  })
}
