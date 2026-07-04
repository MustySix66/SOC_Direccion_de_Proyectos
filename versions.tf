terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # ================================================================
  # BACKEND — Opcional: descomenta para usar S3 como backend remoto
  # Requiere bucket S3 y tabla DynamoDB pre-creados
  # ================================================================
  # backend "s3" {
  #   bucket         = "mi-soc-terraform-state"
  #   key            = "soc/terraform.tfstate"
  #   region         = "us-east-1"   # <-- CAMBIAR según tu región
  #   encrypt        = true
  #   dynamodb_table = "soc-terraform-lock"
  # }
}

provider "aws" {
  # ================================================================
  # REGIÓN AWS — MODIFICA ESTE VALOR SEGÚN TU PREFERENCIA
  # Opciones recomendadas (Free Tier disponible en todas):
  #   "us-east-1"  →  N. Virginia  (más económica, menor latencia global)
  #   "us-west-2"  →  Oregon       (buena alternativa en el oeste)
  #   "us-east-2"  →  Ohio         (buena para estudiantes en LATAM)
  #   "sa-east-1"  →  São Paulo    (menor latencia desde México)
  # NOTA: sa-east-1 puede tener algunos servicios con costo mayor
  # ================================================================
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "SOC-Team"
      CostCenter  = "Security"
    }
  }
}
