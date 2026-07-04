variable "project_name" {
  description = "Nombre del proyecto SOC"
  type        = string
}

variable "aws_region" {
  description = "Región AWS"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR de la VPC"
  type        = string
}

variable "public_subnet_cidr" {
  description = "CIDR de la subred pública"
  type        = string
}

variable "private_subnet_cidr" {
  description = "CIDR de la subred privada"
  type        = string
}

variable "logs_s3_bucket_arn" {
  description = "ARN del bucket S3 de logs (SIEM)"
  type        = string
}

variable "common_tags" {
  description = "Tags comunes para todos los recursos"
  type        = map(string)
  default     = {}
}
