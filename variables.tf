# ==============================================================================
# VARIABLES GLOBALES — SOC en AWS (Free Tier Optimizado)
# ==============================================================================

# ----------------------------------------------------------------
# REGIÓN
# ----------------------------------------------------------------
variable "aws_region" {
  description = <<-EOT
    Región AWS donde se desplegará el SOC.
    Opciones recomendadas:
      us-east-1  → N. Virginia  (más económica, recomendada)
      us-west-2  → Oregon
      us-east-2  → Ohio
      sa-east-1  → São Paulo (menor latencia desde México)
  EOT
  type    = string
  default = "us-east-1" # <-- CAMBIA AQUÍ LA REGIÓN
}

# ----------------------------------------------------------------
# IDENTIFICADORES DEL PROYECTO
# ----------------------------------------------------------------
variable "project_name" {
  description = "Nombre del proyecto SOC. Usado como prefijo en todos los recursos."
  type        = string
  default     = "soc-ezekiel"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,28}[a-z0-9]$", var.project_name))
    error_message = "El nombre debe ser lowercase, alfanumérico con guiones, entre 4 y 30 caracteres."
  }
}

variable "environment" {
  description = "Entorno de despliegue: dev, staging o prod"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "El entorno debe ser: dev, staging o prod."
  }
}

variable "account_id" {
  description = <<-EOT
    ID de cuenta AWS (12 dígitos).
    Obtén el tuyo con: aws sts get-caller-identity --query Account --output text
  EOT
  type    = string
  default = "123456789012" # <-- CAMBIA AQUÍ TU AWS ACCOUNT ID

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "El account_id debe ser un número de 12 dígitos."
  }
}

# ----------------------------------------------------------------
# NOTIFICACIONES
# ----------------------------------------------------------------
variable "alert_email" {
  description = "Email para recibir alertas de seguridad via SNS"
  type        = string
  default     = "231011@utags.edu.mx" # Email del equipo SOC UTAGS
}

variable "alert_phone" {
  description = <<-EOT
    Número de teléfono para SMS via SNS (formato E.164).
    Ejemplo: +521XXXXXXXXXX para México
    NOTA: SNS SMS tiene costo, desactivado por default en Free Tier.
    Para activar: cambiar enable_sms_alerts = true en terraform.tfvars
  EOT
  type    = string
  default = "" # <-- AGREGA TU NÚMERO SI QUIERES SMS
}

variable "enable_sms_alerts" {
  description = "Habilitar alertas por SMS (genera costo adicional)"
  type        = bool
  default     = false # Desactivado por default para Free Tier
}

# ----------------------------------------------------------------
# NETWORKING
# ----------------------------------------------------------------
variable "vpc_cidr" {
  description = "Bloque CIDR para la VPC del SOC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR para subred pública (zona de disponibilidad -a)"
  type        = string
  default     = "10.10.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR para subred privada (zona de disponibilidad -a)"
  type        = string
  default     = "10.10.10.0/24"
}

# ----------------------------------------------------------------
# SIEM — CloudTrail + CloudWatch
# ----------------------------------------------------------------
variable "log_retention_days" {
  description = <<-EOT
    Días de retención en CloudWatch Logs.
    Free Tier: 5 GB de ingesta/mes y 5 GB de almacenamiento.
    Recomendado para Free Tier: 14 días
  EOT
  type    = number
  default = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365], var.log_retention_days)
    error_message = "Los días de retención deben ser un valor válido de CloudWatch."
  }
}

variable "s3_log_retention_days" {
  description = "Días antes de mover logs a Glacier en S3 (costo ~$0.004/GB en Glacier vs $0.023/GB en S3 Standard)"
  type        = number
  default     = 30
}

variable "s3_log_expiration_days" {
  description = "Días antes de eliminar logs de S3 (incluye Glacier)"
  type        = number
  default     = 90
}

# ----------------------------------------------------------------
# EDR/XDR — GuardDuty + Security Hub
# ----------------------------------------------------------------
variable "enable_guardduty" {
  description = "Habilitar Amazon GuardDuty (30 días gratis, luego ~$1-4/mes para cuenta pequeña)"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Habilitar AWS Security Hub (30 días gratis, luego $0.0010/finding)"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = <<-EOT
    Habilitar Amazon Inspector v2 (30 días gratis).
    Requiere al menos 1 instancia EC2 o imagen ECR para ser útil.
    Desactivado por default para ahorrar costos.
  EOT
  type    = bool
  default = false # Activa si tienes EC2 o contenedores
}

variable "guardduty_finding_frequency" {
  description = "Frecuencia de publicación de findings de GuardDuty: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS"
  type        = string
  default     = "SIX_HOURS" # Menos frecuente = menor costo de procesamiento

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_frequency)
    error_message = "La frecuencia debe ser FIFTEEN_MINUTES, ONE_HOUR o SIX_HOURS."
  }
}

# ----------------------------------------------------------------
# SOAR — Lambda + Step Functions + EventBridge
# ----------------------------------------------------------------
variable "auto_remediation_enabled" {
  description = <<-EOT
    Habilitar auto-remediación automática para findings CRÍTICOS.
    CUIDADO: En prod puede aislar instancias o deshabilitar keys automáticamente.
    Recomendado: false para dev/testing, true solo en prod con revisión previa.
  EOT
  type    = bool
  default = false # ⚠ Cambia a true solo si entiendes las implicaciones
}

variable "severity_threshold_auto_remediate" {
  description = "Severidad mínima para auto-remediación (1-10). Default 8 = CRÍTICO"
  type        = number
  default     = 8

  validation {
    condition     = var.severity_threshold_auto_remediate >= 1 && var.severity_threshold_auto_remediate <= 10
    error_message = "La severidad debe estar entre 1 y 10."
  }
}

# ----------------------------------------------------------------
# THREAT INTELLIGENCE
# ----------------------------------------------------------------
variable "enable_custom_threat_intel" {
  description = "Habilitar sets de Inteligencia de Amenazas personalizados en GuardDuty"
  type        = bool
  default     = true
}

variable "threat_intel_ipset_file" {
  description = "Nombre del archivo de IPs maliciosas en S3 (formato TXT, una IP por línea)"
  type        = string
  default     = "threat-intel/malicious-ips.txt"
}

# ----------------------------------------------------------------
# TAGS COMUNES
# ----------------------------------------------------------------
variable "common_tags" {
  description = "Tags adicionales aplicados a todos los recursos"
  type        = map(string)
  default = {
    Universidad = "UTAGS"
    Proyecto    = "SOC-Tesis"
    Año         = "2024"
  }
}
