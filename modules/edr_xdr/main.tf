# ==============================================================================
# MÓDULO: EDR/XDR — main.tf
# Endpoint Detection & Response / Extended Detection & Response
# Servicios: Amazon GuardDuty + AWS Security Hub + Amazon Inspector v2
#
# COSTO ESTIMADO:
#   - GuardDuty: GRATIS 30 días, luego ~$1-4/mes (cuenta pequeña sin tráfico)
#   - Security Hub: GRATIS 30 días, luego $0.001/finding (muy bajo)
#   - Inspector v2: GRATIS 30 días, luego solo con EC2/ECR activos
# ==============================================================================

# ----------------------------------------------------------------
# AMAZON GUARDDUTY — Detección de Amenazas con ML
# Analiza logs de CloudTrail, VPC Flow Logs y DNS para detectar amenazas
# ----------------------------------------------------------------
resource "aws_guardduty_detector" "soc" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  datasources {
    s3_logs {
      enable = true # Detecta acceso anómalo a S3
    }
    kubernetes {
      audit_logs {
        enable = false # Solo activar si tienes EKS
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = false # Activar si tienes instancias EC2
        }
      }
    }
  }

  # Frecuencia de publicación de findings
  # SIX_HOURS = menos procesamiento = menor costo potencial
  finding_publishing_frequency = var.guardduty_finding_frequency

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-guardduty"
  })
}

# Publicar findings de GuardDuty a S3 (para análisis en SIEM)
resource "aws_guardduty_publishing_destination" "s3" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.soc[0].id

  destination_type = "S3"
  destination_arn  = "${var.logs_s3_bucket_arn}/guardduty-findings/"

  # Usamos clave administrada por S3 (sin costo de KMS)
  kms_key_arn = "arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alias/aws/s3"
}

# Datos de la cuenta actual
data "aws_caller_identity" "current" {}

# ----------------------------------------------------------------
# AWS SECURITY HUB — Agregador Central de Findings de Seguridad
# Centraliza findings de GuardDuty, Inspector, Config, IAM Access Analyzer, etc.
# ----------------------------------------------------------------
resource "aws_securityhub_account" "soc" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards = true # Habilita CIS AWS Foundations y AWS Foundational

  auto_enable_controls = true

  tags = var.common_tags
}

# Conectar GuardDuty con Security Hub
resource "aws_securityhub_product_subscription" "guardduty" {
  count = var.enable_security_hub && var.enable_guardduty ? 1 : 0

  product_arn = "arn:aws:securityhub:${var.aws_region}::product/aws/guardduty"

  depends_on = [aws_securityhub_account.soc]
}

# Conectar Inspector con Security Hub
resource "aws_securityhub_product_subscription" "inspector" {
  count = var.enable_security_hub && var.enable_inspector ? 1 : 0

  product_arn = "arn:aws:securityhub:${var.aws_region}::product/aws/inspector"

  depends_on = [aws_securityhub_account.soc]
}

# Conectar IAM Access Analyzer con Security Hub
resource "aws_securityhub_product_subscription" "access_analyzer" {
  count = var.enable_security_hub ? 1 : 0

  product_arn = "arn:aws:securityhub:${var.aws_region}::product/aws/access-analyzer"

  depends_on = [aws_securityhub_account.soc]
}

# Security Hub Insight — Vista de findings de alta severidad
resource "aws_securityhub_insight" "high_severity_findings" {
  count = var.enable_security_hub ? 1 : 0

  name = "${var.project_name}-high-severity-active"

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    workflow_status {
      comparison = "EQUALS"
      value      = "NEW"
    }
  }

  group_by_attribute = "ResourceType"

  depends_on = [aws_securityhub_account.soc]
}

resource "aws_securityhub_insight" "critical_findings" {
  count = var.enable_security_hub ? 1 : 0

  name = "${var.project_name}-critical-findings"

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "AwsAccountId"

  depends_on = [aws_securityhub_account.soc]
}

# ----------------------------------------------------------------
# AMAZON INSPECTOR v2 — Análisis de Vulnerabilidades
# Escanea instancias EC2 y repositorios ECR en busca de CVEs
# NOTA: Solo útil si tienes instancias EC2 o contenedores
# ----------------------------------------------------------------
resource "aws_inspector2_enabler" "soc" {
  count = var.enable_inspector ? 1 : 0

  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR"] # Agrega "LAMBDA" si usas funciones Lambda

  depends_on = [aws_securityhub_account.soc]
}

# ----------------------------------------------------------------
# IAM ACCESS ANALYZER — Detecta acceso no intencionado a recursos
# Analiza políticas IAM, S3, KMS, SQS, Lambda para detectar
# recursos con acceso público o compartido fuera de la cuenta
# COSTO: GRATIS (siempre)
# ----------------------------------------------------------------
resource "aws_accessanalyzer_analyzer" "soc" {
  analyzer_name = "${var.project_name}-access-analyzer"
  type          = "ACCOUNT" # Analiza la cuenta actual

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-access-analyzer"
  })
}

# ----------------------------------------------------------------
# EventBridge — Capturar Findings de GuardDuty para SOAR
# ----------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${var.project_name}-guardduty-findings"
  description = "Captura todos los findings de GuardDuty para procesamiento SOAR"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }] # Solo severidad MEDIA o mayor
    }
  })

  tags = var.common_tags
}

# EventBridge — Capturar findings de Security Hub
resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  count = var.enable_security_hub ? 1 : 0

  name        = "${var.project_name}-securityhub-findings"
  description = "Captura findings críticos y altos de Security Hub"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH", "CRITICAL"]
        }
        RecordState = ["ACTIVE"]
        WorkflowState = ["NEW"]
      }
    }
  })

  tags = var.common_tags
}

# EventBridge — Cambios en findings de Security Hub
resource "aws_cloudwatch_event_rule" "securityhub_insights" {
  count = var.enable_security_hub ? 1 : 0

  name        = "${var.project_name}-securityhub-insight-results"
  description = "Cambios en resultados de Security Hub Insights"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Insight Results"]
  })

  tags = var.common_tags
}
