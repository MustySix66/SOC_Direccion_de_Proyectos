# ==============================================================================
# MAIN.TF — Módulo Raíz del SOC en AWS
# Orquesta todos los módulos: Networking, SIEM, EDR/XDR, SOAR, Threat Intel
# ==============================================================================

# ------------------------------------------------------------------------------
# Datos del proveedor AWS (cuenta actual)
# ------------------------------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  # Usar account_id de la variable o detectarlo automáticamente
  account_id   = var.account_id != "123456789012" ? var.account_id : data.aws_caller_identity.current.account_id
  current_region = data.aws_region.current.name

  # Tags combinados: globales + custom del usuario
  all_tags = merge(
    var.common_tags,
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  )
}

# ==============================================================================
# SNS — Notificaciones de Alertas de Seguridad
# (Primero porque todos los módulos lo necesitan)
# ==============================================================================
resource "aws_sns_topic" "soc_alerts" {
  name         = "${var.project_name}-security-alerts"
  display_name = "SOC Security Alerts"

  tags = local.all_tags
}

# Suscripción por Email
resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.soc_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Suscripción por SMS (solo si está habilitada y hay número)
resource "aws_sns_topic_subscription" "sms_alert" {
  count = var.enable_sms_alerts && var.alert_phone != "" ? 1 : 0

  topic_arn = aws_sns_topic.soc_alerts.arn
  protocol  = "sms"
  endpoint  = var.alert_phone
}

# ==============================================================================
# SSM Parameter Store — Configuración compartida entre módulos
# (Gratis: sin costo para Standard Parameters)
# ==============================================================================
resource "aws_ssm_parameter" "soc_config" {
  name  = "/${var.project_name}/config/alert-email"
  type  = "String"
  value = var.alert_email

  tags = local.all_tags
}

resource "aws_ssm_parameter" "blocklist_ips" {
  name  = "/${var.project_name}/blocklist/ips"
  type  = "StringList"
  value = "0.0.0.0" # Placeholder inicial

  tags = local.all_tags

  lifecycle {
    ignore_changes = [value] # Lambda actualiza este valor dinámicamente
  }
}

# ==============================================================================
# MÓDULO: NETWORKING
# VPC, Subnets, Security Groups, VPC Flow Logs → S3
# ==============================================================================
module "networking" {
  source = "./modules/networking"

  project_name        = var.project_name
  aws_region          = var.aws_region
  vpc_cidr            = var.vpc_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr
  logs_s3_bucket_arn  = module.siem.logs_bucket_arn
  common_tags         = local.all_tags

  depends_on = [module.siem]
}

# ==============================================================================
# MÓDULO: SIEM
# CloudTrail + S3 + CloudWatch Logs + Métricas + Dashboard
# Todo Free Tier / muy bajo costo
# ==============================================================================
module "siem" {
  source = "./modules/siem"

  project_name           = var.project_name
  aws_region             = var.aws_region
  account_id             = local.account_id
  environment            = var.environment
  log_retention_days     = var.log_retention_days
  s3_log_retention_days  = var.s3_log_retention_days
  s3_log_expiration_days = var.s3_log_expiration_days
  sns_alert_topic_arn    = aws_sns_topic.soc_alerts.arn
  common_tags            = local.all_tags
}

# ==============================================================================
# MÓDULO: EDR/XDR
# GuardDuty + Security Hub + Inspector v2 (opcional)
# 30 días Free Trial, luego costo muy bajo para cuenta estudiante
# ==============================================================================
module "edr_xdr" {
  source = "./modules/edr_xdr"

  project_name                = var.project_name
  aws_region                  = var.aws_region
  enable_guardduty            = var.enable_guardduty
  enable_security_hub         = var.enable_security_hub
  enable_inspector            = var.enable_inspector
  guardduty_finding_frequency = var.guardduty_finding_frequency
  logs_s3_bucket_arn          = module.siem.logs_bucket_arn
  sns_alert_topic_arn         = aws_sns_topic.soc_alerts.arn
  common_tags                 = local.all_tags
}

# ==============================================================================
# MÓDULO: SOAR
# EventBridge + Lambda + Step Functions + Auto-Remediación
# Lambda: 1M req gratis/mes | Step Functions: 4000 transitions gratis
# ==============================================================================
module "soar" {
  source = "./modules/soar"

  project_name                      = var.project_name
  aws_region                        = var.aws_region
  account_id                        = local.account_id
  environment                       = var.environment
  auto_remediation_enabled          = var.auto_remediation_enabled
  severity_threshold_auto_remediate = var.severity_threshold_auto_remediate
  isolation_sg_id                   = module.networking.isolation_sg_id
  sns_alert_topic_arn               = aws_sns_topic.soc_alerts.arn
  guardduty_detector_id             = module.edr_xdr.guardduty_detector_id
  blocklist_ssm_param               = aws_ssm_parameter.blocklist_ips.name
  logs_s3_bucket_arn                = module.siem.logs_bucket_arn
  common_tags                       = local.all_tags

  depends_on = [module.edr_xdr, module.networking]
}

# ==============================================================================
# MÓDULO: THREAT INTELLIGENCE
# GuardDuty TI Sets + Sets de IPs maliciosas + Watchlist
# ==============================================================================
module "threat_intel" {
  source = "./modules/threat_intel"

  project_name                = var.project_name
  aws_region                  = var.aws_region
  account_id                  = local.account_id
  enable_custom_threat_intel  = var.enable_custom_threat_intel
  threat_intel_ipset_file     = var.threat_intel_ipset_file
  guardduty_detector_id       = module.edr_xdr.guardduty_detector_id
  logs_s3_bucket_arn          = module.siem.logs_bucket_arn
  logs_bucket_id              = module.siem.logs_bucket_id
  common_tags                 = local.all_tags

  depends_on = [module.edr_xdr, module.siem]
}
