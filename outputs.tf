# ==============================================================================
# OUTPUTS — SOC en AWS
# Valores importantes para referencias post-despliegue
# ==============================================================================

output "soc_region" {
  description = "Región AWS donde está desplegado el SOC"
  value       = var.aws_region
}

output "account_id" {
  description = "ID de la cuenta AWS"
  value       = data.aws_caller_identity.current.account_id
  sensitive   = false
}

# ----------------------------------------------------------------
# SNS / Notificaciones
# ----------------------------------------------------------------
output "sns_alerts_topic_arn" {
  description = "ARN del tópico SNS de alertas de seguridad"
  value       = aws_sns_topic.soc_alerts.arn
}

output "alert_email_configured" {
  description = "Email configurado para recibir alertas (revisa tu bandeja para confirmar suscripción)"
  value       = var.alert_email
}

# ----------------------------------------------------------------
# SIEM
# ----------------------------------------------------------------
output "siem_logs_bucket" {
  description = "Nombre del bucket S3 de logs centralizados del SIEM"
  value       = module.siem.logs_bucket_id
}

output "siem_cloudtrail_arn" {
  description = "ARN del trail de CloudTrail"
  value       = module.siem.cloudtrail_arn
}

output "siem_dashboard_url" {
  description = "URL del dashboard CloudWatch del SOC"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${var.project_name}-soc-overview"
}

output "cloudwatch_log_group_cloudtrail" {
  description = "Log Group de CloudWatch para CloudTrail"
  value       = module.siem.cloudtrail_log_group_name
}

# ----------------------------------------------------------------
# EDR/XDR
# ----------------------------------------------------------------
output "guardduty_detector_id" {
  description = "ID del detector de Amazon GuardDuty"
  value       = module.edr_xdr.guardduty_detector_id
}

output "security_hub_arn" {
  description = "ARN de AWS Security Hub"
  value       = module.edr_xdr.security_hub_arn
}

output "guardduty_console_url" {
  description = "URL de la consola de GuardDuty"
  value       = "https://console.aws.amazon.com/guardduty/home?region=${var.aws_region}#/findings"
}

output "security_hub_console_url" {
  description = "URL de la consola de Security Hub"
  value       = "https://console.aws.amazon.com/securityhub/home?region=${var.aws_region}#/findings"
}

# ----------------------------------------------------------------
# SOAR
# ----------------------------------------------------------------
output "soar_lambda_auto_remediate_arn" {
  description = "ARN de la función Lambda de auto-remediación"
  value       = module.soar.lambda_auto_remediate_arn
}

output "soar_lambda_enrich_finding_arn" {
  description = "ARN de la función Lambda de enriquecimiento de findings"
  value       = module.soar.lambda_enrich_finding_arn
}

output "soar_stepfunctions_arn" {
  description = "ARN del State Machine de Step Functions (Playbook SOC)"
  value       = module.soar.stepfunctions_arn
}

# ----------------------------------------------------------------
# NETWORKING
# ----------------------------------------------------------------
output "vpc_id" {
  description = "ID de la VPC del SOC"
  value       = module.networking.vpc_id
}

output "isolation_sg_id" {
  description = "ID del Security Group de aislamiento (para instancias comprometidas)"
  value       = module.networking.isolation_sg_id
}

# ----------------------------------------------------------------
# THREAT INTELLIGENCE
# ----------------------------------------------------------------
output "threat_intel_ipset_id" {
  description = "ID del IPSet de Inteligencia de Amenazas en GuardDuty"
  value       = module.threat_intel.guardduty_ipset_id
}

# ----------------------------------------------------------------
# RESUMEN GENERAL
# ----------------------------------------------------------------
output "soc_summary" {
  description = "Resumen del SOC desplegado"
  value = {
    nombre_proyecto    = var.project_name
    region             = var.aws_region
    ambiente           = var.environment
    email_alertas      = var.alert_email
    guardduty_activo   = var.enable_guardduty
    security_hub_activo = var.enable_security_hub
    inspector_activo   = var.enable_inspector
    auto_remediacion   = var.auto_remediation_enabled
    dashboard_url      = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${var.project_name}-soc-overview"
  }
}
