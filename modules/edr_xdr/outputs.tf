output "guardduty_detector_id" {
  description = "ID del detector de GuardDuty (null si deshabilitado)"
  value       = var.enable_guardduty ? aws_guardduty_detector.soc[0].id : null
}

output "guardduty_detector_arn" {
  description = "ARN del detector de GuardDuty"
  value       = var.enable_guardduty ? aws_guardduty_detector.soc[0].arn : null
}

output "security_hub_arn" {
  description = "ARN de la cuenta en Security Hub (null si deshabilitado)"
  value       = var.enable_security_hub ? aws_securityhub_account.soc[0].id : null
}

output "access_analyzer_arn" {
  description = "ARN del IAM Access Analyzer"
  value       = aws_accessanalyzer_analyzer.soc.arn
}

output "guardduty_event_rule_arn" {
  description = "ARN de la regla EventBridge para findings de GuardDuty"
  value       = var.enable_guardduty ? aws_cloudwatch_event_rule.guardduty_findings[0].arn : null
}

output "securityhub_event_rule_arn" {
  description = "ARN de la regla EventBridge para findings de Security Hub"
  value       = var.enable_security_hub ? aws_cloudwatch_event_rule.securityhub_findings[0].arn : null
}

output "guardduty_event_rule_name" {
  description = "Nombre de la regla EventBridge de GuardDuty"
  value       = var.enable_guardduty ? aws_cloudwatch_event_rule.guardduty_findings[0].name : null
}

output "securityhub_event_rule_name" {
  description = "Nombre de la regla EventBridge de Security Hub"
  value       = var.enable_security_hub ? aws_cloudwatch_event_rule.securityhub_findings[0].name : null
}
