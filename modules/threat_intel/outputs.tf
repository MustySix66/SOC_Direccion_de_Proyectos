output "guardduty_ipset_id" {
  description = "ID del IPSet de GuardDuty con IPs maliciosas"
  value       = var.enable_custom_threat_intel && var.guardduty_detector_id != null ? aws_guardduty_ipset.malicious_ips[0].id : null
}

output "guardduty_threatintelset_id" {
  description = "ID del ThreatIntelSet de GuardDuty"
  value       = var.enable_custom_threat_intel && var.guardduty_detector_id != null ? aws_guardduty_threatintelset.malicious_domains[0].id : null
}

output "access_analyzer_arn" {
  description = "ARN del IAM Access Analyzer de superficie de ataque"
  value       = aws_accessanalyzer_analyzer.threat_surface.arn
}

output "malicious_ips_s3_key" {
  description = "Key S3 del archivo de IPs maliciosas"
  value       = aws_s3_object.malicious_ips.key
}

output "threat_intel_dashboard" {
  description = "Nombre del dashboard de Threat Intelligence"
  value       = aws_cloudwatch_dashboard.threat_intel.dashboard_name
}
