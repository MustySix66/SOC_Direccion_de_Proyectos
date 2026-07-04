output "logs_bucket_id" {
  description = "ID (nombre) del bucket S3 de logs"
  value       = aws_s3_bucket.soc_logs.id
}

output "logs_bucket_arn" {
  description = "ARN del bucket S3 de logs del SIEM"
  value       = aws_s3_bucket.soc_logs.arn
}

output "cloudtrail_arn" {
  description = "ARN del CloudTrail del SOC"
  value       = aws_cloudtrail.soc.arn
}

output "cloudtrail_log_group_name" {
  description = "Nombre del Log Group de CloudWatch para CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "cloudtrail_log_group_arn" {
  description = "ARN del Log Group de CloudWatch para CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "guardduty_findings_log_group" {
  description = "Log Group para findings de GuardDuty"
  value       = aws_cloudwatch_log_group.guardduty_findings.name
}

output "soar_actions_log_group" {
  description = "Log Group para acciones del SOAR"
  value       = aws_cloudwatch_log_group.soar_actions.name
}

output "soc_dashboard_name" {
  description = "Nombre del Dashboard CloudWatch del SOC"
  value       = aws_cloudwatch_dashboard.soc_overview.dashboard_name
}
