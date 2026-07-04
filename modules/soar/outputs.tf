output "lambda_auto_remediate_arn" {
  description = "ARN de la Lambda de auto-remediación"
  value       = aws_lambda_function.auto_remediate.arn
}

output "lambda_enrich_finding_arn" {
  description = "ARN de la Lambda de enriquecimiento de findings"
  value       = aws_lambda_function.enrich_finding.arn
}

output "stepfunctions_arn" {
  description = "ARN del State Machine Step Functions (Playbook SOC)"
  value       = aws_sfn_state_machine.soc_playbook.arn
}

output "eventbridge_guardduty_rule_arn" {
  description = "ARN de la regla EventBridge para GuardDuty → SOAR"
  value       = aws_cloudwatch_event_rule.guardduty_to_soar.arn
}

output "eventbridge_securityhub_rule_arn" {
  description = "ARN de la regla EventBridge para Security Hub → SNS"
  value       = aws_cloudwatch_event_rule.securityhub_to_sns.arn
}
