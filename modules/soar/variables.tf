variable "project_name" { type = string }
variable "aws_region" { type = string }
variable "account_id" { type = string }
variable "environment" { type = string }
variable "auto_remediation_enabled" { type = bool }
variable "severity_threshold_auto_remediate" { type = number }
variable "isolation_sg_id" { type = string }
variable "sns_alert_topic_arn" { type = string }
variable "guardduty_detector_id" {
  type    = string
  default = null
}
variable "blocklist_ssm_param" { type = string }
variable "logs_s3_bucket_arn" { type = string }
variable "common_tags" {
  type    = map(string)
  default = {}
}
