variable "project_name" { type = string }
variable "aws_region" { type = string }
variable "enable_guardduty" { type = bool }
variable "enable_security_hub" { type = bool }
variable "enable_inspector" { type = bool }
variable "guardduty_finding_frequency" { type = string }
variable "logs_s3_bucket_arn" { type = string }
variable "sns_alert_topic_arn" { type = string }
variable "common_tags" {
  type    = map(string)
  default = {}
}
