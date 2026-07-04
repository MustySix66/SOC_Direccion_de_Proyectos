variable "project_name" { type = string }
variable "aws_region" { type = string }
variable "account_id" { type = string }
variable "enable_custom_threat_intel" { type = bool }
variable "threat_intel_ipset_file" { type = string }
variable "guardduty_detector_id" {
  type    = string
  default = null
}
variable "logs_s3_bucket_arn" { type = string }
variable "logs_bucket_id" { type = string }
variable "sns_alert_topic_arn" { type = string }
variable "common_tags" {
  type    = map(string)
  default = {}
}
