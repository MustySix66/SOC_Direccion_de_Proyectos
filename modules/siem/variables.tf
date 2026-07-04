variable "project_name" { type = string }
variable "aws_region" { type = string }
variable "account_id" { type = string }
variable "environment" { type = string }
variable "log_retention_days" { type = number }
variable "s3_log_retention_days" { type = number }
variable "s3_log_expiration_days" { type = number }
variable "sns_alert_topic_arn" { type = string }
variable "common_tags" {
  type    = map(string)
  default = {}
}
