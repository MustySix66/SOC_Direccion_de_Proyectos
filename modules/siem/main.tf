# ==============================================================================
# MÓDULO: SIEM — main.tf
# Security Information and Event Management
# Servicios: CloudTrail + S3 + CloudWatch Logs + Métricas + Dashboard
#
# COSTO ESTIMADO (Free Tier):
#   - CloudTrail: GRATIS (1 trail de eventos de administración)
#   - S3: GRATIS hasta 5 GB / mes (12 meses)
#   - CloudWatch Logs: GRATIS hasta 5 GB ingesta / mes (12 meses)
#   - CloudWatch Alarms: GRATIS hasta 10 alarmas (12 meses)
#   - CloudWatch Dashboards: GRATIS hasta 3 dashboards (12 meses)
# ==============================================================================

# ----------------------------------------------------------------
# S3 Bucket — Centralización de Logs (SIEM Storage)
# ----------------------------------------------------------------
resource "aws_s3_bucket" "soc_logs" {
  # El nombre debe ser globalmente único: usamos account_id como sufijo
  bucket = "${var.project_name}-logs-${var.account_id}"

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-logs"
    Purpose = "SIEM-Log-Centralization"
  })
}

# Bloquear todo acceso público (seguridad obligatoria para logs de seguridad)
resource "aws_s3_bucket_public_access_block" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versionado de objetos (para integridad de logs)
resource "aws_s3_bucket_versioning" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Cifrado del lado servidor con claves administradas por S3 (GRATIS)
# NOTA: Para usar KMS ($1/mes por clave), cambia a "aws:kms"
resource "aws_s3_bucket_server_side_encryption_configuration" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # S3-SSE: GRATIS
    }
    bucket_key_enabled = true
  }
}

# Ciclo de vida para gestión de costos:
# Standard (30 días) → Glacier Instant ($0.004/GB) → Eliminar (90 días)
resource "aws_s3_bucket_lifecycle_configuration" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  rule {
    id     = "log-lifecycle-management"
    status = "Enabled"

    filter {
      prefix = "" # Aplica a todos los objetos
    }

    # Después de N días mover a Glacier (mucho más barato)
    transition {
      days          = var.s3_log_retention_days
      storage_class = "GLACIER_IR" # Glacier Instant Retrieval
    }

    # Eliminar versiones antiguas después de 90 días
    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    # Expiración total
    expiration {
      days = var.s3_log_expiration_days
    }
  }
}

# Política del bucket S3 — Permite CloudTrail y VPC Flow Logs escribir
resource "aws_s3_bucket_policy" "soc_logs" {
  bucket = aws_s3_bucket.soc_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudTrail: verificar ACL del bucket
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.soc_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${var.account_id}:trail/${var.project_name}-trail"
          }
        }
      },
      # CloudTrail: escribir logs
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.soc_logs.arn}/cloudtrail/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${var.account_id}:trail/${var.project_name}-trail"
          }
        }
      },
      # VPC Flow Logs: verificar ACL
      {
        Sid    = "AWSVPCFlowLogsAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.soc_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
        }
      },
      # VPC Flow Logs: escribir logs
      {
        Sid    = "AWSVPCFlowLogsWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.soc_logs.arn}/vpc-flow-logs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = var.account_id
          }
        }
      }
    ]
  })
}

# ----------------------------------------------------------------
# CloudTrail — Auditoría de Acciones en AWS (GRATIS: 1 trail)
# Registra QUIÉN hizo QUÉ, CUÁNDO y DESDE DÓNDE en la cuenta
# ----------------------------------------------------------------

# Log Group de CloudWatch para CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = var.log_retention_days

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-cloudtrail-logs"
  })
}

# IAM Role para que CloudTrail pueda escribir en CloudWatch
resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
    }]
  })

  tags = var.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name = "${var.project_name}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_to_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# CloudTrail principal
resource "aws_cloudtrail" "soc" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.soc_logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true  # Captura IAM, STS, etc.
  is_multi_region_trail         = false # Single region = GRATIS
  enable_log_file_validation    = true  # Verifica integridad de logs

  # Integración con CloudWatch Logs para alertas en tiempo real
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch.arn

  event_selector {
    read_write_type           = "All" # Captura lecturas y escrituras
    include_management_events = true  # Eventos de gestión (GRATIS)

    # NOTA: Data Events (S3 objects, Lambda invocations) NO son gratis.
    # Para habilitarlos (costo ~$0.10/100K eventos), descomenta:
    # data_resource {
    #   type   = "AWS::S3::Object"
    #   values = ["arn:aws:s3:::"]
    # }
    # data_resource {
    #   type   = "AWS::Lambda::Function"
    #   values = ["arn:aws:lambda"]
    # }
  }

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-cloudtrail"
  })

  depends_on = [
    aws_s3_bucket_policy.soc_logs,
    aws_cloudwatch_log_group.cloudtrail
  ]
}

# ----------------------------------------------------------------
# Log Groups adicionales del SIEM
# ----------------------------------------------------------------

# Logs de GuardDuty (redirigidos desde EventBridge)
resource "aws_cloudwatch_log_group" "guardduty_findings" {
  name              = "/aws/guardduty/${var.project_name}/findings"
  retention_in_days = var.log_retention_days

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-guardduty-findings-log"
  })
}

# Logs del SOAR (acciones de remediación)
resource "aws_cloudwatch_log_group" "soar_actions" {
  name              = "/aws/soc/${var.project_name}/soar-actions"
  retention_in_days = var.log_retention_days

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-soar-actions-log"
  })
}

# ----------------------------------------------------------------
# CloudWatch Metric Filters — Detección de eventos críticos de seguridad
# Basado en CIS AWS Foundations Benchmark (estándar de seguridad)
# ----------------------------------------------------------------

# Filtro 1: Uso de cuenta Root (CRÍTICO)
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "${var.project_name}-root-account-usage"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "${var.project_name}/SIEM"
    value     = "1"
    unit      = "Count"
  }
}

# Filtro 2: Llamadas API no autorizadas
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
  name           = "${var.project_name}-unauthorized-api-calls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "UnauthorizedApiCalls"
    namespace = "${var.project_name}/SIEM"
    value     = "1"
    unit      = "Count"
  }
}

# Filtro 3: Login en consola sin MFA
resource "aws_cloudwatch_log_metric_filter" "console_no_mfa" {
  name           = "${var.project_name}-console-login-no-mfa"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.responseElements.ConsoleLogin = \"Success\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "ConsoleLoginNoMFA"
    namespace = "${var.project_name}/SIEM"
    value     = "1"
    unit      = "Count"
  }
}

# Filtro 4: Cambios en Security Groups
resource "aws_cloudwatch_log_metric_filter" "sg_changes" {
  name           = "${var.project_name}-security-group-changes"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "${var.project_name}/SIEM"
    value     = "1"
    unit      = "Count"
  }
}

# Filtro 5: Cambios en políticas IAM
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "${var.project_name}-iam-policy-changes"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "${var.project_name}/SIEM"
    value     = "1"
    unit      = "Count"
  }
}

# Filtro 6: Creación/eliminación de trails CloudTrail
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "${var.project_name}-cloudtrail-config-changes"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "CloudTrailConfigChanges"
    namespace = "${var.project_name}/SIEM"
    value     = "1"
    unit      = "Count"
  }
}

# Filtro 7: Fallos de autenticación en consola
resource "aws_cloudwatch_log_metric_filter" "console_auth_failures" {
  name           = "${var.project_name}-console-auth-failures"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.responseElements.ConsoleLogin = \"Failure\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "ConsoleAuthFailures"
    namespace = "${var.project_name}/SIEM"
    value     = "1"
    unit      = "Count"
  }
}

# ----------------------------------------------------------------
# CloudWatch Alarms — Notificaciones automáticas por email
# Free Tier: 10 alarmas gratis (12 meses)
# ----------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "${var.project_name}-CRITICO-root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "${var.project_name}/SIEM"
  period              = 300 # 5 minutos
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CRÍTICO: Se usó la cuenta root de AWS. Investigar inmediatamente."
  alarm_actions       = [var.sns_alert_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${var.project_name}-ALTO-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedApiCalls"
  namespace           = "${var.project_name}/SIEM"
  period              = 300
  statistic           = "Sum"
  threshold           = 5 # Alerta si hay 5+ llamadas no autorizadas en 5 min
  alarm_description   = "ALTO: Múltiples llamadas API no autorizadas detectadas. Posible intento de reconocimiento."
  alarm_actions       = [var.sns_alert_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "console_no_mfa" {
  alarm_name          = "${var.project_name}-ALTO-console-login-no-mfa"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleLoginNoMFA"
  namespace           = "${var.project_name}/SIEM"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "ALTO: Login en consola AWS sin MFA. Riesgo de cuenta comprometida."
  alarm_actions       = [var.sns_alert_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "sg_changes" {
  alarm_name          = "${var.project_name}-MEDIO-security-group-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityGroupChanges"
  namespace           = "${var.project_name}/SIEM"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "MEDIO: Cambio en configuración de Security Group detectado."
  alarm_actions       = [var.sns_alert_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "${var.project_name}-ALTO-iam-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChanges"
  namespace           = "${var.project_name}/SIEM"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "ALTO: Cambio en políticas IAM detectado. Verificar autorización."
  alarm_actions       = [var.sns_alert_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  alarm_name          = "${var.project_name}-CRITICO-cloudtrail-config-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailConfigChanges"
  namespace           = "${var.project_name}/SIEM"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CRÍTICO: Configuración de CloudTrail modificada. Posible intento de evasión."
  alarm_actions       = [var.sns_alert_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "console_auth_failures" {
  alarm_name          = "${var.project_name}-MEDIO-console-auth-failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleAuthFailures"
  namespace           = "${var.project_name}/SIEM"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "MEDIO: Múltiples fallos de autenticación en consola AWS. Posible fuerza bruta."
  alarm_actions       = [var.sns_alert_topic_arn]
  treat_missing_data  = "notBreaching"

  tags = var.common_tags
}

# ----------------------------------------------------------------
# CloudWatch Dashboard — Panel de Control del SOC
# Free Tier: 3 dashboards gratis (siempre)
# ----------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "soc_overview" {
  dashboard_name = "${var.project_name}-soc-overview"

  dashboard_body = jsonencode({
    widgets = [
      # Widget 1: Métricas de seguridad en tiempo real
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 24
        height = 6
        properties = {
          title   = "🛡️ SOC — Métricas de Seguridad en Tiempo Real"
          view    = "timeSeries"
          stacked = false
          period  = 300
          stat    = "Sum"
          region  = var.aws_region
          metrics = [
            ["${var.project_name}/SIEM", "RootAccountUsage", { "label" : "Uso Root (CRÍTICO)", "color" : "#d62728" }],
            ["${var.project_name}/SIEM", "UnauthorizedApiCalls", { "label" : "APIs No Autorizadas", "color" : "#ff7f0e" }],
            ["${var.project_name}/SIEM", "ConsoleLoginNoMFA", { "label" : "Login sin MFA", "color" : "#e377c2" }],
            ["${var.project_name}/SIEM", "SecurityGroupChanges", { "label" : "Cambios SG", "color" : "#bcbd22" }],
            ["${var.project_name}/SIEM", "IAMPolicyChanges", { "label" : "Cambios IAM", "color" : "#17becf" }],
            ["${var.project_name}/SIEM", "CloudTrailConfigChanges", { "label" : "Cambios CloudTrail", "color" : "#8c564b" }],
            ["${var.project_name}/SIEM", "ConsoleAuthFailures", { "label" : "Fallos Auth", "color" : "#9467bd" }]
          ]
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      # Widget 2: Logs de llamadas no autorizadas (CloudWatch Insights)
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 12
        height = 8
        properties = {
          title   = "🚨 Últimas Llamadas No Autorizadas"
          region  = var.aws_region
          view    = "table"
          query   = "SOURCE '/aws/cloudtrail/${var.project_name}' | fields @timestamp, eventName, userIdentity.type, sourceIPAddress, errorCode, errorMessage | filter errorCode like /UnauthorizedAccess|AccessDenied/ | sort @timestamp desc | limit 20"
        }
      },
      # Widget 3: Uso de cuenta Root
      {
        type   = "log"
        x      = 12
        y      = 6
        width  = 12
        height = 8
        properties = {
          title   = "👑 Uso de Cuenta Root"
          region  = var.aws_region
          view    = "table"
          query   = "SOURCE '/aws/cloudtrail/${var.project_name}' | fields @timestamp, eventName, sourceIPAddress, userAgent | filter userIdentity.type = 'Root' | sort @timestamp desc | limit 10"
        }
      },
      # Widget 4: Últimos eventos IAM
      {
        type   = "log"
        x      = 0
        y      = 14
        width  = 12
        height = 6
        properties = {
          title   = "🔑 Cambios IAM Recientes"
          region  = var.aws_region
          view    = "table"
          query   = "SOURCE '/aws/cloudtrail/${var.project_name}' | fields @timestamp, eventName, userIdentity.arn, requestParameters | filter eventName like /Policy|Role|User|Group/ and eventName not like /Get|List|Describe/ | sort @timestamp desc | limit 15"
        }
      },
      # Widget 5: Fallos de autenticación
      {
        type   = "log"
        x      = 12
        y      = 14
        width  = 12
        height = 6
        properties = {
          title   = "🔒 Fallos de Autenticación"
          region  = var.aws_region
          view    = "table"
          query   = "SOURCE '/aws/cloudtrail/${var.project_name}' | fields @timestamp, eventName, sourceIPAddress, userIdentity.userName, responseElements.ConsoleLogin | filter eventName = 'ConsoleLogin' and responseElements.ConsoleLogin = 'Failure' | sort @timestamp desc | limit 10"
        }
      }
    ]
  })
}
