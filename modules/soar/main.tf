# ==============================================================================
# MÓDULO: SOAR — main.tf
# Security Orchestration, Automation and Response
# Servicios: EventBridge + Lambda + Step Functions + SNS
#
# COSTO ESTIMADO (Free Tier):
#   - Lambda: GRATIS (1M requests + 400K GB-segundos / mes, siempre)
#   - Step Functions: GRATIS (4,000 transiciones / mes, siempre)
#   - EventBridge: GRATIS (eventos nativos AWS son gratuitos)
#   - SNS: GRATIS (1M publishes + 1,000 emails / mes, 12 meses)
#   - CloudWatch Logs Lambda: GRATIS (5GB / mes, 12 meses)
# ==============================================================================

# ----------------------------------------------------------------
# Datos de la cuenta y región
# ----------------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ----------------------------------------------------------------
# EMPAQUETADO DE FUNCIONES LAMBDA
# Terraform comprime automáticamente los archivos Python
# ----------------------------------------------------------------

# Paquete ZIP para Lambda de Auto-Remediación
data "archive_file" "auto_remediate" {
  type        = "zip"
  source_file = "${path.module}/lambda/auto_remediate.py"
  output_path = "${path.module}/lambda/auto_remediate.zip"
}

# Paquete ZIP para Lambda de Enriquecimiento de Findings
data "archive_file" "enrich_finding" {
  type        = "zip"
  source_file = "${path.module}/lambda/enrich_finding.py"
  output_path = "${path.module}/lambda/enrich_finding.zip"
}

# ----------------------------------------------------------------
# IAM — Roles y Políticas para Lambda
# ----------------------------------------------------------------

# Política personalizada para la Lambda de Auto-Remediación
data "aws_iam_policy_document" "lambda_auto_remediate" {
  statement {
    sid    = "AllowEC2IsolationActions"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:ModifyInstanceAttribute",
      "ec2:CreateTags",
      "ec2:DescribeVpcs"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowIAMKeyDisable"
    effect = "Allow"
    actions = [
      "iam:UpdateAccessKey",
      "iam:TagUser",
      "iam:ListAccessKeys"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowSSMBlocklist"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:PutParameter"
    ]
    resources = [
      "arn:aws:ssm:${var.aws_region}:${var.account_id}:parameter/${var.project_name}/*"
    ]
  }

  statement {
    sid    = "AllowGuardDutyArchive"
    effect = "Allow"
    actions = [
      "guardduty:ArchiveFindings",
      "guardduty:ListDetectors"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowSNSPublish"
    effect = "Allow"
    actions = ["sns:Publish"]
    resources = [var.sns_alert_topic_arn]
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${var.account_id}:*"]
  }

  statement {
    sid    = "AllowStepFunctions"
    effect = "Allow"
    actions = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.soc_playbook.arn]
  }
}

# Política personalizada para Lambda de Enriquecimiento
data "aws_iam_policy_document" "lambda_enrich" {
  statement {
    sid    = "AllowSSMRead"
    effect = "Allow"
    actions = ["ssm:GetParameter"]
    resources = [
      "arn:aws:ssm:${var.aws_region}:${var.account_id}:parameter/${var.project_name}/*"
    ]
  }

  statement {
    sid    = "AllowEC2Describe"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeTags"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${var.account_id}:*"]
  }
}

# Política de confianza (Trust Policy) para Lambda
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Política de confianza para Step Functions
data "aws_iam_policy_document" "stepfunctions_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

# IAM Role para Lambda de Auto-Remediación
resource "aws_iam_role" "lambda_auto_remediate" {
  name               = "${var.project_name}-role-lambda-autoremediacion"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "lambda_auto_remediate" {
  name   = "${var.project_name}-policy-lambda-autoremediacion"
  role   = aws_iam_role.lambda_auto_remediate.id
  policy = data.aws_iam_policy_document.lambda_auto_remediate.json
}

# IAM Role para Lambda de Enriquecimiento
resource "aws_iam_role" "lambda_enrich" {
  name               = "${var.project_name}-role-lambda-enriquecimiento"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "lambda_enrich" {
  name   = "${var.project_name}-policy-lambda-enriquecimiento"
  role   = aws_iam_role.lambda_enrich.id
  policy = data.aws_iam_policy_document.lambda_enrich.json
}

# IAM Role para Step Functions
resource "aws_iam_role" "stepfunctions" {
  name               = "${var.project_name}-role-stepfunctions"
  assume_role_policy = data.aws_iam_policy_document.stepfunctions_assume_role.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "stepfunctions_lambda" {
  name = "${var.project_name}-policy-stepfunctions-lambda"
  role = aws_iam_role.stepfunctions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          aws_lambda_function.auto_remediate.arn,
          aws_lambda_function.enrich_finding.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["sns:Publish"]
        Resource = [var.sns_alert_topic_arn]
      }
    ]
  })
}

# ----------------------------------------------------------------
# FUNCIONES LAMBDA — Motor de Respuesta del SOAR
# ----------------------------------------------------------------

# Lambda 1: Auto-Remediación
# Aísla instancias, deshabilita keys IAM, bloquea IPs
resource "aws_lambda_function" "auto_remediate" {
  function_name    = "${var.project_name}-auto-remediacion"
  description      = "SOAR: Auto-remediación de findings críticos de GuardDuty/SecurityHub"
  filename         = data.archive_file.auto_remediate.output_path
  source_code_hash = data.archive_file.auto_remediate.output_base64sha256
  handler          = "auto_remediate.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60   # 60 segundos máximo
  memory_size      = 128  # 128 MB (mínimo, dentro del free tier)
  role             = aws_iam_role.lambda_auto_remediate.arn

  environment {
    variables = {
      PROJECT_NAME              = var.project_name
      ENVIRONMENT               = var.environment
      ISOLATION_SG_ID           = var.isolation_sg_id
      SNS_ALERT_TOPIC_ARN       = var.sns_alert_topic_arn
      BLOCKLIST_SSM_PARAM       = var.blocklist_ssm_param
      GUARDDUTY_DETECTOR_ID     = var.guardduty_detector_id != null ? var.guardduty_detector_id : ""
      SEVERITY_THRESHOLD        = tostring(var.severity_threshold_auto_remediate)
      AUTO_REMEDIATION_ENABLED  = tostring(var.auto_remediation_enabled)
      STEPFUNCTIONS_ARN         = aws_sfn_state_machine.soc_playbook.arn
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-auto-remediacion"
    Purpose = "SOAR-Remediation"
  })
}

# CloudWatch Log Group para Lambda Auto-Remediación (retención)
resource "aws_cloudwatch_log_group" "lambda_auto_remediate" {
  name              = "/aws/lambda/${aws_lambda_function.auto_remediate.function_name}"
  retention_in_days = 14

  tags = var.common_tags
}

# Lambda 2: Enriquecimiento de Findings
# Agrega contexto adicional a los findings para el analista
resource "aws_lambda_function" "enrich_finding" {
  function_name    = "${var.project_name}-enriquecimiento-findings"
  description      = "SOAR: Enriquece findings con contexto geográfico, instancia y blocklist"
  filename         = data.archive_file.enrich_finding.output_path
  source_code_hash = data.archive_file.enrich_finding.output_base64sha256
  handler          = "enrich_finding.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 128
  role             = aws_iam_role.lambda_enrich.arn

  environment {
    variables = {
      PROJECT_NAME        = var.project_name
      BLOCKLIST_SSM_PARAM = var.blocklist_ssm_param
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-enriquecimiento"
    Purpose = "SOAR-Enrichment"
  })
}

resource "aws_cloudwatch_log_group" "lambda_enrich" {
  name              = "/aws/lambda/${aws_lambda_function.enrich_finding.function_name}"
  retention_in_days = 14

  tags = var.common_tags
}

# ----------------------------------------------------------------
# AWS STEP FUNCTIONS — Playbook de Respuesta a Incidentes
# Orquesta el flujo: Enriquecer → Evaluar → Remediar → Notificar
# Free Tier: 4,000 transiciones de estado / mes (siempre gratis)
# ----------------------------------------------------------------
resource "aws_sfn_state_machine" "soc_playbook" {
  name     = "${var.project_name}-playbook-respuesta-incidentes"
  role_arn = aws_iam_role.stepfunctions.arn

  # Definición del Playbook como máquina de estados
  definition = jsonencode({
    Comment = "SOC Playbook: Flujo de respuesta automatizada a incidentes de seguridad"
    StartAt = "EnriquecerFinding"

    States = {
      # Paso 1: Enriquecer el finding con contexto adicional
      EnriquecerFinding = {
        Type     = "Task"
        Resource = aws_lambda_function.enrich_finding.arn
        Comment  = "Agrega contexto: geoIP, detalles de instancia, verificación de blocklist"
        Next     = "EvaluarSeveridad"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.TooManyRequestsException"]
          IntervalSeconds = 2
          MaxAttempts     = 3
          BackoffRate     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "NotificarError"
        }]
      }

      # Paso 2: Evaluar la severidad del finding
      EvaluarSeveridad = {
        Type    = "Choice"
        Comment = "Enruta según la severidad del finding"
        Choices = [
          {
            Variable      = "$.severity"
            NumericGreaterThanEquals = 8 # CRÍTICO (8-10)
            Next          = "RemediacionCritica"
          },
          {
            Variable      = "$.severity"
            NumericGreaterThanEquals = 5 # ALTO (5-7)
            Next          = "RemediacionAlta"
          }
        ]
        Default = "SoloNotificar" # MEDIO/BAJO: solo notificar
      }

      # Paso 3A: Remediación para findings CRÍTICOS
      RemediacionCritica = {
        Type     = "Task"
        Resource = aws_lambda_function.auto_remediate.arn
        Comment  = "Auto-remedía: aísla instancia, deshabilita keys, bloquea IP"
        Next     = "NotificarCritico"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "NotificarError"
        }]
      }

      # Paso 3B: Remediación para findings ALTOS
      RemediacionAlta = {
        Type     = "Task"
        Resource = aws_lambda_function.auto_remediate.arn
        Comment  = "Remediación parcial: bloquea IP, notifica al analista"
        Next     = "NotificarAlto"
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "NotificarError"
        }]
      }

      # Paso 4A: Notificar evento CRÍTICO
      NotificarCritico = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Comment  = "Envía alerta crítica por email"
        Parameters = {
          TopicArn  = var.sns_alert_topic_arn
          "Message.$" = "States.Format('[CRÍTICO] SOC Alert - Finding: {} | Acciones tomadas: {} | Timestamp: {}', $.finding_id, $.actions_taken, $.timestamp)"
          Subject   = "[SOC-CRITICO] Incidente de Seguridad Detectado y Remediado"
        }
        Next = "RegistrarEnS3"
      }

      # Paso 4B: Notificar evento ALTO
      NotificarAlto = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Comment  = "Envía alerta alta por email"
        Parameters = {
          TopicArn  = var.sns_alert_topic_arn
          "Message.$" = "States.Format('[ALTO] SOC Alert - Finding: {} | Requiere revisión manual. Timestamp: {}', $.finding_id, $.timestamp)"
          Subject   = "[SOC-ALTO] Hallazgo de Seguridad Requiere Atención"
        }
        Next = "RegistrarEnS3"
      }

      # Paso 4C: Solo notificar (MEDIO/BAJO)
      SoloNotificar = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Comment  = "Notificación informativa para severidades media/baja"
        Parameters = {
          TopicArn  = var.sns_alert_topic_arn
          "Message.$" = "States.Format('[INFO] SOC Finding - Tipo: {} | Severidad: {} | Para revisión en próximo ciclo.', $.finding_type, $.severity)"
          Subject   = "[SOC-INFO] Hallazgo de Seguridad para Revisión"
        }
        Next = "RegistrarEnS3"
      }

      # Paso 5: Registrar resultado en S3 (auditoría)
      RegistrarEnS3 = {
        Type    = "Pass"
        Comment = "Marca el playbook como completado exitosamente"
        End     = true
        Result  = { status = "completed", result = "success" }
      }

      # Manejo de errores
      NotificarError = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Comment  = "Notifica error en el playbook de remediación"
        Parameters = {
          TopicArn = var.sns_alert_topic_arn
          "Message.$" = "States.Format('[ERROR] SOAR Playbook falló. Estado: {}. Requiere intervención manual.', $)"
          Subject  = "[SOC-ERROR] Fallo en Playbook de Auto-Remediación"
        }
        End = true
      }
    }
  })

  logging_configuration {
    level                  = "ERROR"
    include_execution_data = false
    log_destination        = "${aws_cloudwatch_log_group.stepfunctions.arn}:*"
  }

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-playbook"
    Purpose = "SOAR-Orchestration"
  })
}

resource "aws_cloudwatch_log_group" "stepfunctions" {
  name              = "/aws/states/${var.project_name}-playbook"
  retention_in_days = 14

  tags = var.common_tags
}

# ----------------------------------------------------------------
# EVENTBRIDGE RULES — Disparadores del SOAR
# Conecta los eventos de GuardDuty/Security Hub con las Lambdas
# ----------------------------------------------------------------

# Regla 1: GuardDuty Finding → Step Functions (Playbook)
resource "aws_cloudwatch_event_rule" "guardduty_to_soar" {
  name        = "${var.project_name}-guardduty-to-soar"
  description = "Dispara el playbook SOAR cuando GuardDuty detecta una amenaza"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 5] }] # Severidad ALTA o mayor
    }
  })

  tags = var.common_tags
}

# Target: EventBridge → Lambda de Enriquecimiento
resource "aws_cloudwatch_event_target" "guardduty_to_enrich" {
  rule      = aws_cloudwatch_event_rule.guardduty_to_soar.name
  target_id = "EnrichFinding"
  arn       = aws_lambda_function.enrich_finding.arn
}

resource "aws_lambda_permission" "eventbridge_enrich" {
  statement_id  = "AllowEventBridgeEnrich"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enrich_finding.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_to_soar.arn
}

# Target: EventBridge → Step Functions (solo si auto-remediación está activa)
resource "aws_cloudwatch_event_target" "guardduty_to_stepfunctions" {
  rule      = aws_cloudwatch_event_rule.guardduty_to_soar.name
  target_id = "StartSOARPlaybook"
  arn       = aws_sfn_state_machine.soc_playbook.arn
  role_arn  = aws_iam_role.eventbridge_stepfunctions.arn

  input_transformer {
    input_paths = {
      finding_id   = "$.detail.id"
      finding_type = "$.detail.type"
      severity     = "$.detail.severity"
      account_id   = "$.detail.accountId"
      region       = "$.detail.region"
      resource     = "$.detail.resource"
      service      = "$.detail.service"
    }
    input_template = <<-EOF
    {
      "finding_id": "<finding_id>",
      "finding_type": "<finding_type>",
      "severity": <severity>,
      "account_id": "<account_id>",
      "region": "<region>",
      "resource": <resource>,
      "service": <service>,
      "timestamp": "<aws.events.event.time>"
    }
    EOF
  }
}

# IAM Role para EventBridge invocar Step Functions
resource "aws_iam_role" "eventbridge_stepfunctions" {
  name = "${var.project_name}-role-eventbridge-sfn"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
    }]
  })

  tags = var.common_tags
}

resource "aws_iam_role_policy" "eventbridge_stepfunctions" {
  name = "${var.project_name}-policy-eventbridge-sfn"
  role = aws_iam_role.eventbridge_stepfunctions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["states:StartExecution"]
      Resource = [aws_sfn_state_machine.soc_playbook.arn]
    }]
  })
}

# Regla 2: Security Hub Findings → SNS (Notificaciones directas)
resource "aws_cloudwatch_event_rule" "securityhub_to_sns" {
  name        = "${var.project_name}-securityhub-to-sns"
  description = "Envía findings críticos de Security Hub directamente al equipo SOC"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        RecordState  = ["ACTIVE"]
        WorkflowState = ["NEW"]
      }
    }
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "securityhub_to_sns" {
  rule      = aws_cloudwatch_event_rule.securityhub_to_sns.name
  target_id = "AlertSOCTeam"
  arn       = var.sns_alert_topic_arn

  input_transformer {
    input_paths = {
      title       = "$.detail.findings[0].Title"
      severity    = "$.detail.findings[0].Severity.Label"
      description = "$.detail.findings[0].Description"
      resource    = "$.detail.findings[0].Resources[0].Id"
    }
    input_template = "\"[SOC Security Hub] <severity>: <title>\\nRecurso afectado: <resource>\\nDescripción: <description>\""
  }
}

# Permiso SNS para recibir de EventBridge
resource "aws_sns_topic_policy" "soc_alerts" {
  arn = var.sns_alert_topic_arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowEventBridgePublish"
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = var.sns_alert_topic_arn
    }]
  })
}
