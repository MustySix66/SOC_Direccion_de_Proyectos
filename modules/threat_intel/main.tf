# ==============================================================================
# MÓDULO: THREAT INTELLIGENCE — main.tf
# Inteligencia de Amenazas integrada con GuardDuty
# Servicios: GuardDuty IPSets + ThreatIntelSets + S3
#
# COSTO ESTIMADO:
#   - GuardDuty IPSet: INCLUIDO en el costo base de GuardDuty
#   - GuardDuty ThreatIntelSet: INCLUIDO en el costo base de GuardDuty
#   - S3 (archivos TI): GRATIS dentro del free tier (5GB)
# ==============================================================================

# ----------------------------------------------------------------
# S3 Objects — Archivos de Inteligencia de Amenazas
# ----------------------------------------------------------------

# Lista inicial de IPs maliciosas conocidas (actualizable)
# Formato: una IP o CIDR por línea
resource "aws_s3_object" "malicious_ips" {
  bucket  = var.logs_bucket_id
  key     = "threat-intel/malicious-ips.txt"

  # Lista de IPs de ejemplo (rangos reservados para documentación RFC 5737)
  # REEMPLAZA estas IPs con feeds reales de inteligencia de amenazas
  # Fuentes recomendadas (gratuitas):
  #   - https://feeds.dshield.org/top10-2.txt
  #   - https://feodotracker.abuse.ch/downloads/ipblocklist.txt
  #   - https://www.binarydefense.com/banlist.txt
  content = <<-IPLIST
    # SOC Ezekiel — Lista de IPs Maliciosas
    # Fuente: GuardDuty Custom Threat Intelligence Set
    # Actualizado: ${timestamp()}
    # NOTA: Estas son IPs de ejemplo RFC 5737 (no reales)
    # Reemplazar con IPs de feeds de inteligencia de amenazas reales

    # Ejemplo: Rangos de documentación RFC 5737 (INOFENSIVOS)
    192.0.2.1
    192.0.2.2
    198.51.100.1
    203.0.113.1

    # Para actualizar esta lista:
    # 1. Edita este archivo con IPs reales de tus feeds de TI
    # 2. Ejecuta: terraform apply
    # 3. GuardDuty actualizará el IPSet automáticamente
  IPLIST

  content_type = "text/plain"

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-malicious-ips"
    Purpose = "GuardDuty-IPSet"
  })
}

# Lista de dominios maliciosos conocidos
resource "aws_s3_object" "malicious_domains" {
  bucket  = var.logs_bucket_id
  key     = "threat-intel/malicious-domains.txt"

  content = <<-DOMLIST
    # SOC Ezekiel — Lista de Dominios Maliciosos
    # Formato: un dominio por línea (sin http/https)
    # Fuentes recomendadas (gratuitas):
    #   - https://urlhaus.abuse.ch/downloads/text/
    #   - https://malwaredomainlist.com/

    # Ejemplos de dominios maliciosos conocidos (FICTICIOS para demo)
    # malware-c2-example.bad
    # phishing-fake-bank.xyz

    # NOTA: GuardDuty analiza consultas DNS y compara contra esta lista
    # Reemplaza con dominios reales de tus feeds de inteligencia
  DOMLIST

  content_type = "text/plain"

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-malicious-domains"
    Purpose = "GuardDuty-ThreatIntelSet"
  })
}

# ----------------------------------------------------------------
# GUARDDUTY IPSET — Lista de IPs que GuardDuty vigilará activamente
# Cuando una IP de este set genera tráfico en la cuenta,
# GuardDuty creará un finding con mayor prioridad
# ----------------------------------------------------------------
resource "aws_guardduty_ipset" "malicious_ips" {
  count = var.enable_custom_threat_intel && var.guardduty_detector_id != null ? 1 : 0

  detector_id = var.guardduty_detector_id
  name        = "${var.project_name}-ips-maliciosas"
  format      = "TXT"

  # Referencia al archivo de IPs en S3
  location = "https://s3.amazonaws.com/${var.logs_bucket_id}/${aws_s3_object.malicious_ips.key}"

  activate = true # Activar inmediatamente

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-ipset-maliciosas"
    Purpose = "ThreatIntelligence-IPSet"
  })

  depends_on = [aws_s3_object.malicious_ips]
}

# ----------------------------------------------------------------
# GUARDDUTY THREAT INTEL SET — Feeds de amenazas externos
# GuardDuty usará estas listas para correlacionar con sus propios
# algoritmos de ML y aumentar la confianza de los findings
# ----------------------------------------------------------------
resource "aws_guardduty_threatintelset" "malicious_domains" {
  count = var.enable_custom_threat_intel && var.guardduty_detector_id != null ? 1 : 0

  detector_id = var.guardduty_detector_id
  name        = "${var.project_name}-dominios-maliciosos"
  format      = "TXT"

  location = "https://s3.amazonaws.com/${var.logs_bucket_id}/${aws_s3_object.malicious_domains.key}"

  activate = true

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-threatintelset-dominios"
    Purpose = "ThreatIntelligence-DomainSet"
  })

  depends_on = [aws_s3_object.malicious_domains]
}

# ----------------------------------------------------------------
# IAM Access Analyzer — Reporte de recursos públicamente accesibles
# Detecta automáticamente buckets S3, roles IAM, funciones Lambda,
# etc. que tienen acceso desde fuera de la cuenta
# COSTO: GRATIS
# ----------------------------------------------------------------
resource "aws_accessanalyzer_analyzer" "threat_surface" {
  analyzer_name = "${var.project_name}-threat-surface-analyzer"
  type          = "ACCOUNT"

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-access-analyzer-ti"
    Purpose = "ThreatSurface-Analysis"
  })
}

# ----------------------------------------------------------------
# EventBridge Rule — Alertas de IAM Access Analyzer
# Notifica cuando Access Analyzer detecta acceso externo a recursos
# ----------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "access_analyzer_findings" {
  name        = "${var.project_name}-access-analyzer-findings"
  description = "Alerta cuando IAM Access Analyzer detecta recursos expuestos externamente"

  event_pattern = jsonencode({
    source      = ["aws.access-analyzer"]
    detail-type = ["Access Analyzer Finding"]
    detail = {
      status = ["ACTIVE"]
    }
  })

  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "access_analyzer_to_sns" {
  rule      = aws_cloudwatch_event_rule.access_analyzer_findings.name
  target_id = "NotifySOCTeam"
  arn       = var.sns_alert_topic_arn

  input_transformer {
    input_paths = {
      resource    = "$.detail.resource"
      resource_type = "$.detail.resourceType"
      finding_type  = "$.detail.findingType"
      region      = "$.detail.region"
    }
    input_template = "\"[SOC-IAMAnalyzer] Recurso con acceso externo detectado:\\nRecurso: <resource>\\nTipo: <resource_type>\\nFinding: <finding_type>\\nRegión: <region>\\n\\nRevisa en: https://console.aws.amazon.com/access-analyzer\""
  }
}

# ----------------------------------------------------------------
# CloudWatch Dashboard — Threat Intelligence
# Visualización del estado de la inteligencia de amenazas
# ----------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "threat_intel" {
  dashboard_name = "${var.project_name}-threat-intelligence"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 3
        properties = {
          markdown = "# 🔍 SOC Threat Intelligence Dashboard\n\n**Inteligencia de Amenazas Activa** | GuardDuty IPSets + ThreatIntelSets + IAM Access Analyzer\n\n📧 Alertas enviadas a: `${var.project_name}` | 🌎 Región: `${var.aws_region}`"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 3
        width  = 12
        height = 6
        properties = {
          title   = "GuardDuty Findings por Tipo de Amenaza"
          view    = "timeSeries"
          region  = var.aws_region
          period  = 3600
          stat    = "Sum"
          metrics = [
            ["AWS/GuardDuty", "FindingCount", "DetectorId", var.guardduty_detector_id != null ? var.guardduty_detector_id : "none", { "label" : "Total Findings" }]
          ]
          yAxis = { left = { min = 0 } }
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 3
        width  = 12
        height = 6
        properties = {
          title  = "Últimos Findings de GuardDuty"
          region = var.aws_region
          view   = "table"
          query  = "SOURCE '/aws/guardduty/${var.project_name}/findings' | fields @timestamp, type, severity, resource.resourceType | sort @timestamp desc | limit 20"
        }
      }
    ]
  })
}
