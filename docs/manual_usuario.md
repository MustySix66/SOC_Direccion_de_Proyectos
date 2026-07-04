# Manual de Usuario — SOC en AWS con Terraform
## Universidad Tecnológica del Área de Guadalajara (UTAGS)
### Proyecto: SOC-Ezekiel | Contacto: 231011@utags.edu.mx

---

> [!NOTE]
> Este manual cubre el despliegue completo de un SOC en AWS usando Terraform, optimizado para cuentas de estudiante y el nivel gratuito (Free Tier) de AWS.

---

## Tabla de Contenidos

1. [Arquitectura del SOC](#1-arquitectura-del-soc)
2. [Requisitos Previos](#2-requisitos-previos)
3. [Estructura del Proyecto](#3-estructura-del-proyecto)
4. [Configuración Inicial](#4-configuración-inicial)
5. [Despliegue Paso a Paso](#5-despliegue-paso-a-paso)
6. [Verificación Post-Despliegue](#6-verificación-post-despliegue)
7. [Uso del SOC](#7-uso-del-soc)
8. [Respuesta a Incidentes](#8-respuesta-a-incidentes)
9. [Estimación de Costos](#9-estimación-de-costos)
10. [Mantenimiento](#10-mantenimiento)
11. [Destrucción del Entorno](#11-destrucción-del-entorno)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Arquitectura del SOC

El SOC desplegado utiliza cuatro capas de seguridad complementarias:

```
┌──────────────────────────────────────────────────────────────────┐
│                      SOC en AWS — Free Tier                       │
├─────────────┬──────────────┬───────────────┬─────────────────────┤
│   SIEM      │   EDR/XDR   │     SOAR      │  Threat Intelligence │
├─────────────┼──────────────┼───────────────┼─────────────────────┤
│ CloudTrail  │ GuardDuty   │ EventBridge   │ GuardDuty IPSets    │
│ CloudWatch  │ Security Hub│ Lambda x2     │ ThreatIntelSets     │
│ S3 (logs)   │ Inspector v2│ Step Functions│ IAM Access Analyzer  │
│ CW Alarms   │ IAM Analyzer│ SNS Alerts    │ SSM Blocklist       │
│ CW Dashboard│             │               │                     │
└─────────────┴──────────────┴───────────────┴─────────────────────┘
                              │
                    SNS → 231011@utags.edu.mx
```

### Componentes y su función

| Componente | Servicio AWS | Función |
|---|---|---|
| **SIEM** | CloudTrail + CloudWatch + S3 | Centraliza y analiza todos los logs de la cuenta AWS |
| **EDR/XDR** | GuardDuty + Security Hub | Detecta amenazas usando ML; agrega findings en un dashboard |
| **SOAR** | EventBridge + Lambda + Step Functions | Automatiza la respuesta a incidentes detectados |
| **Threat Intel** | GuardDuty IPSets + IAM Access Analyzer | Enriquece la detección con listas de IPs/dominios maliciosos |

---

## 2. Requisitos Previos

### Software requerido

| Herramienta | Versión mínima | Instalación |
|---|---|---|
| **Terraform** | >= 1.5.0 | [terraform.io/downloads](https://developer.hashicorp.com/terraform/downloads) |
| **AWS CLI** | >= 2.0 | [aws.amazon.com/cli](https://aws.amazon.com/cli/) |
| **Python** | >= 3.10 | [python.org](https://www.python.org/) (solo para desarrollo local) |
| **Git** | >= 2.0 | [git-scm.com](https://git-scm.com/) |

### Cuenta AWS

- Cuenta AWS activa (Free Tier / Student / AWS Educate)
- Permisos de **AdministratorAccess** o permisos equivalentes para:
  - GuardDuty, Security Hub, Inspector, IAM, S3, CloudTrail
  - Lambda, Step Functions, EventBridge, SNS, SSM, CloudWatch

### Verificar instalación

```powershell
# Verificar Terraform
terraform version
# Output esperado: Terraform v1.5.x o superior

# Verificar AWS CLI
aws --version
# Output esperado: aws-cli/2.x.x

# Verificar credenciales configuradas
aws sts get-caller-identity
# Output esperado: {"UserId": "...", "Account": "123456789012", "Arn": "..."}
```

---

## 3. Estructura del Proyecto

```
soc-ezekiel/
├── main.tf                          # 🏗️ Módulo raíz (orquestador)
├── variables.tf                     # ⚙️ Variables globales con descripciones
├── outputs.tf                       # 📤 Outputs post-despliegue
├── versions.tf                      # 🔒 Versiones de providers
├── terraform.tfvars.example         # 📝 Plantilla de configuración
│
├── modules/
│   ├── networking/                  # 🌐 VPC, subnets, security groups
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   │
│   ├── siem/                        # 📊 CloudTrail, CloudWatch, S3, Dashboard
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   │
│   ├── edr_xdr/                     # 🛡️ GuardDuty, Security Hub, Inspector
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   │
│   ├── soar/                        # ⚡ EventBridge, Lambda, Step Functions
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── lambda/
│   │       ├── auto_remediate.py    # 🔧 Auto-remediación (aísla, bloquea, deshabilita)
│   │       └── enrich_finding.py    # 🔍 Enriquecimiento de findings
│   │
│   └── threat_intel/                # 🔎 IPSets, TISets, IAM Analyzer
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
│
└── docs/
    ├── manual_usuario.md            # 📖 Este documento
    ├── diagrama_codigo.puml         # 🗺️ Estructura del código Terraform
    └── diagrama_soc.puml            # 🔄 Flujo funcional del SOC
```

---

## 4. Configuración Inicial

### Paso 1: Obtener tu AWS Account ID

```powershell
aws sts get-caller-identity --query Account --output text
# Output: 123456789012  ← Guarda este número
```

### Paso 2: Crear el archivo de variables

```powershell
# Desde la raíz del proyecto
Copy-Item terraform.tfvars.example terraform.tfvars
```

Edita `terraform.tfvars` con tus datos:

```hcl
# ─── OBLIGATORIO: Cambia estos valores ───────────────────────────
aws_region   = "us-east-1"          # ← Tu región preferida
account_id   = "123456789012"        # ← Tu AWS Account ID (12 dígitos)
project_name = "soc-ezekiel"

# ─── Ya configurado ──────────────────────────────────────────────
alert_email  = "231011@utags.edu.mx" # Email para alertas SOC
environment  = "dev"

# ─── Opcionales ──────────────────────────────────────────────────
enable_guardduty    = true   # Recomendado: true
enable_security_hub = true   # Recomendado: true
enable_inspector    = false  # Activar si tienes EC2/ECR
auto_remediation_enabled = false  # ⚠ false para dev/testing
```

> [!IMPORTANT]
> **NUNCA** subas `terraform.tfvars` a Git. Agrega `terraform.tfvars` a tu `.gitignore` para proteger tu `account_id`.

### Paso 3: Configurar credenciales AWS

```powershell
# Opción A: Variables de entorno (recomendada para sesiones temporales)
$env:AWS_ACCESS_KEY_ID="AKIA..."
$env:AWS_SECRET_ACCESS_KEY="..."
$env:AWS_DEFAULT_REGION="us-east-1"

# Opción B: AWS CLI configure (para credenciales permanentes)
aws configure
# AWS Access Key ID: AKIA...
# AWS Secret Access Key: ...
# Default region name: us-east-1
# Default output format: json

# Opción C: AWS SSO (para cuentas AWS Educate/Organizations)
aws sso login --profile estudiante
```

---

## 5. Despliegue Paso a Paso

### Paso 1: Inicializar Terraform

```powershell
cd "d:\DevOps\SOC Ezekiel"

terraform init
```

**Salida esperada:**
```
Initializing the backend...
Initializing modules...
- edr_xdr in modules/edr_xdr
- networking in modules/networking
- siem in modules/siem
- soar in modules/soar
- threat_intel in modules/threat_intel

Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.0"...
- Installing hashicorp/aws v5.x.x...
- Finding hashicorp/archive versions matching "~> 2.4"...

Terraform has been successfully initialized!
```

### Paso 2: Validar la configuración

```powershell
terraform validate
# Output esperado: Success! The configuration is valid.
```

### Paso 3: Revisar el plan de despliegue

```powershell
terraform plan -out=soc.tfplan
```

Revisa la salida. Verás aproximadamente **45-55 recursos** a crear. Verifica que:
- ✅ No aparece ningún recurso marcado con `-` (destruir)
- ✅ La región mostrada es la que configuraste
- ✅ El bucket S3 usa tu `account_id` en el nombre

### Paso 4: Aplicar el despliegue

```powershell
terraform apply soc.tfplan

# O en un solo paso (sin plan previo):
terraform apply -auto-approve
```

**Tiempo estimado de despliegue:** 3-8 minutos

**Salida final esperada:**
```
Apply complete! Resources: 52 added, 0 changed, 0 destroyed.

Outputs:

soc_summary = {
  "ambient"              = "dev"
  "auto_remediacion"     = false
  "dashboard_url"        = "https://console.aws.amazon.com/cloudwatch/..."
  "email_alertas"        = "231011@utags.edu.mx"
  "guardduty_activo"     = true
  "nombre_proyecto"      = "soc-ezekiel"
  "region"               = "us-east-1"
  "security_hub_activo"  = true
}
```

### Paso 5: Confirmar suscripción de email

> [!IMPORTANT]
> Después del `terraform apply`, AWS enviará un email a `231011@utags.edu.mx` para confirmar la suscripción SNS. **Debes hacer clic en "Confirm subscription"** o no recibirás alertas.

---

## 6. Verificación Post-Despliegue

### Verificar GuardDuty

```powershell
# Obtener el ID del detector
$DETECTOR_ID = terraform output -raw guardduty_detector_id

# Verificar que está activo
aws guardduty get-detector --detector-id $DETECTOR_ID

# Listar findings (vacío inicialmente)
aws guardduty list-findings --detector-id $DETECTOR_ID
```

### Verificar CloudTrail

```powershell
# Listar trails
aws cloudtrail describe-trails --include-shadow-trails false

# Verificar que está activo
aws cloudtrail get-trail-status --name soc-ezekiel-trail
# Output: "IsLogging": true
```

### Verificar SNS

```powershell
$SNS_ARN = terraform output -raw sns_alerts_topic_arn

# Ver suscripciones del tópico
aws sns list-subscriptions-by-topic --topic-arn $SNS_ARN

# Enviar un mensaje de prueba
aws sns publish `
  --topic-arn $SNS_ARN `
  --subject "[SOC-TEST] Prueba de Alertas" `
  --message "El sistema SOC está funcionando correctamente. Esta es una alerta de prueba."
```

### Verificar Dashboard CloudWatch

```powershell
# Obtener URL del dashboard
terraform output siem_dashboard_url
# Abre la URL en tu navegador
```

---

## 7. Uso del SOC

### Consolas Principales

| Panel | URL |
|---|---|
| **SOC Dashboard** | CloudWatch → Dashboards → `soc-ezekiel-soc-overview` |
| **GuardDuty Findings** | [console.aws.amazon.com/guardduty](https://console.aws.amazon.com/guardduty) |
| **Security Hub** | [console.aws.amazon.com/securityhub](https://console.aws.amazon.com/securityhub) |
| **CloudTrail** | [console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail) |
| **Step Functions** | [console.aws.amazon.com/states](https://console.aws.amazon.com/states) |
| **IAM Access Analyzer** | [console.aws.amazon.com/access-analyzer](https://console.aws.amazon.com/access-analyzer) |

### Consultas útiles en CloudWatch Logs Insights

Accede a CloudWatch → Logs → Insights → selecciona el Log Group `/aws/cloudtrail/soc-ezekiel`

**Consultar todas las acciones de la cuenta Root:**
```
fields @timestamp, eventName, sourceIPAddress, userAgent
| filter userIdentity.type = 'Root'
| sort @timestamp desc
| limit 20
```

**Ver llamadas API no autorizadas:**
```
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, errorCode
| filter errorCode like /UnauthorizedAccess|AccessDenied/
| sort @timestamp desc
| limit 50
```

**Ver cambios en IAM:**
```
fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventName like /Policy|Role|User/ and eventName not like /Get|List|Describe/
| sort @timestamp desc
| limit 30
```

**Ver intentos de login fallidos:**
```
fields @timestamp, eventName, sourceIPAddress, userIdentity.userName
| filter eventName = 'ConsoleLogin' and responseElements.ConsoleLogin = 'Failure'
| sort @timestamp desc
| limit 20
```

---

## 8. Respuesta a Incidentes

### Niveles de Severidad

| Nivel | Rango | Tiempo Respuesta | Acción |
|---|---|---|---|
| 🔴 **CRÍTICO** | 9.0 - 10.0 | < 15 min | Auto-remediación + alerta inmediata |
| 🟠 **ALTO** | 7.0 - 8.9 | < 1 hora | Auto-remediación + revisión |
| 🟡 **MEDIO** | 5.0 - 6.9 | < 4 horas | Notificación + revisión manual |
| 🟢 **BAJO** | 0.1 - 4.9 | < 24 horas | Registro + revisión en ciclo |

### Playbook de Respuesta Manual

#### Si recibes alerta de "Root Account Usage":
1. Ir a IAM → Activity → ver qué hizo root
2. Verificar que no hay nuevos usuarios IAM creados
3. Cambiar contraseña root si no fue uso autorizado
4. Activar MFA en la cuenta root si no está activo

#### Si recibes alerta de "Unauthorized API Calls":
1. CloudTrail → Event History → filtrar por el período
2. Identificar el usuario/rol que hace las llamadas
3. Verificar si el acceso es legítimo
4. Si no: deshabilitar credenciales IAM afectadas

#### Para restaurar una instancia EC2 aislada:
```powershell
# 1. Ver los SGs originales (guardados en tags)
aws ec2 describe-instances --instance-ids i-XXXXXXXXX `
  --query 'Reservations[].Instances[].Tags[?Key==`soc-ezekiel:sgs_originales`].Value'

# 2. Restaurar los SGs originales
aws ec2 modify-instance-attribute `
  --instance-id i-XXXXXXXXX `
  --groups sg-original1 sg-original2

# 3. Eliminar el tag de estado
aws ec2 delete-tags `
  --resources i-XXXXXXXXX `
  --tags Key=soc-ezekiel:estado
```

#### Para reactivar una clave IAM deshabilitada:
```powershell
# Verificar primero que el usuario no fue comprometido
aws iam list-access-keys --user-name NombreUsuario

# Solo si el acceso fue legítimo
aws iam update-access-key `
  --user-name NombreUsuario `
  --access-key-id AKIAIOSFODNN7EXAMPLE `
  --status Active
```

---

## 9. Estimación de Costos

### Costo Mensual Estimado (Cuenta Estudiante / Free Tier)

| Servicio | Tier Gratuito | Costo Post-Tier | Estimado/mes |
|---|---|---|---|
| **CloudTrail** | 1 trail gratis (siempre) | $2/100K eventos | **$0** |
| **CloudWatch Logs** | 5 GB ingesta (12 meses) | $0.50/GB | **$0** |
| **CloudWatch Alarms** | 10 alarmas (12 meses) | $0.10/alarma | **$0** |
| **CloudWatch Dashboard** | 3 dashboards (siempre) | $3/dashboard | **$0** |
| **S3** | 5 GB (12 meses) | $0.023/GB | **$0** |
| **Lambda** | 1M req / 400K GB-s (siempre) | $0.20/1M req | **$0** |
| **Step Functions** | 4,000 transitions (siempre) | $0.025/1K | **$0** |
| **EventBridge** | Eventos AWS gratis | $1/1M eventos | **$0** |
| **SNS** | 1,000 emails (12 meses) | $2/100K | **$0** |
| **SSM Parameters** | Standard: gratis | - | **$0** |
| **IAM/VPC/SG** | Siempre gratis | - | **$0** |
| **GuardDuty** | 30 días trial | ~$1-4/mes (cuenta pequeña) | **$0 (trial)** |
| **Security Hub** | 30 días trial | ~$0.001/finding | **$0 (trial)** |
| **Inspector** | 30 días trial | Solo con EC2/ECR | **$0 (desactivado)** |

**Total estimado en Free Tier: $0/mes** ✅
**Total estimado post-trial (sin EC2): ~$2-6/mes** 💚

> [!TIP]
> Para minimizar costos después del período de prueba:
> - Configura `guardduty_finding_frequency = "SIX_HOURS"` (menor frecuencia = menos procesamiento)
> - Mantén `enable_inspector = false` si no tienes instancias EC2
> - Usa `environment = "dev"` para no crear recursos adicionales costosos

---

## 10. Mantenimiento

### Actualizar la lista de IPs maliciosas (Threat Intelligence)

```powershell
# 1. Editar el archivo en Terraform
# modules/threat_intel/main.tf → aws_s3_object.malicious_ips → content

# 2. Aplicar cambios
terraform apply -target=module.threat_intel.aws_s3_object.malicious_ips

# 3. GuardDuty actualizará automáticamente el IPSet
```

### Consultar el Blocklist actual de IPs

```powershell
aws ssm get-parameter --name "/soc-ezekiel/blocklist/ips" --query "Parameter.Value"
```

### Limpiar el Blocklist de IPs (SOAR)

```powershell
aws ssm put-parameter `
  --name "/soc-ezekiel/blocklist/ips" `
  --value "0.0.0.0" `
  --type StringList `
  --overwrite
```

### Ver historial de ejecuciones del Playbook (Step Functions)

```powershell
$SFN_ARN = terraform output -raw soar_stepfunctions_arn

aws stepfunctions list-executions `
  --state-machine-arn $SFN_ARN `
  --status-filter SUCCEEDED `
  --max-results 10
```

### Actualizar Terraform

```powershell
# Actualizar providers a versiones más recientes
terraform init -upgrade

# Revisar cambios antes de aplicar
terraform plan

# Aplicar actualizaciones
terraform apply
```

---

## 11. Destrucción del Entorno

> [!CAUTION]
> Esto eliminará **TODOS los recursos** del SOC incluyendo logs almacenados en S3. Esta acción es **irreversible**.

```powershell
# Revisar qué se va a destruir
terraform plan -destroy

# Destruir todo el entorno
terraform destroy

# Confirmar escribiendo "yes" cuando se solicite
```

**Nota:** El bucket S3 con logs puede requerir vaciado manual si tiene objetos:
```powershell
$BUCKET = terraform output -raw siem_logs_bucket

# Vaciar el bucket primero
aws s3 rm s3://$BUCKET --recursive

# Luego destruir
terraform destroy
```

---

## 12. Troubleshooting

### Error: "BucketAlreadyExists"
```
Error: creating S3 Bucket: BucketAlreadyExists
```
**Solución:** El nombre del bucket ya existe (es globalmente único). Cambia `project_name` en `terraform.tfvars`.

### Error: "GuardDuty already enabled"
```
Error: creating GuardDuty Detector: already enabled
```
**Solución:** GuardDuty ya está activo en tu cuenta. Importa el recurso:
```powershell
$DETECTOR_ID = aws guardduty list-detectors --query "DetectorIds[0]" --output text
terraform import module.edr_xdr.aws_guardduty_detector.soc[0] $DETECTOR_ID
```

### Error: "Security Hub not enabled"
```
Error: InvalidAccessException: Account is not subscribed to AWS Security Hub
```
**Solución:** Habilitar Security Hub primero o agregar `depends_on`:
```powershell
aws securityhub enable-security-hub --enable-default-standards
```

### Error: "AccessDenied" al crear recursos
**Solución:** Verifica que tu usuario/rol tenga los permisos necesarios:
```powershell
aws iam get-user
aws iam list-attached-user-policies --user-name TU_USUARIO
```

### No recibo emails de alerta
1. Verifica que confirmaste la suscripción SNS en tu bandeja de entrada
2. Revisa la carpeta de SPAM
3. Verifica el estado de la suscripción:
```powershell
$SNS_ARN = terraform output -raw sns_alerts_topic_arn
aws sns list-subscriptions-by-topic --topic-arn $SNS_ARN
# SubscriptionStatus debe ser "Confirmed", no "PendingConfirmation"
```

### Las alarmas no se disparan
1. Verifica que CloudTrail esté enviando logs a CloudWatch:
```powershell
aws cloudwatch describe-log-groups --log-group-name-prefix "/aws/cloudtrail/soc-ezekiel"
```
2. Verifica que los metric filters estén creados:
```powershell
aws cloudwatch describe-metric-filters --log-group-name "/aws/cloudtrail/soc-ezekiel"
```

---

## Referencias

- [Amazon GuardDuty — User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/)
- [AWS Security Hub — User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/)
- [AWS CloudTrail — User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [AWS Free Tier](https://aws.amazon.com/free/)

---

*Documento generado para el proyecto SOC-Ezekiel — UTAGS 2024*
*Contacto: 231011@utags.edu.mx*
