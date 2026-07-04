"""
==============================================================================
enrich_finding.py — Lambda de Enriquecimiento de Findings SOAR
==============================================================================
Función: Enriquece los findings de seguridad con contexto adicional antes
         de que el playbook de Step Functions tome decisiones de remediación.

Contexto agregado:
  - Información geográfica de la IP remota (desde el finding)
  - Verificación de IP en la lista de bloqueo (SSM)
  - Detalles adicionales del recurso AWS afectado (EC2, IAM, S3)
  - Clasificación de severidad legible
  - Metadata del analista de seguridad

Disparador: EventBridge → Lambda (antes del Step Functions)
==============================================================================
"""

import boto3
import json
import os
import logging
from datetime import datetime, timezone

# Configuración del logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Clientes AWS
ec2_client = boto3.client("ec2")
ssm_client = boto3.client("ssm")

# Variables de entorno
PROJECT_NAME = os.environ.get("PROJECT_NAME", "soc")
BLOCKLIST_SSM_PARAM = os.environ.get("BLOCKLIST_SSM_PARAM", "/soc/blocklist/ips")

# Tabla de clasificación de severidad GuardDuty → Etiqueta legible
SEVERITY_LABELS = {
    (0.1, 3.9): "LOW",
    (4.0, 6.9): "MEDIUM",
    (7.0, 8.9): "HIGH",
    (9.0, 10.0): "CRITICAL"
}


def lambda_handler(event, context):
    """
    Punto de entrada de la Lambda de enriquecimiento.
    
    Args:
        event: Finding de GuardDuty/Security Hub (desde EventBridge o Step Functions)
        context: Contexto de Lambda
    
    Returns:
        dict: Finding enriquecido con contexto adicional
    """
    logger.info(f"[ENRICH] Enriqueciendo finding: {json.dumps(event, default=str)}")
    
    # Normalizar el evento (puede venir de EventBridge o directamente)
    detail = event.get("detail", event)
    
    # Extraer campos base del finding
    finding_id = detail.get("id", "unknown")
    finding_type = detail.get("type", detail.get("finding_type", "Unknown"))
    severity = float(detail.get("severity", 0))
    region = detail.get("region", os.environ.get("AWS_REGION", "unknown"))
    account_id = detail.get("accountId", "unknown")
    
    # =========================================================================
    # CONSTRUCCIÓN DEL FINDING ENRIQUECIDO
    # =========================================================================
    finding_enriquecido = {
        # Datos base del finding
        "finding_id": finding_id,
        "finding_type": finding_type,
        "severity": severity,
        "severity_label": _clasificar_severidad(severity),
        "region": region,
        "account_id": account_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        
        # Contexto de red (IP remota, geolocalización)
        "network_context": _extraer_contexto_red(detail),
        
        # Contexto del recurso afectado
        "resource_context": _extraer_contexto_recurso(detail),
        
        # Inteligencia de amenaza (verificación de blocklist)
        "threat_context": _verificar_amenaza(detail),
        
        # Recomendaciones para el analista
        "analyst_notes": _generar_notas_analista(finding_type, severity),
        
        # Campos para el playbook de Step Functions
        "playbook_input": {
            "finding_id": finding_id,
            "finding_type": finding_type,
            "severity": severity,
            "auto_remediate": severity >= 7,  # AUTO si es HIGH o CRITICAL
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    }
    
    logger.info(f"[ENRICH] ✅ Finding enriquecido correctamente. Severidad: {severity} ({finding_enriquecido['severity_label']})")
    return finding_enriquecido


def _clasificar_severidad(severity: float) -> str:
    """
    Convierte la severidad numérica de GuardDuty en una etiqueta legible.
    
    Args:
        severity: Valor de severidad entre 0.1 y 10
    
    Returns:
        str: Etiqueta de severidad (LOW, MEDIUM, HIGH, CRITICAL)
    """
    for (min_val, max_val), label in SEVERITY_LABELS.items():
        if min_val <= severity <= max_val:
            return label
    return "INFORMATIONAL"


def _extraer_contexto_red(detail: dict) -> dict:
    """
    Extrae información de red del finding: IP remota, puerto, protocolo, geolocalización.
    
    Args:
        detail: Detalles del finding
    
    Returns:
        dict: Contexto de red extraído
    """
    contexto = {
        "ip_remota": None,
        "puerto_remoto": None,
        "puerto_local": None,
        "protocolo": None,
        "pais": None,
        "ciudad": None,
        "organizacion": None,
        "direccion": None
    }
    
    try:
        service = detail.get("service", {})
        action = service.get("action", {})
        
        # NetworkConnectionAction (la más común en GuardDuty)
        network_action = action.get("networkConnectionAction", {})
        if network_action:
            remote_ip_details = network_action.get("remoteIpDetails", {})
            local_port_details = network_action.get("localPortDetails", {})
            remote_port_details = network_action.get("remotePortDetails", {})
            
            contexto["ip_remota"] = remote_ip_details.get("ipAddressV4")
            contexto["puerto_local"] = local_port_details.get("port")
            contexto["puerto_remoto"] = remote_port_details.get("port")
            contexto["protocolo"] = network_action.get("protocol")
            
            # Geolocalización (incluida en el finding de GuardDuty)
            country = remote_ip_details.get("country", {})
            city = remote_ip_details.get("city", {})
            organization = remote_ip_details.get("organization", {})
            
            contexto["pais"] = country.get("countryName")
            contexto["ciudad"] = city.get("cityName")
            contexto["organizacion"] = organization.get("org")
            
            if contexto["ip_remota"]:
                contexto["direccion"] = f"{contexto['ip_remota']}:{contexto['puerto_remoto'] or '?'}"
        
        # PortProbeAction
        port_probe = action.get("portProbeAction", {})
        if port_probe and not contexto["ip_remota"]:
            probe_details = port_probe.get("portProbeDetails", [{}])
            if probe_details:
                first_probe = probe_details[0]
                remote_ip = first_probe.get("remoteIpDetails", {})
                contexto["ip_remota"] = remote_ip.get("ipAddressV4")
                contexto["pais"] = remote_ip.get("country", {}).get("countryName")
        
        # DNSRequestAction
        dns_action = action.get("dnsRequestAction", {})
        if dns_action:
            contexto["dominio"] = dns_action.get("domain")
            contexto["protocolo"] = "DNS"
        
    except Exception as e:
        logger.warning(f"[ENRICH] ⚠ Error extrayendo contexto de red: {str(e)}")
    
    return contexto


def _extraer_contexto_recurso(detail: dict) -> dict:
    """
    Extrae información del recurso AWS afectado (EC2, IAM User, S3, etc.).
    
    Args:
        detail: Detalles del finding
    
    Returns:
        dict: Contexto del recurso afectado
    """
    contexto = {
        "tipo": None,
        "id": None,
        "arn": None,
        "detalles": {}
    }
    
    try:
        resource = detail.get("resource", {})
        resource_type = resource.get("resourceType", "Unknown")
        contexto["tipo"] = resource_type
        
        if resource_type == "Instance":
            instance_details = resource.get("instanceDetails", {})
            instance_id = instance_details.get("instanceId")
            contexto["id"] = instance_id
            contexto["detalles"] = {
                "instance_type": instance_details.get("instanceType"),
                "image_id": instance_details.get("imageId"),
                "launch_time": instance_details.get("launchTime"),
                "tags": {tag["key"]: tag["value"] for tag in instance_details.get("tags", [])},
                "network_interfaces": [
                    {
                        "private_ip": ni.get("privateIpAddress"),
                        "public_ip": ni.get("publicIp"),
                        "subnet_id": ni.get("subnetId"),
                        "vpc_id": ni.get("vpcId")
                    }
                    for ni in instance_details.get("networkInterfaces", [])
                ]
            }
            
            # Obtener información adicional de EC2 si tenemos el instance_id
            if instance_id:
                try:
                    ec2_response = ec2_client.describe_instances(InstanceIds=[instance_id])
                    if ec2_response["Reservations"]:
                        inst = ec2_response["Reservations"][0]["Instances"][0]
                        contexto["detalles"]["estado"] = inst.get("State", {}).get("Name")
                        contexto["detalles"]["sgs_actuales"] = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                        contexto["arn"] = f"arn:aws:ec2:{detail.get('region', 'us-east-1')}:{detail.get('accountId', 'unknown')}:instance/{instance_id}"
                except Exception as ec2_e:
                    logger.warning(f"[ENRICH] ⚠ No se pudo obtener detalles EC2: {str(ec2_e)}")
        
        elif resource_type == "AccessKey":
            access_key_details = resource.get("accessKeyDetails", {})
            contexto["id"] = access_key_details.get("accessKeyId")
            contexto["detalles"] = {
                "username": access_key_details.get("userName"),
                "access_key_id": access_key_details.get("accessKeyId"),
                "user_type": access_key_details.get("userType"),
                "principal_id": access_key_details.get("principalId")
            }
        
        elif resource_type == "S3Bucket":
            s3_details = resource.get("s3BucketDetails", [{}])
            if s3_details:
                bucket = s3_details[0]
                contexto["id"] = bucket.get("name")
                contexto["arn"] = bucket.get("arn")
                contexto["detalles"] = {
                    "bucket_name": bucket.get("name"),
                    "owner": bucket.get("owner", {}).get("id"),
                    "public_access": bucket.get("publicAccess", {}),
                    "tipo_objeto": bucket.get("type")
                }
        
    except Exception as e:
        logger.warning(f"[ENRICH] ⚠ Error extrayendo contexto de recurso: {str(e)}")
    
    return contexto


def _verificar_amenaza(detail: dict) -> dict:
    """
    Verifica la IP del finding contra la lista de bloqueo en SSM.
    
    Args:
        detail: Detalles del finding
    
    Returns:
        dict: Información de inteligencia de amenaza
    """
    contexto_amenaza = {
        "ip_en_blocklist": False,
        "total_ips_bloqueadas": 0,
        "nivel_confianza": "bajo",
        "fuente": "guardduty-ti"
    }
    
    try:
        # Extraer IP del finding
        service = detail.get("service", {})
        action = service.get("action", {})
        network_action = action.get("networkConnectionAction", {})
        ip_remota = network_action.get("remoteIpDetails", {}).get("ipAddressV4")
        
        if ip_remota:
            # Verificar contra blocklist en SSM
            try:
                param_response = ssm_client.get_parameter(Name=BLOCKLIST_SSM_PARAM)
                ips_bloqueadas = [ip.strip() for ip in param_response["Parameter"]["Value"].split(",") if ip.strip()]
                contexto_amenaza["total_ips_bloqueadas"] = len(ips_bloqueadas)
                contexto_amenaza["ip_en_blocklist"] = ip_remota in ips_bloqueadas
                
                if contexto_amenaza["ip_en_blocklist"]:
                    contexto_amenaza["nivel_confianza"] = "alto"
                    logger.warning(f"[ENRICH] ⚠ IP {ip_remota} está en la blocklist del SOC")
                    
            except ssm_client.exceptions.ParameterNotFound:
                logger.info("[ENRICH] Blocklist SSM no encontrada (normal si es el primer despliegue)")
        
        # Información de TI interna del finding de GuardDuty
        service_info = detail.get("service", {})
        additional_info = service_info.get("additionalInfo", {})
        threat_intel_details = service_info.get("action", {}).get("networkConnectionAction", {}).get(
            "remoteIpDetails", {}).get("organization", {})
        
        if threat_intel_details:
            contexto_amenaza["asn"] = threat_intel_details.get("asn")
            contexto_amenaza["isp"] = threat_intel_details.get("isp")
        
        # Información de threat names de GuardDuty
        if "threatIntelligenceDetails" in service_info:
            ti_details = service_info["threatIntelligenceDetails"]
            if ti_details:
                contexto_amenaza["nombres_amenaza"] = [
                    t.get("threatName") for t in ti_details if t.get("threatName")
                ]
                contexto_amenaza["listas_amenaza"] = [
                    t.get("threatListName") for t in ti_details if t.get("threatListName")
                ]
                contexto_amenaza["nivel_confianza"] = "alto"
        
    except Exception as e:
        logger.warning(f"[ENRICH] ⚠ Error verificando amenaza: {str(e)}")
    
    return contexto_amenaza


def _generar_notas_analista(finding_type: str, severity: float) -> dict:
    """
    Genera notas y recomendaciones para el analista de seguridad basadas
    en el tipo de amenaza y severidad.
    
    Args:
        finding_type: Tipo de finding de GuardDuty
        severity: Nivel de severidad
    
    Returns:
        dict: Notas y recomendaciones para el analista
    """
    notas = {
        "prioridad": "NORMAL",
        "tiempo_respuesta_recomendado": "24 horas",
        "acciones_recomendadas": [],
        "referencias": []
    }
    
    # Definir prioridad según severidad
    if severity >= 9:
        notas["prioridad"] = "CRÍTICA"
        notas["tiempo_respuesta_recomendado"] = "INMEDIATO (< 15 minutos)"
    elif severity >= 7:
        notas["prioridad"] = "ALTA"
        notas["tiempo_respuesta_recomendado"] = "< 1 hora"
    elif severity >= 5:
        notas["prioridad"] = "MEDIA"
        notas["tiempo_respuesta_recomendado"] = "< 4 horas"
    else:
        notas["prioridad"] = "BAJA"
        notas["tiempo_respuesta_recomendado"] = "< 24 horas"
    
    # Recomendaciones por tipo de finding
    if "CryptoCurrency" in finding_type:
        notas["acciones_recomendadas"] = [
            "1. Aislar instancia EC2 de la red",
            "2. Tomar snapshot del volumen EBS para análisis forense",
            "3. Revisar procesos en ejecución en la instancia",
            "4. Verificar costo de EC2 en los últimos días (búsqueda de minería)",
            "5. Revisar IAM roles asignados a la instancia"
        ]
    elif "UnauthorizedAccess:IAMUser" in finding_type or "AnomalousBehavior:IAMUser" in finding_type:
        notas["acciones_recomendadas"] = [
            "1. Deshabilitar inmediatamente las credenciales de acceso",
            "2. Revisar actividad de CloudTrail de los últimos 24 horas",
            "3. Verificar si se crearon nuevos usuarios IAM o roles",
            "4. Revisar políticas IAM para cambios no autorizados",
            "5. Habilitar MFA en todas las cuentas IAM"
        ]
    elif "Recon" in finding_type or "PortProbe" in finding_type:
        notas["acciones_recomendadas"] = [
            "1. Agregar IP fuente a la lista de bloqueo",
            "2. Revisar reglas de Security Groups (¿puertos innecesarios abiertos?)",
            "3. Verificar si hay más reconocimiento desde la misma IP/subred",
            "4. Considerar activar AWS Shield si persiste"
        ]
    elif "Exfiltration" in finding_type:
        notas["acciones_recomendadas"] = [
            "1. Identificar qué datos fueron accedidos o transferidos",
            "2. Verificar políticas de S3 Bucket (acceso público)",
            "3. Revisar logs de S3 Access Logs",
            "4. Notificar al equipo legal si hay datos sensibles involucrados",
            "5. Evaluar activar AWS Macie para clasificación de datos"
        ]
    else:
        notas["acciones_recomendadas"] = [
            "1. Revisar el finding en detalle en la consola de GuardDuty",
            "2. Investigar el recurso afectado",
            "3. Documentar el incidente en el sistema de tickets",
            "4. Determinar si se requiere escalación"
        ]
    
    return notas
