"""
==============================================================================
auto_remediate.py — Lambda de Auto-Remediación SOAR
==============================================================================
Función: Responde automáticamente a findings críticos de GuardDuty/SecurityHub
Acciones disponibles:
  1. Aislar instancia EC2 (asignar Security Group de cuarentena)
  2. Deshabilitar clave de acceso IAM comprometida
  3. Registrar IP maliciosa en la lista de bloqueo (SSM Parameter Store)
  4. Archivar el finding en GuardDuty (marcar como procesado)

Disparador: EventBridge (GuardDuty Finding) → Lambda
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

# Clientes AWS (reutilizables entre invocaciones = mejor rendimiento)
ec2_client = boto3.client("ec2")
iam_client = boto3.client("iam")
ssm_client = boto3.client("ssm")
sns_client = boto3.client("sns")

# Variables de entorno (configuradas en Terraform)
ISOLATION_SG_ID = os.environ.get("ISOLATION_SG_ID", "")
SNS_ALERT_TOPIC_ARN = os.environ.get("SNS_ALERT_TOPIC_ARN", "")
BLOCKLIST_SSM_PARAM = os.environ.get("BLOCKLIST_SSM_PARAM", "/soc/blocklist/ips")
SEVERITY_THRESHOLD = float(os.environ.get("SEVERITY_THRESHOLD", "8"))
AUTO_REMEDIATION_ENABLED = os.environ.get("AUTO_REMEDIATION_ENABLED", "false").lower() == "true"
PROJECT_NAME = os.environ.get("PROJECT_NAME", "soc")
GUARDDUTY_DETECTOR_ID = os.environ.get("GUARDDUTY_DETECTOR_ID", "")


def lambda_handler(event, context):
    """
    Punto de entrada principal de la Lambda.
    
    Args:
        event: Evento de EventBridge con el finding de seguridad
        context: Contexto de ejecución de Lambda
    
    Returns:
        dict: Resultado de las acciones de remediación tomadas
    """
    logger.info(f"[SOAR] Evento recibido: {json.dumps(event, default=str)}")
    
    # Extraer detalles del finding
    detail = event.get("detail", event)  # Soporta tanto EventBridge como Step Functions
    finding_id = detail.get("id", detail.get("finding_id", "unknown"))
    finding_type = detail.get("type", detail.get("finding_type", "Unknown"))
    severity = float(detail.get("severity", 0))
    
    resultado = {
        "finding_id": finding_id,
        "finding_type": finding_type,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "auto_remediation_active": AUTO_REMEDIATION_ENABLED,
        "actions_taken": [],
        "status": "processed"
    }
    
    # Verificar umbral de severidad
    if severity < SEVERITY_THRESHOLD:
        logger.info(f"[SOAR] Severidad {severity} por debajo del umbral {SEVERITY_THRESHOLD}. Solo registrando.")
        resultado["status"] = "below_threshold"
        resultado["actions_taken"].append({
            "action": "logged",
            "status": "success",
            "note": f"Severidad {severity} < umbral {SEVERITY_THRESHOLD}"
        })
        return resultado
    
    # Si auto-remediación está desactivada, solo notificar
    if not AUTO_REMEDIATION_ENABLED:
        logger.warning(f"[SOAR] Auto-remediación DESACTIVADA. Finding {finding_id} requiere revisión manual.")
        resultado["status"] = "manual_review_required"
        resultado["actions_taken"].append({
            "action": "manual_review",
            "status": "pending",
            "note": "auto_remediation_enabled=false en terraform.tfvars"
        })
        _notificar_revision_manual(finding_id, finding_type, severity)
        return resultado
    
    # =========================================================================
    # LÓGICA DE REMEDIACIÓN según tipo de amenaza
    # =========================================================================
    logger.info(f"[SOAR] Iniciando remediación para: {finding_type} (severidad: {severity})")
    
    # Tipo 1: Minería de criptomonedas o malware en EC2
    if any(t in finding_type for t in ["CryptoCurrency", "Trojan", "Backdoor:EC2", "Behavior:EC2"]):
        accion = _aislar_instancia_ec2(detail)
        resultado["actions_taken"].append(accion)
    
    # Tipo 2: Acceso no autorizado desde EC2
    elif any(t in finding_type for t in ["UnauthorizedAccess:EC2", "Recon:EC2"]):
        accion = _aislar_instancia_ec2(detail)
        resultado["actions_taken"].append(accion)
        accion2 = _bloquear_ip_remota(detail)
        resultado["actions_taken"].append(accion2)
    
    # Tipo 3: Comportamiento anómalo en IAM
    elif any(t in finding_type for t in ["UnauthorizedAccess:IAMUser", "AnomalousBehavior:IAMUser", "Persistence:IAMUser"]):
        accion = _deshabilitar_clave_iam(detail)
        resultado["actions_taken"].append(accion)
    
    # Tipo 4: Reconocimiento de red
    elif any(t in finding_type for t in ["Recon:", "PortProbeUnprotectedPort", "SSHBruteForce", "RDPBruteForce"]):
        accion = _bloquear_ip_remota(detail)
        resultado["actions_taken"].append(accion)
    
    # Tipo 5: Exfiltración de datos
    elif any(t in finding_type for t in ["Exfiltration:", "S3", "DNS"]):
        accion = _bloquear_ip_remota(detail)
        resultado["actions_taken"].append(accion)
        logger.warning(f"[SOAR] Posible exfiltración detectada. Revisar logs S3/DNS manualmente.")
    
    # Tipo genérico: Notificar para revisión manual
    else:
        logger.info(f"[SOAR] Tipo de finding sin playbook específico: {finding_type}")
        resultado["actions_taken"].append({
            "action": "no_specific_playbook",
            "status": "notified",
            "note": f"Finding type '{finding_type}' requiere playbook personalizado"
        })
    
    # Archivar el finding en GuardDuty si se tomó alguna acción
    if GUARDDUTY_DETECTOR_ID and any(a.get("status") == "success" for a in resultado["actions_taken"]):
        _archivar_finding_guardduty(finding_id)
    
    logger.info(f"[SOAR] Resultado final: {json.dumps(resultado, default=str)}")
    return resultado


def _aislar_instancia_ec2(detail: dict) -> dict:
    """
    Aísla una instancia EC2 comprometida asignando el Security Group de cuarentena.
    La instancia queda sin acceso de red entrante ni saliente.
    
    Args:
        detail: Detalles del finding de GuardDuty
    
    Returns:
        dict: Resultado de la acción de aislamiento
    """
    try:
        resource = detail.get("resource", {})
        instance_details = resource.get("instanceDetails", {})
        instance_id = instance_details.get("instanceId")
        
        if not instance_id:
            return {
                "action": "aislar_instancia_ec2",
                "status": "skipped",
                "reason": "No se encontró instanceId en el finding"
            }
        
        if not ISOLATION_SG_ID:
            return {
                "action": "aislar_instancia_ec2",
                "status": "failed",
                "reason": "ISOLATION_SG_ID no configurado en variables de entorno"
            }
        
        # Obtener SGs actuales antes de aislar
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        sgs_originales = [sg["GroupId"] for sg in instance["SecurityGroups"]]
        
        # Verificar si ya está aislada
        if sgs_originales == [ISOLATION_SG_ID]:
            return {
                "action": "aislar_instancia_ec2",
                "status": "already_isolated",
                "instance_id": instance_id
            }
        
        # Etiquetar instancia como comprometida (para trazabilidad)
        ec2_client.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": f"{PROJECT_NAME}:estado", "Value": "AISLADA"},
                {"Key": f"{PROJECT_NAME}:tiempo_aislamiento", "Value": datetime.now(timezone.utc).isoformat()},
                {"Key": f"{PROJECT_NAME}:sgs_originales", "Value": ",".join(sgs_originales)},
                {"Key": f"{PROJECT_NAME}:finding_tipo", "Value": detail.get("type", "unknown")}
            ]
        )
        
        # Asignar SOLO el Security Group de aislamiento (sin tráfico)
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[ISOLATION_SG_ID]
        )
        
        logger.info(f"[SOAR] ✅ Instancia {instance_id} AISLADA. SGs originales: {sgs_originales}")
        
        return {
            "action": "aislar_instancia_ec2",
            "status": "success",
            "instance_id": instance_id,
            "sgs_originales": sgs_originales,
            "sg_cuarentena": ISOLATION_SG_ID,
            "nota": "Para restaurar: asignar SGs originales y eliminar tag soc:estado"
        }
        
    except ec2_client.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"[SOAR] ❌ Error al aislar instancia: {error_code} - {str(e)}")
        return {
            "action": "aislar_instancia_ec2",
            "status": "failed",
            "error_code": error_code,
            "error": str(e)
        }
    except Exception as e:
        logger.error(f"[SOAR] ❌ Error inesperado al aislar instancia: {str(e)}")
        return {"action": "aislar_instancia_ec2", "status": "failed", "error": str(e)}


def _deshabilitar_clave_iam(detail: dict) -> dict:
    """
    Deshabilita la clave de acceso IAM comprometida para detener el acceso no autorizado.
    
    Args:
        detail: Detalles del finding de GuardDuty
    
    Returns:
        dict: Resultado de la acción de deshabilitación
    """
    try:
        resource = detail.get("resource", {})
        access_key_details = resource.get("accessKeyDetails", {})
        username = access_key_details.get("userName")
        access_key_id = access_key_details.get("accessKeyId")
        
        if not username or not access_key_id:
            return {
                "action": "deshabilitar_clave_iam",
                "status": "skipped",
                "reason": "Faltan userName o accessKeyId en el finding"
            }
        
        # Deshabilitar la clave de acceso
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status="Inactive"
        )
        
        # Etiquetar al usuario como sospechoso
        iam_client.tag_user(
            UserName=username,
            Tags=[
                {"Key": f"{PROJECT_NAME}:estado", "Value": "SUSPENDIDO"},
                {"Key": f"{PROJECT_NAME}:tiempo_suspension", "Value": datetime.now(timezone.utc).isoformat()},
                {"Key": f"{PROJECT_NAME}:clave_deshabilitada", "Value": access_key_id}
            ]
        )
        
        logger.info(f"[SOAR] ✅ Clave IAM {access_key_id} del usuario {username} DESHABILITADA")
        
        return {
            "action": "deshabilitar_clave_iam",
            "status": "success",
            "username": username,
            "access_key_id": access_key_id,
            "nota": "La clave está Inactive. Revisar y eliminar si es comprometida."
        }
        
    except iam_client.exceptions.NoSuchEntityException:
        return {
            "action": "deshabilitar_clave_iam",
            "status": "failed",
            "reason": "Usuario o clave no encontrada (puede haber sido eliminada)"
        }
    except Exception as e:
        logger.error(f"[SOAR] ❌ Error al deshabilitar clave IAM: {str(e)}")
        return {"action": "deshabilitar_clave_iam", "status": "failed", "error": str(e)}


def _bloquear_ip_remota(detail: dict) -> dict:
    """
    Registra la IP remota maliciosa en el parámetro SSM de lista de bloqueo.
    La lista es consumida por GuardDuty IPSet para bloqueo activo.
    
    Args:
        detail: Detalles del finding de GuardDuty
    
    Returns:
        dict: Resultado del bloqueo de IP
    """
    try:
        # Extraer IP según el tipo de acción del finding
        service = detail.get("service", {})
        action = service.get("action", {})
        ip_remota = None
        
        # Intentar extraer de networkConnectionAction
        network_action = action.get("networkConnectionAction", {})
        if network_action:
            ip_remota = network_action.get("remoteIpDetails", {}).get("ipAddressV4")
        
        # Intentar extraer de portProbeAction
        if not ip_remota:
            port_probe = action.get("portProbeAction", {})
            port_probe_details = port_probe.get("portProbeDetails", [{}])
            if port_probe_details:
                ip_remota = port_probe_details[0].get("remoteIpDetails", {}).get("ipAddressV4")
        
        if not ip_remota:
            return {
                "action": "bloquear_ip",
                "status": "skipped",
                "reason": "No se encontró IP remota en el finding"
            }
        
        # Obtener lista actual del SSM Parameter Store
        try:
            param_response = ssm_client.get_parameter(Name=BLOCKLIST_SSM_PARAM)
            ips_actuales = [ip.strip() for ip in param_response["Parameter"]["Value"].split(",") if ip.strip() and ip.strip() != "0.0.0.0"]
        except ssm_client.exceptions.ParameterNotFound:
            ips_actuales = []
        
        # Agregar IP si no existe ya
        if ip_remota in ips_actuales:
            return {
                "action": "bloquear_ip",
                "status": "already_blocked",
                "ip": ip_remota
            }
        
        ips_actuales.append(ip_remota)
        
        # Actualizar la lista en SSM
        ssm_client.put_parameter(
            Name=BLOCKLIST_SSM_PARAM,
            Value=",".join(ips_actuales),
            Type="StringList",
            Overwrite=True,
            Description=f"IPs maliciosas - Actualizado por SOAR el {datetime.now(timezone.utc).isoformat()}"
        )
        
        logger.info(f"[SOAR] ✅ IP {ip_remota} agregada a la lista de bloqueo. Total IPs bloqueadas: {len(ips_actuales)}")
        
        return {
            "action": "bloquear_ip",
            "status": "success",
            "ip_bloqueada": ip_remota,
            "total_ips_bloqueadas": len(ips_actuales),
            "nota": "IP registrada en SSM. GuardDuty IPSet se actualizará en el próximo ciclo."
        }
        
    except Exception as e:
        logger.error(f"[SOAR] ❌ Error al bloquear IP: {str(e)}")
        return {"action": "bloquear_ip", "status": "failed", "error": str(e)}


def _archivar_finding_guardduty(finding_id: str) -> None:
    """
    Archiva el finding en GuardDuty para indicar que fue procesado por el SOAR.
    
    Args:
        finding_id: ID del finding a archivar
    """
    try:
        if GUARDDUTY_DETECTOR_ID:
            guardduty_client = boto3.client("guardduty")
            guardduty_client.archive_findings(
                DetectorId=GUARDDUTY_DETECTOR_ID,
                FindingIds=[finding_id]
            )
            logger.info(f"[SOAR] ✅ Finding {finding_id} archivado en GuardDuty")
    except Exception as e:
        logger.warning(f"[SOAR] ⚠ No se pudo archivar finding {finding_id}: {str(e)}")


def _notificar_revision_manual(finding_id: str, finding_type: str, severity: float) -> None:
    """
    Envía notificación SNS solicitando revisión manual del finding.
    
    Args:
        finding_id: ID del finding
        finding_type: Tipo de amenaza detectada
        severity: Nivel de severidad (1-10)
    """
    try:
        if SNS_ALERT_TOPIC_ARN:
            mensaje = (
                f"[SOC - REVISIÓN MANUAL REQUERIDA]\n\n"
                f"Finding ID: {finding_id}\n"
                f"Tipo: {finding_type}\n"
                f"Severidad: {severity}/10\n"
                f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n\n"
                f"La auto-remediación está DESACTIVADA.\n"
                f"Por favor revisa el finding en la consola de GuardDuty:\n"
                f"https://console.aws.amazon.com/guardduty/home#/findings"
            )
            sns_client.publish(
                TopicArn=SNS_ALERT_TOPIC_ARN,
                Subject=f"[SOC-MANUAL] Finding {severity:.1f}/10 - {finding_type[:50]}",
                Message=mensaje
            )
    except Exception as e:
        logger.error(f"[SOAR] Error enviando notificación SNS: {str(e)}")
