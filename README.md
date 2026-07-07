# Centro de Operaciones de Seguridad (SOC) Automatizado en AWS

Este repositorio contiene la arquitectura de infraestructura como código (IaC) en Terraform para el despliegue de un **SOC (Security Operations Center) Automatizado y Optimizado para el Nivel Gratuito (Free Tier)** de Amazon Web Services (AWS). El diseño proporciona capacidades completas de auditoría, monitoreo, detección de intrusos y respuesta automática ante incidentes con costos mínimos o nulos.

---

## 👥 Presentación del Equipo y Proyecto

Este proyecto fue desarrollado en la materia **Dirección de Proyectos II** en la **Universidad Tecnológica de Aguascalientes**.

* **Institución:** Universidad Tecnológica de Aguascalientes (UTA)
* **Materia:** Dirección de Proyectos II
* **Autores (Alumnos):**
  * **Kevin Antonio Andrade López**
  * **Job Yunior**
  * **Dulce Esmeralda**

---

## 📋 Requisitos de Software

Antes de iniciar con el despliegue, asegúrate de contar con las siguientes herramientas instaladas y configuradas:

1. **Cuenta Activa de AWS:** Se recomienda una cuenta en el nivel gratuito (Free Tier) o cuenta de estudiante.
2. **AWS CLI (Interfaz de Línea de Comandos):** Versión 2.x instalada. Debes configurar tus credenciales locales ejecutando:
   ```bash
   aws configure
   ```
3. **Terraform:** Versión `>= 1.5.0` instalada localmente.
4. **Git:** Para control de versiones y clonación de este repositorio.
5. **Visor de Diagramas (Opcional):** Extensión de PlantUML en tu IDE para visualizar la arquitectura de los diagramas incluidos.

---

## 🚀 Instrucciones de Instalación Paso a Paso

Sigue estos pasos detallados para desplegar el SOC completo en tu cuenta de AWS:

### Paso 1: Clonar el Repositorio
Clona este repositorio en tu máquina local y accede a la carpeta raíz:
```bash
git clone https://github.com/MustySix66/SOC_Direccion_de_Proyectos.git
cd SOC_Direccion_de_Proyectos
```

### Paso 2: Crear el archivo de Variables
Crea una copia del archivo de ejemplo para configurar tus variables personalizadas:
```bash
cp terraform.tfvars.example terraform.tfvars
```
Abre el archivo `terraform.tfvars` recién creado con tu editor de texto y define:
* `aws_region`: La región de AWS (ej. `"us-east-1"`).
* `account_id`: Tu ID de cuenta de AWS de 12 dígitos.
* `alert_email`: Correo electrónico donde quieres recibir las notificaciones del SOC (ej. `tu-correo@utags.edu.mx`).

### Paso 3: Inicializar el Directorio de Terraform
Descarga los proveedores necesarios y los módulos internos:
```bash
terraform init
```

### Paso 4: Validar y Planificar los Recursos
Genera el plan de ejecución de Terraform para verificar que no haya errores y ver qué recursos serán creados:
```bash
terraform plan
```

### Paso 5: Desplegar la Infraestructura
Aplica los cambios en AWS. Escribe `yes` cuando la consola te pida confirmación:
```bash
terraform apply
```

### Paso 6: Confirmar la Suscripción del SOC
> [!IMPORTANT]
> Recibirás un correo electrónico de AWS SNS en la dirección configurada en `alert_email` con el asunto **"AWS Notification - Subscription Confirmation"**. Debes abrirlo y hacer clic en **"Confirm subscription"** para empezar a recibir alertas de seguridad en tiempo real.

---

## 💻 Ejemplo de Uso y Comandos Principales

### Comandos de Administración de la Infraestructura
* **Ver estado actual del SOC:**
  ```bash
  terraform show
  ```
* **Destruir todos los recursos creados (limpieza para evitar cobros futuros):**
  ```bash
  terraform destroy
  ```

### Simulación de Ataque para Probar el SOC (Ejemplo Práctico)
Puedes forzar un error de autorización para comprobar que las alertas del SIEM y el SOAR están funcionando:
```bash
# Intenta listar buckets usando un perfil inexistente o credenciales inválidas
aws s3 ls --profile perfil-invalido
```
* **Resultado:** Esto generará un evento de tipo `AccessDenied` en CloudTrail.
* **Procesamiento:** El filtro métrico de CloudWatch detectará la anomalía, incrementará el contador de la alarma `soc-ezekiel-unauthorized-api-alarm` y enviará un correo de alerta detallado a tu bandeja en menos de 5 minutos.

---

## 📊 Resultado Esperado (Capturas de Pantalla)

Una vez desplegada la infraestructura y generados los primeros eventos de prueba, podrás visualizar el **Dashboard Unificado del SOC** en tu consola de CloudWatch:

![Dashboard del SOC en CloudWatch](docs/expected_result_dashboard.png)
*Figura 1: Vista del Dashboard de CloudWatch configurado automáticamente por Terraform, mostrando métricas de intentos fallidos, llamadas denegadas y logs del SOC.*

---

## 🛠️ Detalle Técnico de los Servicios del SOC

El SOC divide sus operaciones en 5 servicios integrados:

1. **SIEM (Monitoreo e Integridad):** Recolecta logs de auditoría en CloudTrail y VPC Flow Logs en S3, con políticas de ciclo de vida automáticas (Standard ➔ Glacier a los 30 días ➔ eliminación a los 90 días). Cuenta con 7 filtros métricos en CloudWatch para alertar sobre accesos de `root`, acciones sin MFA, o cambios en grupos de seguridad.
2. **EDR/XDR (Detección de Intrusos):** Amazon GuardDuty analiza patrones de comportamiento sospechosos mediante Machine Learning. AWS Security Hub audita la postura frente a los estándares de seguridad (CIS Benchmark).
3. **Networking (Micro-segmentación):** Proporciona subredes aisladas y un Security Group de cuarentena (`sg-isolation`) con reglas cerradas de entrada y salida para mitigar movimientos laterales.
4. **Threat Intelligence:** Ingesta listas de IPs maliciosas conocidas (`malicious-ips.txt`) guardadas en S3 hacia GuardDuty para detectar conexiones de actores maliciosos.
5. **SOAR (Respuesta Automática):** Enrutado por EventBridge, una máquina de estados de Step Functions coordina funciones Lambda en Python para enriquecer alertas con GeoIP y contener incidentes de forma automática (bloqueo de IPs de atacantes, aislamiento de instancias EC2 y desactivación de claves IAM comprometidas).

---

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT**. Puedes consultar más detalles a continuación:

```text
MIT License

Copyright (c) 2026 Kevin Antonio Andrade López, Job Yunior, Dulce Esmeralda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
