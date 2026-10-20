# Guía de despliegue en AWS Academy (Cloud Architecting)

Paso a paso para levantar **todo** el laboratorio SIEM en el sandbox de
*AWS Academy Learner Lab / Cloud Architecting*. Todo está automatizado: tú solo
ejecutas `deploy.sh` y AWS construye la red, las máquinas y los servicios.

---

## 0. Requisitos previos (una sola vez)

1. **Inicia el laboratorio** en AWS Academy y pulsa **Start Lab** (semáforo verde).
2. Abre **AWS Details → AWS CLI → Show** y copia el bloque de credenciales.
   Pégalo en tu equipo en `~/.aws/credentials` (perfil `default`). Ejemplo:
   ```ini
   [default]
   aws_access_key_id=ASIA...
   aws_secret_access_key=...
   aws_session_token=...
   ```
   > Estas credenciales **caducan** cuando se detiene el lab; vuelve a copiarlas si expiran.
3. Ten instalada la **AWS CLI v2** y `bash` (Linux/macOS, WSL en Windows, o AWS CloudShell).
4. **Par de claves:** usa el que el sandbox ya trae, llamado **`vockey`** (no crees uno).
   En **AWS Details → Download PEM** guarda `labsuser.pem` (típicamente en `~/Downloads`).
   Dale permisos: `chmod 400 ~/Downloads/labsuser.pem`.
5. (Recomendado) Averigua tu IP pública (`curl ifconfig.me`) para restringir el acceso.

> **Región:** `us-east-1` (no la cambies). **IAM es de solo lectura** en este sandbox, así
> que el despliegue **no crea ningún rol**: las instancias descargan sus scripts mediante una
> URL prefirmada de S3 que `deploy.sh` genera.

### Restricciones del sandbox ya contempladas en el proyecto
- **Máximo 9 instancias** (más = cuenta suspendida): por eso solo hay dos perfiles,
  `minima` (7) y `completa` (9).
- **Tipos de instancia** hasta `t3.medium` (2 vCPU / 4 GB): el SIEM Wazuh corre en
  `t3.medium` con swap y el heap del indexer limitado para caber en 4 GB.
- **Discos** gp2 de ≤ 35 GB.
- **AMIs:** Ubuntu 22.04 (Canonical) y Windows Server 2019. Si tu sandbox rechazara la AMI
  de Ubuntu por política, avísame y adapto los hosts Linux a Amazon Linux 2023.

---

## 1. Desplegar

Desde la carpeta `AWS/` (en CloudShell, WSL, Linux o macOS):

```bash
chmod +x *.sh
./deploy.sh -c TU_IP_PUBLICA/32
```

Parámetros de `deploy.sh` (todos opcionales, con valores por defecto del sandbox):

| Flag | Significado | Valor por defecto |
|---|---|---|
| `-k` | Par de claves EC2 | `vockey` |
| `-p` | Perfil: `minima` \| `completa` | `completa` |
| `-c` | CIDR de administración (SSH/RDP/dashboard) | `0.0.0.0/0` (mejor `TU_IP/32`) |
| `-r` | Región | `us-east-1` |
| `-s` | Nombre del stack | `siem-lab` |

### ¿Qué perfil elegir? (máximo 9 instancias en el sandbox)
- **`minima`** (7 instancias): SIEM, DC, web+Suricata, firewall, atacante, 1 Windows, 1 Linux.
  Cubre **las 5 fuentes de logs y los 5 ataques**.
- **`completa`** (9 instancias): `minima` + DNS1 + NTP (más tráfico normal y sincronización
  horaria). Es el **máximo permitido**; los demás servicios (DNS2/DHCP/SMTP/2ª estación)
  están en `userdata/` y se intercambian editando el template sin pasar de 9.

`deploy.sh` crea un bucket S3, empaqueta y sube los scripts, genera la URL prefirmada, lanza
el stack y muestra las salidas (URL del dashboard, IPs públicas, etc.).

---

## 2. Esperar el aprovisionamiento

CloudFormation termina en 3-5 min, pero **el software se instala dentro de las instancias**:

| Instancia | Tiempo aprox. | Señal de "listo" |
|---|---|---|
| Wazuh (SIEM) | 15-30 min | `https://<IP_PUBLICA_SIEM>` responde (login `admin`) |
| Windows DC | 15-25 min (2-3 reinicios) | `C:\siem-state.txt` = `DONE` |
| Estaciones Windows | +10-15 min tras el DC | `C:\siem-state.txt` = `DONE` |
| Linux / servicios | 5-10 min | agente activo |

Revisa el progreso:
- **Linux:** `ssh -i ~/Downloads/labsuser.pem ubuntu@<IP> 'sudo tail -f /var/log/siem-bootstrap.log'`
- **Windows:** conéctate por RDP y abre `C:\siem-bootstrap.log`.

---

## 3. Acceder

- **Dashboard Wazuh:** `https://<IP_PUBLICA_SIEM>` → usuario `admin`.
  La contraseña está en el SIEM en `/root/wazuh_passwords.txt`:
  ```bash
  ssh -i ~/Downloads/labsuser.pem ubuntu@<IP_SIEM> 'sudo cat /root/wazuh_passwords.txt'
  ```
- **DC Windows (RDP):** usuario `Administrator`, contraseña `P@ssw0rd` (fijada por el
  script del dominio). O recupera la contraseña autogenerada con la key pair en
  **EC2 → Connect → RDP client → Get password**.
- **Atacante:** `ssh -i ~/Downloads/labsuser.pem ubuntu@<IP_ATACANTE>` y luego `sudo su - attacker`.

Comprueba en el dashboard que los **agentes** aparecen *Active* (Management → Agents):
`dc-empresa`, `web-server`, `win-ws-01`, `linux-01`, `fw-gateway`, etc.

---

## 4. Ejecutar los escenarios (Fase 3) y evaluar (Fase 4)

En la estación atacante:

```bash
sudo su - attacker
source ~/lab.env          # carga los objetivos (IPs de AWS)
cd ~/ataques
./run_all_attacks.sh      # Escenario 2: 5 ataques x5 repeticiones
```

O usa el menú guiado (súbelo o clónalo en el atacante):

```bash
./run_lab_aws.sh
```

Para la **evaluación** (tasa de detección ≥ 80 %), tras ejecutar los escenarios:

```bash
# En el SIEM (o copiando alerts.json):
python3 evaluacion/recolectar_alertas.py \
   --alerts-file /var/ossec/logs/alerts/alerts.json \
   --inicio 2026-06-01T14:00:00Z --fin 2026-06-01T18:00:00Z --out alertas.json
python3 evaluacion/calcular_metricas.py \
   --ataques ~/ataques/log_ataques.csv --alertas alertas.json --out reporte_metricas.md
```

> Los ataques 3 (Pass-the-Hash) y 5 (payload) requieren un hash NTLM / credenciales
> capturados en el ejercicio, igual que en el laboratorio físico. Se lanzan por separado
> (opción 4 del menú).

---

## 5. Apagar / eliminar (¡importante para el presupuesto!)

- **Parar sin borrar** (para seguir otro día): detén las instancias desde la consola EC2
  (o `Stop Lab` en Academy). *Ojo:* al reiniciar pueden cambiar las IPs públicas.
- **Eliminar todo** (red, VMs, bucket):
  ```bash
  ./teardown.sh -y
  ```

---

## 6. Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| `deploy.sh`: *credentials* | Credenciales caducadas | Vuelve a copiar **AWS Details → AWS CLI** |
| El stack falla en una instancia | Tipo de instancia no permitido / límite de vCPU | Usa `-p minima` o tipos más pequeños |
| Dashboard no responde a los 30 min | Instalación de Wazuh aún en curso o poca RAM | Revisa `/var/log/siem-bootstrap.log` (en 4 GB tarda; el script crea swap) |
| Estación Windows no se une al dominio | El DC aún no estaba listo | El script reintenta en cada arranque (hasta 6). Verifica que el DC esté en `DONE` |
| Un agente no aparece *Active* | SG o IP del manager | Confirma 1514/tcp hacia 10.0.30.10 y la IP en `ossec.conf` |
| Flow Logs no se crean | Entrega IAM no permitida | Deja `EnableVpcFlowLogs=no` (la fuente #2 ya la da el fw-gateway) |

> **AMIs de Windows 10 y Kali:** ver `MAPEO_RED_FISICA_A_AWS.md` (§2) para la justificación
> de las sustituciones por Windows Server 2019 y Ubuntu+toolkit.
