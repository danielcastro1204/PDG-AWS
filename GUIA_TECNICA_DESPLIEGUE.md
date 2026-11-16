# Guía Técnica de Despliegue — Laboratorio SIEM (Wazuh) en la nube (AWS), dual-stack IPv4/IPv6

> **Propósito.** Este documento es la guía técnica reproducible del proyecto *"Diseño,
> implementación y validación de una plataforma SIEM open source para el monitoreo de eventos
> de seguridad en una red empresarial"*, en su versión migrada a la nube de Amazon Web Services.
> Documenta, de principio a fin, cómo reconstruir el laboratorio completo, configurarlo,
> ejecutar los tres escenarios de validación, calcular las métricas de detección, operar la red
> en modo dual-stack (IPv4/IPv6) y, finalmente, apagar todo. Está pensada para que cualquier
> persona —sin haber participado en el proyecto— pueda reproducir el laboratorio de cabo a rabo.

**Índice**

1. [Arquitectura del laboratorio](#1-arquitectura-del-laboratorio)
2. [Prerrequisitos](#2-prerrequisitos)
3. [Estructura del repositorio](#3-estructura-del-repositorio)
4. [Despliegue paso a paso](#4-despliegue-paso-a-paso)
5. [Verificación post-despliegue](#5-verificación-post-despliegue)
6. [Configuración dual-stack (IPv4/IPv6)](#6-configuración-dual-stack-ipv4ipv6)
7. [Reglas de correlación y afinamiento](#7-reglas-de-correlación-y-afinamiento-tuning)
8. [Ejecución de los escenarios](#8-ejecución-de-los-escenarios)
9. [Evaluación y cálculo de métricas](#9-evaluación-y-cálculo-de-métricas)
10. [Ejecución de los ataques sobre IPv6](#10-ejecución-de-los-ataques-sobre-ipv6)
11. [Solución de problemas (troubleshooting)](#11-solución-de-problemas-troubleshooting)
12. [Apagado del laboratorio (teardown)](#12-apagado-del-laboratorio-teardown)
13. [Apéndices](#13-apéndices)

---

## 1. Arquitectura del laboratorio

El laboratorio reconstruye en AWS una red empresarial segmentada en **tres VLAN**, modeladas
como tres subredes de una **VPC `10.0.0.0/16`** con un bloque **IPv6 `2600:1f18:…::/56`**
asignado por Amazon (dual-stack). El enrutamiento entre segmentos lo realiza el enrutador
implícito de la VPC; el filtrado perimetral lo proveen los *Security Groups* y un firewall
`nftables`.

### 1.1 Segmentación y direccionamiento

| VLAN | Subred | IPv4 | IPv6 (/64 del /56 de la VPC) |
|---|---|---|---|
| 10 — Servidores | `subnet-servidores` | `10.0.10.0/24` | `…:1300::/64` |
| 20 — Clientes | `subnet-clientes` | `10.0.20.0/24` | `…:1301::/64` |
| 30 — Gestión | `subnet-gestion` | `10.0.30.0/24` | `…:1302::/64` |

### 1.2 Instancias (perfil `completa` = 9, máximo del sandbox)

| Host | VLAN | IPv4 privada | Rol |
|---|---|---|---|
| `wazuh-server` (SIEM) | 30 | `10.0.30.10` | Wazuh manager + indexer + dashboard |
| `fw-gateway` | 30 | `10.0.30.30` | Firewall perimetral (nftables, sustituto de pfSense) |
| `atacante` | 30 | `10.0.30.20` | Estación ofensiva (Kali-equivalente) |
| `web-server` | 10 | `10.0.10.10` | Apache + Suricata (IDS) |
| `dc-empresa` | 10 | `10.0.10.20` | Active Directory / DNS del dominio `empresa.local` |
| `dns1-server` | 10 | `10.0.10.50` | BIND9 |
| `ntp-server` | 10 | `10.0.10.80` | Chrony |
| `win-ws-01` | 20 | `10.0.20.30` | Estación Windows (Sysmon) |
| `linux-01` | 20 | `10.0.20.40` | Estación Linux |

### 1.3 Las cinco fuentes de registro (requisito de la metodología)

1. **Active Directory / seguridad de Windows** (controlador de dominio).
2. **Firewall perimetral** (nftables → syslog).
3. **Servidor web** (logs de acceso de Apache).
4. **Telemetría de endpoint** (Sysmon en la estación Windows).
5. **IDS de red** (Suricata en el servidor web).

### 1.4 Técnicas de ataque evaluadas (MITRE ATT&CK)

| Técnica | MITRE | Herramienta |
|---|---|---|
| Fuerza bruta SSH | T1110.001 | Hydra |
| Escaneo de puertos | T1046 | Nmap |
| Pass-the-Hash | T1550.002 / T1021.002 | Impacket |
| Inyección SQL | T1190 | sqlmap / curl |
| Ejecución de payload | T1059.001 / T1204 | PowerShell `-enc` vía WinRM |

### 1.5 Equivalencia físico → nube

| Laboratorio físico | Equivalente en AWS |
|---|---|
| VirtualBox + Vagrant | EC2 + CloudFormation |
| Router Cisco (dot1Q) | Enrutador implícito de la VPC |
| Switches / troncales | Subredes de la VPC |
| pfSense | Security Groups + firewall nftables |
| Direccionamiento estático Netplan | IPv4 fija del template + IPv6 de la VPC |

---

## 2. Prerrequisitos

**Una sola vez:**

1. **Iniciar el laboratorio** en AWS Academy Learner Lab y pulsar **Start Lab** (semáforo verde).
2. **Credenciales:** abrir **AWS Details → AWS CLI → Show** y pegar el bloque en `~/.aws/credentials`
   (perfil `default`). **Caducan al detener el lab**; hay que volver a copiarlas si expiran.
   ```ini
   [default]
   aws_access_key_id=ASIA...
   aws_secret_access_key=...
   aws_session_token=...
   ```
3. **AWS CLI v2** y `bash` (Linux, macOS, WSL en Windows o AWS CloudShell).
4. **Par de claves:** usar el preexistente **`vockey`** (no crear otro). Descargar `labsuser.pem`
   desde **AWS Details → Download PEM** y darle permisos:
   ```bash
   chmod 400 ~/Downloads/labsuser.pem
   ```
   > **Consejo:** si la ruta del PEM tiene espacios o paréntesis, cópialo a una ruta sin
   > espacios (p. ej. `cp ~/Downloads/labsuser.pem ~/lab.pem`) para evitar errores de SSH.
5. **Tu IP pública** para restringir el acceso administrativo:
   ```bash
   curl -s https://api.ipify.org
   ```

**Restricciones del sandbox (ya contempladas en el proyecto):**

- **Máximo 9 instancias.** Perfiles `minima` (7) y `completa` (9).
- **Tipos** hasta `t3.medium` (el SIEM corre en `t3.medium` con swap y heap del indexer acotado).
- **Discos** gp2 ≤ 35 GB.
- **IAM de solo lectura:** el despliegue **no crea roles**; las instancias descargan sus scripts
  mediante una **URL prefirmada de S3** que `deploy.sh` genera.
- **Región:** `us-east-1`.

---

## 3. Estructura del repositorio

```
AWS/
├── deploy.sh                      # Orquestador: empaqueta scripts, sube a S3, lanza el stack
├── teardown.sh                    # Elimina el stack
├── cloudformation/siem-lab.yaml   # Plantilla: VPC, subredes (dual-stack), SGs, 9 instancias
├── userdata/                      # Scripts de aprovisionamiento por rol
│   ├── _common.sh                 # Funciones compartidas (hostname, hosts, habilitar_ipv6)
│   ├── wazuh-server.sh            # Instala Wazuh all-in-one + despliega reglas
│   ├── web-server.sh              # Apache + Suricata
│   ├── dns1-server.sh             # BIND9 (listen-on-v6 + AAAA)
│   ├── fw-gateway.sh              # Firewall nftables (family inet = dual-stack)
│   ├── windows-dc.ps1             # Active Directory
│   ├── windows-ws.ps1             # Estación Windows + Sysmon + Script Block Logging
│   └── ...
├── deteccion/
│   ├── local_rules.xml            # Reglas de correlación (afinadas)
│   └── agent.conf.windows-sysmon  # Config compartida: suscripción al canal de Sysmon
├── ataques/                       # Scripts de ataque (IPv6-aware)
│   ├── _lib_log_ataque.sh         # Librería común (log CSV + helpers IPv6)
│   ├── attack1..5_*.sh            # Los 5 ataques
│   ├── sigilosos/                 # Variantes de evasión
│   └── run_all_attacks.sh         # Escenario 2
├── escenarios/
│   ├── generar_trafico_realista.sh# Generador de tráfico de fondo (dual-stack)
│   ├── orquestar_trafico.sh       # Lanza tráfico en todas las instancias
│   └── escenario3_mixto.sh        # Escenario 3
└── evaluacion/
    ├── recolectar_alertas.py      # Filtra alerts.json por ventana temporal
    ├── calcular_metricas.py       # Detección/precisión/F1 + relevancia por técnica
    └── analizar_linea_base.py     # Falsos positivos (Escenario 1)
```

---

## 4. Despliegue paso a paso

Desde la carpeta `AWS/` (CloudShell, WSL, Linux o macOS):

```bash
chmod +x *.sh
./deploy.sh -c TU_IP_PUBLICA/32
```

**Parámetros de `deploy.sh`** (todos opcionales):

| Flag | Significado | Por defecto |
|---|---|---|
| `-k` | Par de claves EC2 | `vockey` |
| `-p` | Perfil: `minima` \| `completa` | `completa` |
| `-c` | CIDR de administración (SSH/RDP/dashboard) | `0.0.0.0/0` (mejor `TU_IP/32`) |
| `-r` | Región | `us-east-1` |
| `-s` | Nombre del stack | `siem-lab` |

**Qué hace internamente:** (1) crea un bucket S3; (2) empaqueta `userdata/`, `deteccion/`,
`ataques/`, `escenarios/`, `evaluacion/` en un `.tgz` y lo sube; (3) genera una URL prefirmada;
(4) despliega la plantilla CloudFormation; (5) muestra las salidas (URL del dashboard, IPs públicas).

**Tiempos de aprovisionamiento** (el software se instala *dentro* de las instancias):

| Componente | Tiempo aprox. | Señal de "listo" |
|---|---|---|
| Stack CloudFormation | 3–5 min | Estado `CREATE_COMPLETE` |
| Wazuh (SIEM) | 15–30 min | `https://<IP_SIEM>` responde (login `admin`) |
| Windows DC | 15–25 min (2–3 reinicios) | agente `dc-empresa` *Active* |
| Estación Windows | +10–15 min tras el DC | agente `win-ws-01` *Active* |
| Linux / servicios | 5–10 min | agentes *Active* |

Seguir el progreso:

```bash
# Linux
ssh -i ~/lab.pem ubuntu@<IP> 'sudo tail -f /var/log/siem-bootstrap.log'
# estado de la pila
aws cloudformation describe-stacks --stack-name siem-lab \
  --query "Stacks[0].StackStatus" --output text
# IPs de todas las instancias
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].[Tags[?Key=='Name']|[0].Value,PublicIpAddress,PrivateIpAddress,Ipv6Address]" \
  --output text | sort
```

---

## 5. Verificación post-despliegue

**5.1 Acceso al dashboard de Wazuh**

```bash
# contraseña del usuario admin
ssh -i ~/lab.pem ubuntu@<IP_SIEM> 'sudo cat /root/wazuh_passwords.txt'
```
Abrir `https://<IP_SIEM>` → usuario `admin` (acepta el certificado autofirmado).

**5.2 Agentes activos** (deben estar los 7 agentes + el nodo gestor):

```bash
ssh -i ~/lab.pem ubuntu@<IP_SIEM> 'sudo /var/ossec/bin/agent_control -l'
```
Esperado: `web-server`, `fw-gateway`, `ntp-server`, `dns1-server`, `linux-01`, `dc-empresa`,
`win-ws-01` → **Active**.

**5.3 Servicios clave**

```bash
# Suricata y Apache en el web
ssh -i ~/lab.pem ubuntu@<IP_WEB> 'sudo systemctl is-active suricata apache2; curl -s -o /dev/null -w "%{http_code}\n" http://localhost/'
# reglas afinadas desplegadas en el manager
ssh -i ~/lab.pem ubuntu@<IP_SIEM> 'sudo grep -oE "id=\"(100004|100023|100045|100046|100051)\"" /var/ossec/etc/rules/local_rules.xml'
```

**5.4 Acceso a los hosts**

- **Atacante:** `ssh -i ~/lab.pem ubuntu@<IP_ATACANTE>` → `sudo -u attacker bash -l`.
- **DC / estación Windows (RDP o WinRM):** usuario de dominio **`empresa\Administrator`**,
  contraseña `P@ssw0rd`.

---

## 6. Configuración dual-stack (IPv4/IPv6)

El direccionamiento IPv6 **ya viene incorporado en la plantilla** y en los scripts; esta sección
documenta cómo se logra, por si se requiere adaptarlo o verificarlo.

**6.1 Capa de red (CloudFormation — `cloudformation/siem-lab.yaml`):**
- `AWS::EC2::VPCCidrBlock` con `AmazonProvidedIpv6CidrBlock: true` → bloque **/56**.
- Cada subred: `Ipv6CidrBlock` (vía `Fn::Cidr`, un **/64** por subred) + `AssignIpv6AddressOnCreation: true`.
- `AWS::EC2::EgressOnlyInternetGateway` + ruta `::/0` → IPv6 saliente e intra-VPC **sin exponer**
  las instancias al Internet IPv6.
- Security Groups: regla de ingreso `CidrIpv6: ::/0` para el tráfico **intra-lab** (solo alcanzable
  dentro de la VPC por el egress-only gateway).
- Cada instancia: `Ipv6AddressCount: 1`.

**6.2 Capa de host (scripts):**
- `userdata/_common.sh` → `habilitar_ipv6()` configura **netplan** (`dhcp6: true`, `accept-ra: true`)
  para que cada host levante su IPv6.
- `userdata/dns1-server.sh` → BIND con `listen-on-v6 { any; }` y registros **AAAA**.
- El firewall usa `table inet` de nftables, que es **dual-stack nativo** (registra IPv4 e IPv6).

**6.3 Resolución de nombres dual-stack (post-despliegue):** las direcciones IPv6 globales las
asigna AWS en el despliegue (no son predecibles), por lo que tras el despliegue se recolectan y se
publican como `/etc/hosts` dual-stack y registros AAAA del DNS:

```bash
# recolectar las IPv6 asignadas
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].[Tags[?Key=='Name']|[0].Value,PrivateIpAddress,Ipv6Address]" \
  --output text
```

**6.4 Verificación de conectividad IPv6** (desde el atacante):

```bash
ping6 -c3 <IPv6_del_web>
curl -6 -g "http://[<IPv6_del_web>]/"           # debe responder 200
dig +short AAAA web-server.empresa.local @10.0.10.50
getent ahosts web-server                         # devuelve IPv4 e IPv6
```

---

## 7. Reglas de correlación y afinamiento (tuning)

Las reglas personalizadas están en `deteccion/local_rules.xml` y se despliegan automáticamente
al `/var/ossec/etc/rules/` del manager. El conjunto **final** (tras el ciclo de afinamiento) es:

| Regla | Evento detectado | Técnica |
|---|---|---|
| `100010` / `100011` | Fuerza bruta SSH (frecuencia de fallos) | T1110.001 |
| `100003` → `100004` / `100023` (y `100022`) | Escaneo de puertos (puertos «canario» y correlación de conexiones del firewall) | T1046 |
| `92650` (nativa) / `100031` | Pass-the-Hash (servicio creado desde ADMIN$) | T1550.002 |
| `100040` / `100041` | Inyección SQL (patrón web / firma Suricata) | T1190 |
| `100044` → `100045`, `100046` | Inyección SQL ofuscada (ráfaga de peticiones con parámetros / carga codificada) | T1190 |
| `100050` / `100051` | Payload PowerShell ofuscado (Sysmon Event 1) | T1059.001 |
| `100099` | Correlación de varias familias de ataque (Escenario 3) | — |

**Los cuatro ajustes aplicados** (ver el capítulo de Resultados del documento):

1. **FP de NTLM:** `100030`/`100032` se degradaron a informativas; el PtH se detecta por la
   regla nativa **`92650`** (comportamiento de host).
2. **Escaneo:** se añadió `100003` (reclasifica la regla netfilter `4100` a nivel 2) y la
   correlación **`100022`** sobre las conexiones del firewall; el reconocimiento enumera el perímetro.
3. **Ingesta de Sysmon:** el agente Windows se suscribe al canal `Microsoft-Windows-Sysmon/Operational`
   (en `windows-ws.ps1` y en la config compartida `agent.conf.windows-sysmon`).
4. **Payload:** con Sysmon ingerido, **`100051`** dispara sobre la línea de comando `-enc`.

**Segunda vuelta de afinamiento (variantes de evasión, corrida 7):**

5. **SQLi ofuscado:** las firmas por contenido se evaden con `--tamper`. Se añadieron `100045`
   (12 peticiones con parámetros en 120 s desde un mismo origen) y `100046` (carga codificada).
   Detección de la variante: 20–60 % → **100 %**.
6. **Firewall «canario»:** `fw-gateway.sh` registra solo los puertos sin servicio legítimo
   (21, 23, 111, 135, 139, 1433, 3306, 3389, 5900, 8080), casando **por puerto de destino**
   (sin condición de flags TCP). La `100004` depende de la `100003` (antes quedaba eclipsada) y
   la `100023` correlaciona dos sondas del mismo origen. El agente del firewall lee además
   `/var/log/kern.log`, para no depender del syslog por UDP.
7. **Límite conocido — escaneo sigiloso** (`nmap -sS -T1 -f`): las sondas fragmentadas y
   espaciadas no quedan registradas por el firewall en AWS; lo detecta Suricata (`86601`) en
   3/5 intentos sobre IPv4 y 2/5 sobre IPv6. No fuerces las reglas para subir la cifra.

Para re-desplegar las reglas tras un cambio:

```bash
scp -i ~/lab.pem deteccion/local_rules.xml ubuntu@<IP_SIEM>:/tmp/
ssh -i ~/lab.pem ubuntu@<IP_SIEM> \
  'sudo cp /tmp/local_rules.xml /var/ossec/etc/rules/ && sudo systemctl restart wazuh-manager'
```

---

## 8. Ejecución de los escenarios

Las IPs objetivo se definen en `~/lab.env` en el atacante (se genera en el aprovisionamiento).
Para orquestar el tráfico de fondo se exportan las **IPs públicas** de cada host.

### 8.1 Escenario 1 — Línea base (solo tráfico legítimo)

Desde la máquina de administración (la que tiene acceso SSH):

```bash
export LINUX01_PUB=<IP_PUB_linux-01> WEB_PUB=<IP_PUB_web> DNS_PUB=<IP_PUB_dns1> \
       ATACANTE_PUB=<IP_PUB_atacante> WINWS_IP_PRIV=10.0.20.30
date -u +%Y-%m-%dT%H:%M:%SZ > /tmp/e1_ini.txt
./escenarios/orquestar_trafico.sh 30 ~/lab.pem 4     # 30 min, intensidad 4
date -u +%Y-%m-%dT%H:%M:%SZ > /tmp/e1_fin.txt
```

### 8.2 Escenario 2 — Ataques controlados (5 técnicas × 5 repeticiones)

En el atacante:

```bash
sudo -u attacker bash -lc 'source ~/lab.env; export INCLUIR_SIGILOSOS=1 ESCENARIO=2; \
  cd ~/ataques && ./run_all_attacks.sh'
```

### 8.3 Escenario 3 — Mixto (tráfico de fondo + ataques aleatorios)

Tráfico de fondo desde administración + ataques en el atacante en paralelo:

```bash
# (admin) tráfico de fondo
export LINUX01_PUB=... WEB_PUB=... DNS_PUB=... ATACANTE_PUB=... WINWS_IP_PRIV=10.0.20.30
./escenarios/orquestar_trafico.sh 40 ~/lab.pem 4 &
# (atacante) ataques mixtos
ssh -i ~/lab.pem ubuntu@<IP_ATACANTE> \
  "sudo -u attacker bash -lc 'source ~/lab.env; export ESCENARIO=3 SKIP_BASELINE=1; \
   bash ~/escenarios/escenario3_mixto.sh 40'"
```

---

## 9. Evaluación y cálculo de métricas

Tras cada escenario se descargan las alertas del SIEM y se cruzan con el log de ataques (CSV).

```bash
# 1) descargar alerts.json del SIEM
ssh -i ~/lab.pem ubuntu@<IP_SIEM> 'sudo cp /var/ossec/logs/alerts/alerts.json /tmp/a.json && sudo chmod 644 /tmp/a.json'
scp -i ~/lab.pem ubuntu@<IP_SIEM>:/tmp/a.json resultados/alerts_full.json

# 2) descargar el log de ataques del atacante
ssh -i ~/lab.pem ubuntu@<IP_ATACANTE> 'sudo cp /home/attacker/log_ataques.csv /tmp/log.csv && sudo chmod 644 /tmp/log.csv'
scp -i ~/lab.pem ubuntu@<IP_ATACANTE>:/tmp/log.csv resultados/log_ataques.csv

# 3) filtrar por ventana temporal
python3 evaluacion/recolectar_alertas.py --alerts-file resultados/alerts_full.json \
  --inicio "$(cat /tmp/ini.txt)" --fin "$(cat /tmp/fin.txt)" --out resultados/alertas_ventana.json

# 4a) Escenario 1 — falsos positivos de la línea base
python3 evaluacion/analizar_linea_base.py --alertas resultados/alertas_ventana.json \
  --inicio "$(cat /tmp/ini.txt)" --fin "$(cat /tmp/fin.txt)" --out resultados/reporte_e1.md

# 4b) Escenarios 2 y 3 — detección por técnica
python3 evaluacion/calcular_metricas.py --ataques resultados/log_ataques.csv \
  --alertas resultados/alertas_ventana.json --escenario 2 --out resultados/reporte_e2.md
```

**Interpretación de las métricas** (`calcular_metricas.py`):
- **Detección estricta:** el ataque se considera detectado solo si disparó una **regla pertinente**
  a su técnica (criterio del proyecto, ≥ 80 %).
- **Detección amplia:** cualquier alerta en la ventana del ataque.
- **Precisión:** TP / (TP + FP) sobre alertas accionables.
- **Falsas alarmas accionables:** alertas de grupo de ataque sobre tráfico legítimo.

---

## 10. Ejecución de los ataques sobre IPv6

Las herramientas ofensivas requieren pequeñas adaptaciones para dirigir los ataques a
direcciones IPv6 (ya implementadas en los scripts, detectando `:` en el objetivo):

| Herramienta | Adaptación IPv6 |
|---|---|
| Nmap | `nmap -6 <IPv6>` |
| Hydra | `hydra -6 ssh://[<IPv6>]` |
| sqlmap / curl | URL con corchetes: `http://[<IPv6>]/...` |
| Impacket (secretsdump/psexec) | `-target-ip <IPv6>` + nombre del host (no `user@[IPv6]`) |
| evil-winrm | `-i <nombre>` que resuelva a IPv6 (no acepta literal IPv6) |

**Procedimiento:** se crea un `~/lab.env.ipv6` con los objetivos IPv6 (literales para
nmap/hydra/sqlmap; **nombres** para el DC y la estación Windows), se añaden alias de solo-IPv6 en
`/etc/hosts` del atacante (`dc6`, `winws6`) y se ejecuta igual que en IPv4:

```bash
sudo -u attacker bash -lc 'source ~/lab.env.ipv6; export INCLUIR_SIGILOSOS=1 ESCENARIO=2; \
  cd ~/ataques && ./run_all_attacks.sh'
```

> **Resultado esperado:** las cinco técnicas se detectan al 100 % también sobre IPv6, con el
> `srcip` en el espacio `2600:1f18:…`. La capacidad de detección es equivalente a IPv4.

---

## 11. Solución de problemas (troubleshooting)

Problemas reales encontrados durante las corridas y su solución:

| Síntoma | Causa | Solución |
|---|---|---|
| El SSH a las instancias da *timeout* (pero el dashboard por 443 sí carga) | El **Security Group** solo permite tu IP anterior y **tu IP pública cambió** | Actualiza el CIDR de administración: `aws cloudformation update-stack --stack-name siem-lab --use-previous-template --parameters ParameterKey=AdminIngressCidr,ParameterValue=<IP_NUEVA>/32 ParameterKey=...,UsePreviousValue=true` (repite `UsePreviousValue=true` para los demás parámetros) |
| `github.com:22` también da *timeout* desde tu red | Tu **ISP/red doméstica bloquea el puerto 22 saliente** | Usa el **hotspot del celular** (otra ruta de red) o una red que no filtre el 22 |
| No llegan eventos de **Sysmon** (payload no se detecta) | El agente Windows **no está suscrito** al canal `Microsoft-Windows-Sysmon/Operational` | Despliega la config compartida: copia `deteccion/agent.conf.windows-sysmon` a `/var/ossec/etc/shared/default/agent.conf` en el manager y reinicia los agentes (`agent_control -R -a`) |
| El DC/estación Windows no termina de aprovisionarse | Bucle DNS tras la promoción de AD / reinicios | El script reanuda con reintentos; espera 15–25 min y revisa `C:\siem-bootstrap.log` |
| `evil-winrm` falla con `WinRMAuthorizationError` | Se usó la cuenta **local** `Administrator` en vez de la de **dominio** | Usa `-u 'empresa\Administrator'` (cuenta de dominio) |
| `impacket-secretsdump` sobre IPv6 falla (`Name or service not known`) | Impacket no resuelve `user@[IPv6]` | Usa `-target-ip <IPv6>` con el **nombre** del host |
| El manager no arranca tras editar `ossec.conf` | XML mal cerrado | Añade un bloque `<ossec_config>` nuevo **al final** (no reabras el archivo borrando el cierre) |
| El SIEM se queda sin memoria durante la instalación | 4 GB de RAM del sandbox | El script crea swap y limita el heap del indexer a 1 GB; si aun así falla, reinicia la instancia |
| Una corrida larga se corta a mitad (SSH `exit 255`) | La sesión SSH se cayó o el laboratorio expiró (≈ 4 h) | Lanza los escenarios **desacoplados** en el atacante (`setsid … &`) y consulta el avance por el número de filas de `log_ataques.csv` |
| El escaneo sigiloso no genera eventos `FW-SCAN` | Sondas fragmentadas (`-f`) que el firewall no llega a registrar | Comportamiento esperado y documentado; la detección depende de Suricata (`86601`) |
| `delete-stack` falla con `ExpiredToken` | Las credenciales del sandbox **caducaron** | Copia credenciales nuevas desde *AWS Details* o usa **End Lab** en el portal |

---

## 12. Apagado del laboratorio (teardown)

**Opción A — CLI** (con credenciales vigentes):

```bash
aws cloudformation delete-stack --stack-name siem-lab
aws cloudformation wait stack-delete-complete --stack-name siem-lab
# limpiar el bucket de scripts
aws s3 rm "s3://siem-lab-<ACCOUNT_ID>-us-east-1" --recursive
aws s3api delete-bucket --bucket "siem-lab-<ACCOUNT_ID>-us-east-1"
```

O simplemente `./teardown.sh -y`.

**Opción B — Portal:** en **AWS Academy → Learner Lab**, pulsar **End Lab**. Esto detiene y
limpia todos los recursos sin necesidad de CLI (útil si las credenciales expiraron).

> Verifica que no quedan instancias:
> `aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" --query "Reservations[].Instances[].InstanceId" --output text`

---

## 13. Apéndices

### 13.1 Puertos relevantes

| Puerto | Servicio |
|---|---|
| 443 | Dashboard de Wazuh |
| 1514–1516 | Agentes Wazuh |
| 514/udp | Syslog del firewall → SIEM |
| 55000 | API de Wazuh |
| 22 / 3389 / 5985 | SSH / RDP / WinRM (administración) |

### 13.2 Credenciales de prueba (laboratorio aislado)

| Cuenta | Credencial | Uso |
|---|---|---|
| `admin` (dashboard) | ver `/root/wazuh_passwords.txt` | Panel de Wazuh |
| `empresa\Administrator` | `P@ssw0rd` | Dominio / WinRM / RDP |
| `usuario` (linux-01) | `admin123` | Objetivo de fuerza bruta SSH |
| `attacker` (atacante) | sudo sin contraseña | Ejecución de ataques |

> Son credenciales de un laboratorio aislado y efímero, no deben reutilizarse en producción.

### 13.3 Criterio de éxito

Tasa de **detección estricta ≥ 80 %**. Resultado obtenido: **100 % para las cinco técnicas
de la metodología**, con **0 falsas alarmas accionables** y precisión del **97–100 %**, tanto
sobre IPv4 como sobre IPv6. Incluyendo las tres variantes de evasión (40 ataques), la última
corrida (v7) alcanzó **95,0 % sobre IPv4** y **92,5 % sobre IPv6**. El detalle de todas las
corridas está en `RESULTADOS_CONSOLIDADOS.md` y `resultados_v7/RESULTADOS_v7.md`.

---

*Guía técnica de despliegue — Proyecto de grado. Reproducible de principio a fin con un único
comando (`deploy.sh`) y apagable con `teardown.sh` o «End Lab».*
