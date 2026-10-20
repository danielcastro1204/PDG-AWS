# Migración a AWS del laboratorio SIEM (Wazuh) — Proyecto de grado

Infraestructura como código que **reconstruye en AWS** la red empresarial simulada del
proyecto *"Diseño, implementación y documentación de una plataforma SIEM open source para
el monitoreo de eventos de seguridad en una red empresarial"*, antes virtualizada con
VirtualBox + Vagrant en el laboratorio físico.

Todo el despliegue está **100 % automatizado**: un solo comando (`deploy.sh`) crea la red,
las máquinas y aprovisiona cada servicio (Wazuh, Active Directory, web, Suricata, firewall,
atacante, DNS/DHCP/SMTP/NTP) reutilizando los scripts del laboratorio original.

> Pensado para el **sandbox de AWS Academy Cloud Architecting**: no crea recursos IAM, usa el
> `LabRole`/`LabInstanceProfile` preexistentes y resuelve las AMIs vía SSM.

## Inicio rápido

> Sandbox AWS Academy: key pair `vockey` (descarga `labsuser.pem` desde *AWS Details*),
> región `us-east-1`, **máx. 9 instancias**, tipos ≤ `t3.medium`, discos gp2 ≤ 35 GB.
> Ejecuta desde CloudShell / WSL / Linux / macOS.

**Opción A — Todo de una (despliega, prueba y entrega el reporte):**
```bash
cd AWS
chmod +x *.sh
./run_all_aws.sh -i ~/Downloads/labsuser.pem -c TU_IP/32
# → deja ./resultados/reporte_metricas.md con la tasa de detección
```

**Opción B — Por pasos (más control):**
```bash
cd AWS
chmod +x *.sh
./deploy.sh -c TU_IP/32                                 # 1) desplegar (perfil completa=9)
# ...esperar a que los agentes estén Active en el dashboard...
# 2) ejecutar escenarios/evaluación con run_lab_aws.sh (en el atacante)
./teardown.sh -y                                        # 3) eliminar todo
```

Guía completa paso a paso: **[GUIA_DESPLIEGUE_AWS.md](GUIA_DESPLIEGUE_AWS.md)**.
Decisiones de arquitectura y equivalencias físico→AWS: **[MAPEO_RED_FISICA_A_AWS.md](MAPEO_RED_FISICA_A_AWS.md)**.

## Qué se despliega

Una VPC `10.0.0.0/16` con 3 subredes que representan las VLAN del proyecto:

```
                 Internet Gateway
                        │
      ┌─────────────────┼──────────────────┐
  subnet-servidores  subnet-clientes   subnet-gestion
   10.0.10.0/24       10.0.20.0/24      10.0.30.0/24   (VLAN 10 / 20 / 30)
   ├ web-server .10   ├ win-ws-01 .30   ├ wazuh(SIEM) .10
   ├ windows-dc .20   ├ win-ws-02 .31   ├ atacante    .20
   ├ dns1 .50/dns2 .60├ linux-01  .40   └ fw-gateway  .30 (sustituto pfSense)
   ├ dhcp4 .30/dhcp6 .40 linux-02 .41
   ├ smtp .70 / ntp .80
```

**Las 5 fuentes de logs** de la metodología se conservan: AD (DC), firewall (fw-gateway),
web (Apache), Sysmon (estaciones Windows) e IDS (Suricata). Ver el mapeo para el detalle.

## Estructura del repositorio

```
AWS/
├── README.md                     # este archivo
├── GUIA_DESPLIEGUE_AWS.md        # paso a paso para AWS Academy
├── MAPEO_RED_FISICA_A_AWS.md     # equivalencias físico → AWS y justificación
├── run_all_aws.sh                # ORQUESTADOR end-to-end (despliega+prueba+reporte)
├── deploy.sh                     # despliegue de un comando (CloudFormation + S3)
├── teardown.sh                   # eliminación del laboratorio
├── run_lab_aws.sh                # menú de operación manual (escenarios + evaluación)
├── cloudformation/
│   └── siem-lab.yaml             # plantilla única: VPC, subredes, SG, 7-15 EC2
├── userdata/                     # aprovisionamiento por rol (migrado de los scripts Vagrant)
│   ├── _common.sh                #   helper: agente Wazuh, hostname, hosts, etc.
│   ├── wazuh-server.sh           #   SIEM all-in-one + syslog + reglas del proyecto
│   ├── fw-gateway.sh             #   firewall nftables + syslog→Wazuh (sustituto pfSense)
│   ├── attacker.sh               #   toolkit de pentesting (sustituto Kali)
│   ├── web-server.sh             #   Apache + Suricata + agente
│   ├── linux-ws.sh               #   estación Linux (auditd + agente + SSH objetivo)
│   ├── dns1/dns2/dhcpv4/dhcpv6/ntp/smtp-server.sh
│   ├── windows-dc.ps1            #   DC AD DS/DNS (máquina de estados con reinicios)
│   └── windows-ws.ps1            #   estación Windows (join dominio + Sysmon + agente)
├── deteccion/local_rules.xml     # reglas de correlación MITRE (reutilizadas sin cambios)
├── config/sysmonconfig.xml       # configuración Sysmon (reutilizada sin cambios)
├── ataques/                      # los 5 ataques + orquestador (reutilizados; honran env)
├── escenarios/                   # escenario 1 (línea base) y 3 (mixto)
└── evaluacion/                   # recolección de alertas y cálculo de métricas (Python)
```

## Relación con las fases del proyecto

| Fase de la metodología | En esta migración |
|---|---|
| Fase 1 — Arquitectura de red | `cloudformation/siem-lab.yaml` (VPC/subredes/SG/EC2) |
| Fase 2 — Implementación SIEM | `userdata/wazuh-server.sh` + agentes + `deteccion/` + Suricata |
| Fase 3 — Escenarios de prueba | `ataques/`, `escenarios/`, `run_lab_aws.sh` |
| Fase 4 — Evaluación de resultados | `evaluacion/` (tasa de detección ≥ 80 %) |

## Notas importantes
- Las credenciales de laboratorio son **débiles a propósito** (entorno aislado de pruebas y
  objetivos de los ataques controlados): `Administrator/P@ssw0rd`, `usuario/admin123`, etc.
- No ejecutes los ataques contra nada fuera de esta VPC.
- Recuerda **`teardown.sh`** o detener las instancias para no agotar el presupuesto del sandbox.
- Sustituciones (pfSense→nftables, Kali→Ubuntu+toolkit, Win10→Win Server 2019) y su
  justificación técnica: ver `MAPEO_RED_FISICA_A_AWS.md`.
