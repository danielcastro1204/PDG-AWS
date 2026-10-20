# Mapeo: laboratorio físico (VirtualBox/Vagrant) → AWS

Este documento explica **cómo se traslada la red empresarial simulada del proyecto
de grado a AWS** y justifica las decisiones de equivalencia. El objetivo de diseño
fue conservar la topología, el esquema de direccionamiento y **las 5 fuentes de
logs** que exige la metodología, reemplazando únicamente lo que el hardware físico
(switches/router Cisco, hipervisor, ISOs de Windows) aportaba.

## 1. Redes: VLAN → Subred de VPC

El laboratorio físico usaba 3 VLAN sobre `192.168.X.0/24`. En AWS se crean 3 subredes
dentro de una VPC `10.0.0.0/16`, **conservando el último octeto** de cada equipo para
que el direccionamiento siga siendo legible e idéntico en espíritu.

| Elemento físico | VLAN | Red física | Subred AWS | Rango |
|---|---|---|---|---|
| Segmento Servidores | 10 | 192.168.10.0/24 | `subnet-servidores` | `10.0.10.0/24` |
| Segmento Clientes   | 20 | 192.168.20.0/24 | `subnet-clientes`   | `10.0.20.0/24` |
| Segmento Gestión    | 30 | 192.168.30.0/24 | `subnet-gestion`    | `10.0.30.0/24` |

El **router Cisco ISR4321** (enrutamiento entre VLAN + salida a Internet) se sustituye
por los componentes nativos de la VPC: **Internet Gateway** + **tabla de rutas** +
**resolvedor DNS de la VPC**. El filtrado entre segmentos que hacía el router/pfSense
se implementa con **Security Groups** (uno por segmento).

## 2. Máquinas: VM → Instancia EC2

| Rol (físico) | SO original | IP física | Instancia AWS | IP AWS | AMI / tipo |
|---|---|---|---|---|---|
| SIEM Wazuh | Ubuntu 22.04 | 192.168.30.10 | `Wazuh` | **10.0.30.10** | Ubuntu 22.04 / t3.medium (4 GB) |
| Firewall (pfSense) | FreeBSD | 192.168.30.30 | `FwGateway` | **10.0.30.30** | Ubuntu + nftables / t3.small |
| Atacante (Kali) | Kali | 192.168.30.20 | `Attacker` | **10.0.30.20** | Ubuntu + toolkit / t3.small |
| Servidor Web | Ubuntu 22.04 | 192.168.10.10 | `WebServer` | **10.0.10.10** | Ubuntu 22.04 / t3.small |
| Controlador de Dominio | Win Server 2019 | 192.168.10.20 | `WindowsDC` | **10.0.10.20** | Win Server 2019 / t3.medium |
| Estación Windows | Windows 10 | 192.168.20.30/31 | `WinWs01/02` | **10.0.20.30/31** | Win Server 2019 / t3.medium |
| Estación Linux | Ubuntu 22.04 | 192.168.20.40/41 | `LinuxWs01/02` | **10.0.20.40/41** | Ubuntu 22.04 / t3.small |
| DNS1 / DNS2 (BIND9) | Ubuntu | .10.50 / .10.60 | `Dns1/Dns2` | 10.0.10.50/60 | Ubuntu / t3.small |
| DHCPv4 / DHCPv6 (Kea) | Ubuntu | .10.30 / .10.40 | `Dhcpv4/Dhcpv6` | 10.0.10.30/40 | Ubuntu / t3.small |
| SMTP (Postfix) | Ubuntu | .10.70 | `Smtp` | 10.0.10.70 | Ubuntu / t3.small |
| NTP (chrony) | Ubuntu | .10.80 | `Ntp` | 10.0.10.80 | Ubuntu / t3.small |

> **Límite del sandbox (máx. 9 instancias).** No se pueden levantar las 15 a la vez. Por eso
> el despliegue usa dos perfiles: `minima` (7: SIEM, DC, web, firewall, atacante, 1 Windows,
> 1 Linux) y `completa` (9: `minima` + DNS1 + NTP). Los scripts de DNS2, DHCPv4, DHCPv6, SMTP
> y 2ª estación quedan en `userdata/` y se intercambian editando el template sin pasar de 9.
> Tipos de instancia ≤ `t3.medium` (2 vCPU / 4 GB) y discos gp2 ≤ 35 GB por política del sandbox.

### Sustituciones y por qué
- **pfSense → instancia Linux con nftables + rsyslog.** pfSense (FreeBSD) no tiene una
  AMI gratuita ni desplegable de forma desatendida en el sandbox. El sustituto registra
  las conexiones con nftables y **reenvía los logs por syslog a Wazuh (`10.0.30.10:514`)**,
  exactamente la integración que el proyecto documentaba para pfSense. → **Fuente de log #2**.
- **Kali → Ubuntu + toolkit de pentesting.** AWS Academy no permite suscribir la AMI de
  Kali de Marketplace de forma fiable. Se instala el mismo conjunto de herramientas
  (`nmap, hydra, sqlmap, impacket, netexec/crackmapexec, metasploit, evil-winrm`) y se
  conservan **verbatim** los 5 scripts de ataque.
- **Windows 10 → Windows Server 2019 (miembro de dominio).** AWS no ofrece AMIs de Windows
  10 cliente. Para las fuentes de detección del proyecto (telemetría **Sysmon**, eventos de
  logon tipo 3/NTLM para Pass-the-Hash, ejecución de payload) un miembro de dominio con
  Sysmon es equivalente. → **Fuente de log #4**.

## 3. Las 5 fuentes de logs (requisito de la metodología)

| # | Fuente | Dónde se genera en AWS | Cómo llega a Wazuh |
|---|---|---|---|
| 1 | Autenticación Active Directory | `WindowsDC` (10.0.10.20) | Agente Wazuh (eventos de seguridad de Windows) |
| 2 | Firewall perimetral | `FwGateway` (10.0.10.30) nftables | rsyslog → Wazuh UDP/514 (+ VPC Flow Logs opcional) |
| 3 | Servidor web | `WebServer` (10.0.10.10) Apache | Agente Wazuh (`access.log`/`error.log`) |
| 4 | Telemetría de endpoints Windows | `WinWs01/02` Sysmon | Agente Wazuh |
| 5 | IDS Suricata | `WebServer` (eve.json) | Agente Wazuh (`localfile` JSON) |

Las reglas de correlación personalizadas del proyecto (`deteccion/local_rules.xml`,
mapeadas a MITRE ATT&CK: T1110.001, T1046, T1550.002/T1021.002, T1190, T1059.001/T1204.002)
se despliegan **sin cambios** en el Wazuh Manager.

## 4. Lo que cambia respecto a Vagrant
- La **IP fija** ya no se configura con `netplan`/detección de interfaz puente: la asigna
  la ENI de la instancia (`PrivateIpAddress` en CloudFormation). Los scripts de
  aprovisionamiento conservan **toda** la lógica de servicios y agentes, pero sin el bloque
  de red.
- Los **reinicios** que Vagrant orquestaba con `vagrant-reload` (hostname, promoción de AD,
  unión al dominio) se resuelven con una **máquina de estados** en la user-data de Windows
  (`<persist>true</persist>` de EC2Launch re-ejecuta el script en cada arranque).
- `vagrant up` se reemplaza por **`./deploy.sh`** (CloudFormation + S3).

## 5. Direccionamiento IPv6
La topología física definía dual-stack (`fd00:10::/64`, etc.). En AWS el dual-stack
requiere asociar un bloque IPv6 a la VPC/subredes; se deja **documentado y opcional** para
no exceder el presupuesto del sandbox. Los servicios (DNS/DHCPv6) conservan su configuración
IPv6 de laboratorio. Si se requiere IPv6 nativo en AWS, se añade `Ipv6CidrBlock` a la VPC y
`AssignIpv6AddressOnCreation` a las subredes.
