# Pruebas exhaustivas de servicios — verificación pre-escenarios

**Fecha:** 22 de octubre de 2026
**Objetivo:** garantizar que todos los servicios de la red simulada funcionan correctamente antes de ejecutar los 3 escenarios de validación.

## Resultado global: ✅ TODOS LOS SERVICIOS OPERATIVOS (7/7 agentes activos)

| # | Instancia / Servicio | Prueba | Resultado | Detalle |
|---|---|---|---|---|
| a | **web-server** — Apache | `systemctl is-active` + `curl` | ✅ OK | HTTP 200 en `/` y `/index.php?id=1` |
| a | **web-server** — Suricata (IDS) | servicio + `eve.json` | ✅ OK | activo; `eve.json` creciendo (4.6 MB, registrando tráfico) |
| a | **web-server** — Samba | `testparm` + acceso cliente | ✅ OK | share `[compartido]` accesible desde linux-01 |
| b | **dns1** — BIND9 | `dig @localhost google.com` | ✅ OK | resuelve externos (172.253.62.138) |
| c | **ntp** — chrony | `chronyc tracking` | ✅ OK | sincronizado, stratum 2 (time.ecansol.net) |
| d | **firewall** — nftables | `nft list ruleset` | ✅ OK | activo, 16 reglas cargadas |
| d | **firewall** — rsyslog→Wazuh | `systemctl is-active` | ✅ OK | activo (reenvío de logs al SIEM) |
| e | **atacante** — toolkit | `which` de cada herramienta | ✅ OK | evil-winrm, impacket (psexec/secretsdump), hydra, nmap, sqlmap, sshpass, dig, swaks presentes |
| f | **linux-01** — SSH | `sshd -T passwordauth` | ✅ OK | `PasswordAuthentication yes`; login `usuario/admin123` funciona |
| f | **linux-01** — auditd | `systemctl is-active` | ✅ OK | activo (telemetría de auditoría) |
| g | **Agentes Wazuh** | `agent_control -l` | ✅ OK | **7/7 Active**: web, linux-01, ntp, fw-gateway, dns1, dc-empresa, win-ws-01 |
| h | **DC / Active Directory** | `dig empresa.local` + LDAP | ✅ OK | dominio resuelve a 10.0.10.20; consultas LDAP/Kerberos OK |
| h | **DC — captura de hash (PtH)** | `impacket-secretsdump` | ✅ OK | hash NTLM del Administrator capturado correctamente |
| i | **estación Windows — WinRM** | `evil-winrm` | ✅ OK | conexión exitosa, `empresa\administrator` |
| i | **estación Windows — Sysmon** | servicio + event log | ✅ OK | Sysmon64 Running, 2018 eventos registrados |

## Verificación de la cadena de ataque completa (end-to-end)

Las 5 técnicas tienen su objetivo verificado y funcional:

| Técnica | Verificación | Estado |
|---|---|---|
| Fuerza bruta SSH (T1110.001) | login `usuario/admin123` a linux-01 responde | ✅ listo |
| Escaneo de puertos (T1046) | DC y servicios con puertos abiertos | ✅ listo |
| Inyección SQL (T1190) | endpoint `/index.php?id=` reflejado + HTTP 200 | ✅ listo |
| Pass-the-Hash (T1550.002) | `secretsdump` captura el hash NTLM del DC | ✅ listo |
| Ejecución de payload (T1059.001) | WinRM conecta + Sysmon registrando en la estación | ✅ listo |

## Verificación del instrumental de tráfico realista

| Componente | Estado |
|---|---|
| `generar_trafico_realista.sh` en instancias Linux | ✅ desplegado (`/opt/lab/escenarios/`) |
| `generar_trafico_windows.ps1` en estación Windows | ✅ desplegado (`C:\lab\escenarios\`) |
| `swaks` (correo SMTP del tráfico) | ✅ instalado en linux-01, web y atacante |

## Conclusión

La red simulada está **completamente operativa y verificada**: las 5 fuentes de logs (AD, firewall, web/Apache, Sysmon, Suricata IDS) activas, los 7 agentes reportando, la cadena de ataque funcional end-to-end, y el instrumental de tráfico realista desplegado. El laboratorio está listo para ejecutar los 3 escenarios con rigor metodológico.
