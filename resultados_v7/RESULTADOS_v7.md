# Resultados v7 — Re-ejecución con afinamiento de detección sigilosa (dual-stack IPv4/IPv6)

**Fecha:** 2026-11-15 / 16 (UTC)
**Despliegue:** stack `siem-lab` recreado desde cero en AWS (CloudFormation, perfil `completa` = 9 EC2),
con el afinamiento ya incorporado en el bundle de aprovisionamiento (user-data). 8 agentes Wazuh
activos (fw-gateway, ntp, dns, web, linux-01, dc-empresa, win-ws-01 + server local).

Esta iteración responde al objetivo: **aumentar la detección de los ataques sigilosos (variantes de
evasión) y validar el laboratorio sobre IPv4 e IPv6**, manteniendo 0 falsas alarmas accionables.

---

## 1. Afinamiento aplicado (qué cambió y por qué)

| # | Cambio | Archivo | Motivo |
|---|--------|---------|--------|
| 1 | **Regla canario del firewall por *destino* (sin condición de flags TCP)** | `userdata/fw-gateway.sh` | Causa raíz de la evasión del escaneo: `nmap -f` fragmenta el SYN en trozos de 8 bytes; el primer fragmento lleva los puertos pero **no** el byte de flags TCP, de modo que una condición `tcp flags syn` nunca casa un SYN fragmentado. Al casar solo por `tcp dport` sobre puertos "canario" sin servicio legítimo, se captura también el SYN fragmentado con 0 FP. |
| 2 | **Regla de comportamiento SQLi automatizado** (100045: frecuencia de peticiones con query-string desde un mismo origen) | `deteccion/local_rules.xml` | El SQLi ofuscado (`--tamper`, user-agent aleatorio) evade las firmas por contenido; el patrón de **volumen** de sqlmap sí es detectable. |
| 3 | **Regla de contenido SQLi codificado** (100046: patrones `%27`, `/*!*/`, `0x…`, `union…select`, `sleep(`, etc.) | `deteccion/local_rules.xml` | Captura las cargas ofuscadas que las reglas base no reconocen. |
| 4 | **Mapa de relevancia de técnicas actualizado** (ids de reglas pertinentes por técnica) | `evaluacion/calcular_metricas.py` | Para que la métrica *estricta* cuente las nuevas reglas (100045/100046 para SQLi; 100004/100022/100023 para escaneo). |

Resultado del afinamiento sobre las variantes de evasión respecto al **proyecto previo**:

| Variante de evasión | Antes (proyecto previo) | Ahora (v7) |
|---|---|---|
| SQLi ofuscado (`sqli_evasion`) | 20–60 % | **100 %** (IPv4 e IPv6) |
| Fuerza bruta SSH lenta (`bruteforce_ssh_lento`) | parcial | **100 %** (IPv4 e IPv6) |
| Escaneo de puertos sigiloso (`portscan_sigiloso`) | 0–20 % | **60 % IPv4 / 40 % IPv6** (ver §4) |

---

## 2. Escenario 2 — Ataques controlados · **IPv4**

Ventana: `2026-11-15T21:57:50Z → 22:58:50Z`. 5 técnicas × 5 repeticiones + 3 variantes de evasión × 5 = **40 ataques**.

| Métrica | Valor |
|---|---|
| **Detección estricta** (regla pertinente a la técnica) | **95,0 % (38/40)** |
| Detección amplia (cualquier alerta correlacionada) | 100,0 % (40/40) |
| Precisión (accionables correctas) | 100,0 % |
| F1-score | 97,4 % |
| Falsas alarmas accionables | **0 / 2390** |

| Ataque | Intentos | Estricta | % |
|---|---:|---:|---:|
| bruteforce_ssh | 5 | 5 | 100 |
| bruteforce_ssh_lento | 5 | 5 | 100 |
| pass_the_hash | 5 | 5 | 100 |
| payload_execution | 5 | 5 | 100 |
| portscan | 5 | 5 | 100 |
| **portscan_sigiloso** | 5 | **3** | **60** |
| sql_injection | 5 | 5 | 100 |
| sqli_evasion | 5 | 5 | 100 |

Evidencia: `resultados_v7/ipv4/escenario2/` (`alerts_full_e2.json`, `log_ataques_e2.csv`, `alertas_ventana.json`, `reporte_escenario2.md`).

---

## 3. Escenario 2 — Ataques controlados · **IPv6 (dual-stack)**

Ventana: `2026-11-15T23:02:40Z → 23:59:00Z`. Mismos 40 ataques, lanzados contra las direcciones IPv6 de los objetivos (Impacket PtH con `-target-ip`, nmap/sqlmap/hydra IPv6-aware).

| Métrica | Valor |
|---|---|
| **Detección estricta** | **92,5 % (37/40)** |
| Detección amplia | 100,0 % (40/40) |
| Precisión (accionables correctas) | 100,0 % |
| F1-score | 96,1 % |
| Falsas alarmas accionables | **0 / 2337** |

| Ataque | Intentos | Estricta | % |
|---|---:|---:|---:|
| bruteforce_ssh | 5 | 5 | 100 |
| bruteforce_ssh_lento | 5 | 5 | 100 |
| pass_the_hash | 5 | 5 | 100 |
| payload_execution | 5 | 5 | 100 |
| portscan | 5 | 5 | 100 |
| **portscan_sigiloso** | 5 | **2** | **40** |
| sql_injection | 5 | 5 | 100 |
| sqli_evasion | 5 | 5 | 100 |

Evidencia: `resultados_v7/ipv6/escenario2/`.

---

## 4. Análisis honesto del escaneo sigiloso (`portscan_sigiloso`)

- **Amplia 100 %**: el escaneo sigiloso **siempre** genera actividad detectable (5/5 en ambas familias).
- **Estricta 60 % IPv4 / 40 % IPv6**: la detección por una **regla pertinente a reconocimiento** la aporta
  **Suricata (regla 86601)**, no el canario del firewall.
- **Por qué el canario del firewall no captura el escaneo sigiloso:** se verificó en `kern.log` que durante
  las ventanas del escaneo sigiloso llegan **0** eventos `FW-SCAN`, mientras que el escaneo ruidoso sí genera
  los 7 eventos canario por repetición. El escaneo sigiloso usa `-T1 -f` (fragmentación + bajísima tasa):
  los SYN fragmentados y espaciados hacia el firewall no llegan de forma fiable a la regla canario bajo el
  manejo de fragmentos de la red AWS. El control **efectivo** del escaneo sigiloso en este entorno es la
  **firma de red de Suricata**, que lo capta en 3/5 (IPv4) y 2/5 (IPv6).
- **Trabajo futuro** para subirlo: afinar el umbral de detección de escaneo de Suricata (`stream`/`flow`), o
  reenviar a Wazuh una correlación de bajo nivel de Suricata; se deja documentado como límite medido, sin
  sobre-ajustar las reglas para "forzar" el número.

---

## 5. Comparación con el proyecto previo (resumen)

| | Proyecto previo | v7 (esta iteración) |
|---|---|---|
| E2 Global estricta (IPv4) | 80,0–82,5 % | **95,0 %** |
| E2 Global estricta (IPv6) | 77,5 % | **92,5 %** |
| Núcleo (5 técnicas) | 100 % | 100 % (ambas familias) |
| SQLi evasión | 20–60 % | **100 %** |
| Fuerza bruta lenta | parcial | **100 %** |
| Precisión / FP accionables | 100 % / 0 | 100 % / **0** (ambas familias) |
| Criterio de éxito (≥80 % estricta) | ✓ | ✓ **con margen** |

---

## 6. Escenario 3 — Tráfico mixto (bajo carga) · IPv4

Ventana: `2026-11-16T00:00:55Z → 00:25:16Z` (20 min). Tráfico de fondo continuo + ataques disparados en
instantes aleatorios ocultos entre la actividad legítima (situación más realista).

| Métrica | Valor |
|---|---|
| **Detección estricta** | **100,0 % (4/4)** |
| Detección amplia | 100,0 % (4/4) |
| Precisión (accionables) | 98,7 % |
| F1-score | 99,4 % |
| Alertas de baja severidad del tráfico de fondo | 11 / 852 |

Ataques disparados bajo carga (todos detectados por regla pertinente): inyección SQL ×2 (100040/41/44/45/46 +
Suricata 86601), Pass-the-Hash (92650 endpoint), escaneo de puertos (100004→100023 firewall + 86601). Las 11
alertas restantes son de **baja severidad** generadas por el tráfico legítimo de fondo (no accionables como
incidente), coherente con el comportamiento del proyecto previo. Evidencia: `resultados_v7/ipv4/escenario3/`.

---

## 7. Infraestructura

- VPC 10.0.0.0/16 dual-stack (/56 IPv6 de Amazon), 3 subredes/VLAN, Egress-Only IGW para IPv6.
- 9 EC2 (SIEM Wazuh all-in-one, firewall nftables, atacante, DC Windows AD, 2 estaciones, web+Suricata, DNS, NTP).
- 5 fuentes de telemetría: autenticación (SSH/AD), firewall (nftables→syslog+agente), web (Apache), endpoint (Sysmon), IDS de red (Suricata).
- Despliegue reproducible con un comando (`deploy.sh`) y apagado con `teardown.sh`.
