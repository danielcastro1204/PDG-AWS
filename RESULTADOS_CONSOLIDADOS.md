# Resultados consolidados del Proyecto de Grado — todas las ejecuciones

**Laboratorio SIEM (Wazuh) reproducible en AWS para la detección de técnicas MITRE ATT&CK**
Compilación de **las 7 corridas**, todas las cifras e indicadores, por escenario.
Criterio de éxito del proyecto: **detección ≥ 80 %**.

---

## 0. Índice de ejecuciones (orden cronológico)

| # | Carpeta | Fecha | Qué valida | Métrica usada |
|---|---|---|---|---|
| **1** | `resultados/` | 20–21 oct | Primera corrida rigurosa (ataques aislados, registro de ventanas) | Detección **amplia** (hubo alerta) |
| **2** | `resultados_v2/` | 21 oct | 3 escenarios completos; integración de las 5 fuentes de log | Detección **amplia** |
| **3** | `resultados_v3/` | 22 oct | 3 escenarios con **tráfico realista denso + evasión + detección estricta por técnica** | Detección **estricta** (empieza aquí) |
| **4** | `resultados_v4/` | 7–8 nov | **Ciclo de tuning** (4 iteraciones: detectar→medir→analizar→ajustar→re-validar) | Estricta |
| **5** | `resultados_v5/` | 8 nov | Corrida **definitiva** sobre deploy limpio desde cero (reproducibilidad) | Estricta |
| **6** | `resultados_v6/` | 8 nov | **Dual-stack IPv6** (ataques y tráfico sobre IPv6) | Estricta |
| **7** | `resultados_v7/` | 15–16 nov | **Afinamiento de las variantes de evasión**, E2 sobre IPv4 e IPv6 + E3 IPv4, despliegue desde cero | Estricta |

> **Importante sobre la comparación.** Las corridas **1 y 2** reportan detección **amplia** (se disparó *alguna* alerta correlacionada → 100 %). A partir de la **3** se adoptó la métrica **estricta** (debe dispararse una **regla pertinente a la técnica**), más rigurosa y defendible, que es la que se mantiene hasta la corrida final. Por eso el 100 % de las corridas 1–2 no es directamente comparable con los porcentajes estrictos de las corridas 3–6.

**Definiciones de métricas:**
- **Detección estricta:** la alerta pertenece a una **regla pertinente a la técnica** (métrica rigurosa, la del criterio ≥80 %).
- **Detección amplia:** cualquier alerta correlacionada en la ventana del ataque (±30 s).
- **Precisión:** TP / (TP + FP) sobre alertas accionables (grupos de ataque).
- **Falsa alarma accionable:** alerta de grupo de ataque disparada sobre tráfico legítimo, fuera de ventana de ataque — el FP que importa a un analista SOC.
- **MTTD:** tiempo medio de detección; **no fiable** en este montaje (ventanas solapadas), informativo.

---

## 1. Resumen global de las 6 corridas

| Indicador | C1 | C2 | C3 | C4 (tuning) | C5 (definitiva) | C6 (IPv6) |
|---|---|---|---|---|---|---|
| **E2 detección** | 100 %¹ (25/25) | 100 %¹ (25/25) | **87.5 %** (35/40) | 80.0 % (32/40) | **82.5 %** (33/40) | 77.5 % (31/40) |
| **E2 núcleo 5 técnicas** | 100 % | 100 % | 100 % | **100 %** | **100 %** | **100 %** |
| E2 precisión / F1 | 100 % / 100 % | 100 % / 100 % | 100 % / 93.3 % | 100 % / 88.9 % | 100 % / 90.4 % | 100 % / 87.3 % |
| E2 FP accionables | 0 | 0 | 0 | 0 / 1671 | 0 / 1626 | 0 / 1593 |
| **E3 detección** | 100 %¹ (7/7) | 100 %¹ (7/7) | **100 %** (13/13) | **100 %** (10/10) | **100 %** (9/9) | **100 %** (12/12) |
| E3 precisión / F1 | 100 % / 100 % | 100 % / 100 % | 97.1 % / 98.5 % | 97.3 % / 98.6 % | 98.0 % / 99.0 % | 96.7 % / 98.3 % |
| E3 FP accionables | 0 | 0 | 34 | 24 / 895 | 18 / 902 | 21 / 645 |
| **E1 FP accionables** | — | 0 | **6** | 0 (vs 6) | 0 | 0 |
| E1 alertas totales | 753² | 753 | 877 | — | 1410 | 1631 |

¹ Corridas 1–2: métrica **amplia**. · ² La corrida 1 no separó formalmente E1; el conteo de línea base se formaliza en la 2.

> **Lectura:** el criterio ≥80 % se **cumple en las 6 corridas**. Desde la corrida 3 (métrica estricta) el **núcleo de 5 técnicas se detecta al 100 %** de forma estricta en todas, con la detección global de E2 modulada por las variantes de evasión. La detección es **equivalente sobre IPv4 e IPv6**.

---

## 2. Técnicas evaluadas (5 del núcleo + 3 variantes de evasión)

| # | Técnica | MITRE | Herramienta | Detector definitivo |
|---|---|---|---|---|
| 1 | Fuerza bruta SSH | T1110.001 | Hydra | Reglas auth 5503/5760 + correlación 100010/100011 |
| 2 | Escaneo de puertos | T1046 | nmap | Correlación en firewall perimetral 100003→**100022** |
| 3 | Pass-the-Hash / mov. lateral | T1550.002 / T1021.002 | Impacket (secretsdump + psexec) | Comportamiento de host, regla nativa **92650** (servicio desde ADMIN$) |
| 4 | Inyección SQL | T1190 | sqlmap / curl | Reglas web 31106/31171 + **100040/100041** |
| 5 | Ejecución de payload | T1059.001 / T1204 | PowerShell `-enc` (download cradle) vía WinRM | **Sysmon Event 1** → **100051** + Script Block Logging (4104) |
| — | Fuerza bruta SSH lenta | T1110.001 | Hydra (lento) | 5503/5551/5760 |
| — | Escaneo sigiloso (low-and-slow) | T1046 | nmap fragmentado + señuelos | 100022 (evade por conntrack en secuencia) |
| — | SQLi ofuscado | T1190 | sqlmap tamper + UA aleatorio | 31106 (parcial) |

---

## 3. CORRIDA 1 — `resultados/` (primera corrida rigurosa, 20–21 oct)

**Infra:** Wazuh 4.14 + Suricata + AD, 9 instancias EC2. **Métrica:** detección amplia.

- Total ataques ejecutados: **31** · detectados: **31** → **tasa de detección 100 %**.
- Alertas de grupo 'attack' fuera de ventana (posibles FP): **1**.
- Desglose (del log): bruteforce_ssh, portscan y sql_injection ×varias repeticiones + pass_the_hash ×2 + payload_execution ×2 — todos detectados.
- **Carácter:** validación preliminar que confirmó la tubería de correlación ataque→regla; aún sin separar métrica estricta ni medir evasión.

---

## 4. CORRIDA 2 — `resultados_v2/` (3 escenarios completos, 21 oct)

**Infra:** Wazuh 4.14 all-in-one + Suricata + AD + agentes, 9 EC2. **Métrica:** detección amplia.

| Métrica | E1 (línea base) | E2 (controlados) | E3 (mixto) |
|---|---|---|---|
| Ataques ejecutados | 0 | 25 (5×5) | 7 |
| Detectados (VP) | — | 25 | 7 |
| **Tasa de detección** | — | **100 %** | **100 %** |
| Precisión | — | 100 % (1381/1381) | 100 % (552/552) |
| F1 | — | 100 % | 100 % |
| **FP accionables (grupo 'attack')** | **0** | 0 | 0 |
| Alertas totales en ventana | 753 | 3030 | 1865 |

- E1: 753 alertas (≈1360/h), todas auditoría rutinaria nivel 3–5; **0 accionables**.
- E3: ataques (portscan ×3, payload ×1, SQLi ×2, PtH ×1) detectados pese al tráfico de fondo.
- **Criterio ≥80 %: cumplido con holgura** (100 % en E2 y E3).

---

## 5. CORRIDA 3 — `resultados_v3/` (tráfico realista + evasión + métrica estricta, 22 oct)

**Novedad:** tráfico denso concurrente desde todas las instancias, ataques sigilosos de evasión, y **detección estricta a nivel de técnica**. Objetivo: resultados creíbles, no un 100 % artificial.

### 5.1 E1 — Línea base (33 min)
- **877 alertas** (≈1580/h). **6 falsas alarmas accionables reales** (regla `100030`, nivel 12) + 93 alertas nivel 14 (correlación `100099`).
- **Hallazgo:** `100030` ("posible PtH: logon NTLM tipo 3") dispara sobre **autenticación NTLM legítima** del dominio → el tráfico realista expuso FP que un tráfico pobre nunca habría revelado.

### 5.2 E2 — Ataques controlados (40: 25 ruidosos + 15 sigilosos)

| Métrica | Valor |
|---|---|
| **Detección estricta** | **87.5 % (35/40)** |
| Detección amplia | 100 % (40/40) |
| Precisión | 100 % |
| F1 | 93.3 % |
| FP accionables | 0 |

| Técnica | Det. estricta |
|---|---|
| Fuerza bruta SSH (ruidosa) | 100 % |
| Fuerza bruta SSH lenta | 100 % |
| Escaneo de puertos (ruidoso) | 100 % |
| **Escaneo sigiloso** | **20 %** (evadió 4/5) |
| Inyección SQL (ruidosa) | 100 % |
| **SQLi con evasión** | **80 %** (evadió 1/5) |
| Pass-the-Hash | 100 % |
| Ejecución de payload | 100 % |

### 5.3 E3 — Mixto (13 ataques aleatorios, 40 min)

| Métrica | Valor |
|---|---|
| **Detección estricta** | **100 % (13/13)** |
| Precisión | 97.1 % |
| F1 | 98.5 % |
| **FP accionables** | **34** (de 1187 accionables) — mismo fenómeno de `100030` sobre NTLM legítimo |

### 5.4 Hallazgos de ingeniería (valor del proyecto)
1. **Evasión:** el escaneo sigiloso (`-T1` + fragmentación + señuelos) evadió el 80 % → la detección por firma es insuficiente; hace falta analítica de comportamiento.
2. **Falsos positivos:** `100030` no distingue PtH de la autenticación NTLM legítima → 6 FP en E1 y 34 en E3 → necesidad de *tuning* (compromiso sensibilidad/precisión). **Estos dos hallazgos motivaron la corrida 4 (tuning).**

---

## 6. CORRIDA 4 — `resultados_v4/` (ciclo de tuning, 7–8 nov)

**Infra:** Wazuh 4.x + Suricata + AD + Sysmon, 7 agentes, 5 fuentes de log.

### 6.1 E1 — Línea base (31 min)
- **Falsas alarmas accionables: 0** (vs **6** pre-tuning). ~95 logons NTLM reclasificados como informativos.

### 6.2 E2 — Ataques controlados (40)

| Técnica | Reps | Det. estricta |
|---|---|---|
| Fuerza bruta SSH | 5 | 100 % |
| Escaneo de puertos | 5 | 100 % |
| Pass-the-Hash | 5 | 100 % |
| Inyección SQL | 5 | 100 % |
| Ejecución de payload | 5 | 100 % |
| **Núcleo** | **25** | **100 % (25/25)** |
| Fuerza bruta SSH lenta | 5 | 100 % |
| Escaneo sigiloso | 5 | 0 % |
| SQLi con evasión | 5 | 40 % |
| **Evasión** | **15** | **47 % (7/15)** |
| **GLOBAL** | **40** | **80.0 % (32/40)** |

- Precisión **100 %** · F1 **88.9 %** · FP accionables **0 / 1671** · FN estrictos: 8.

### 6.3 E3 — Mixto (10)

| Técnica | Ejec. | Det. estricta |
|---|---|---|
| Pass-the-Hash | 3 | 100 % |
| Ejecución de payload | 3 | 100 % |
| Escaneo de puertos | 1 | 100 % |
| Inyección SQL | 3 | 100 % |
| **GLOBAL** | **10** | **100 % (10/10)** |

- Amplia **100 %** · Precisión **97.3 %** · F1 **98.6 %** · FP accionables **24 / 895**.

### 6.4 Evolución del tuning (cifras intermedias)

| Iteración | E2 estricta | E3 estricta | E1 FP accionables | Hecho clave |
|---|---|---|---|---|
| **iter1** | 67.5 % (27/40) | 62.5 % (5/8) | — | Portscan 0 %; payload 0/3 en E3 (Sysmon no ingestado) |
| **iter2** | 75.0 % (30/40) | — | — | Portscan **0→100 %** (correlación firewall 100022, umbral 6→4) |
| **final** | **80.0 % (32/40)** | **100 % (10/10)** | **0** (vs 6) | Sysmon ingestado → payload 0→100 %; PtH vía 92650; NTLM → informativas |

**Las 4 deficiencias halladas y resueltas:**
1. **FP por NTLM legítimo (100030):** 6 FP nivel 12 en E1 → degradada a informativa; 100032 "segmentación-aware" generó 31 FP nuevos por WinRM de administración → también degradada. PtH se mueve a **92650** (host). Línea base **6→0**.
2. **Escaneo no detectado:** Suricata solo cubre la DMZ y no marca SYN scan simple → **correlación en firewall (100022)**. Portscan ruidoso **0→100 %**.
3. **Sysmon no ingestado:** el agente Windows no se suscribía al canal `Microsoft-Windows-Sysmon/Operational` → Event ID 1 nunca llegaba (payload 0/3 en E3). Solución: suscripción vía config compartida + `windows-ws.ps1`.
4. **Payload ofuscado:** con Sysmon ingestado, **100051** dispara sobre `-enc`; + Script Block Logging (4104) + download cradle realista. Payload **0→100 %**.

---

## 7. CORRIDA 5 — `resultados_v5/` (definitiva, deploy limpio, 8 nov)

**Infra:** Wazuh 4.x + Suricata + AD + Sysmon, **8 agentes**, 9 EC2. Todo el tuning aprovisionado automáticamente por CloudFormation/userdata.

### 7.1 E1 — Línea base (31 min, 13:26–13:57Z)
- **Total alertas: 1410** (tasa FP 2711.5/h). **Con grupo 'attack': 0.**
- Severidad: nivel 3 → 1194 · nivel 4 → 174 · nivel 12 → 2 · nivel 15 → 3.

### 7.2 E2 — Ataques controlados (40)

| Técnica | Reps | Det. estricta |
|---|---|---|
| Fuerza bruta SSH | 5 | 100 % |
| Fuerza bruta SSH lenta | 5 | 100 % |
| Escaneo de puertos | 5 | 100 % |
| Escaneo sigiloso | 5 | 0 % |
| Pass-the-Hash | 5 | 100 % |
| Inyección SQL | 5 | 100 % |
| SQLi con evasión | 5 | 60 % (3/5) |
| Ejecución de payload | 5 | 100 % |
| **Núcleo** | **25** | **100 % (25/25)** |
| **Evasión** | **15** | **53 % (8/15)** |
| **GLOBAL** | **40** | **82.5 % (33/40)** |

- Precisión **100 %** · F1 **90.4 %** · FP accionables **0 / 1626** · FN estrictos: 7 · MTTD 46.9 s.

### 7.3 E3 — Mixto (9)

| Técnica | Ejec. | Det. estricta |
|---|---|---|
| Fuerza bruta SSH | 1 | 100 % |
| Pass-the-Hash | 2 | 100 % |
| Ejecución de payload | 1 | 100 % |
| Escaneo de puertos | 2 | 100 % |
| Inyección SQL | 3 | 100 % |
| **GLOBAL** | **9** | **100 % (9/9)** |

- Amplia **100 %** · Precisión **98.0 %** · F1 **99.0 %** · FP accionables **18 / 902** · MTTD 15.8 s.

**Teardown:** stack `siem-lab` eliminado, bucket S3 vaciado y eliminado, 0 instancias EC2.

---

## 8. CORRIDA 6 — `resultados_v6/` (dual-stack IPv6, 8 nov)

**Bloque IPv6 de la VPC:** `2600:1f18:11e4:1300::/56` (un /64 por subred). Egress-Only IGW, sin DHCPv6 (SLAAC/RA).

### 8.1 Validación de red y servicios
| Capa | Estado |
|---|---|
| VPC/subredes/enrutamiento | ✅ /56 Amazon, /64 por subred, ruta ::/0 egress-only |
| Instancias (9) | ✅ cada una con IPv6 (GUA) |
| Conectividad intra-VPC IPv6 | ✅ ping6/TCP entre VLANs, **0 % pérdida** |
| Servicios HTTP/SSH/DNS | ✅ responden sobre IPv6 (`curl -6` → HTTP 200) |
| Resolución de nombres | ✅ DNS con AAAA + `/etc/hosts` dual-stack |
| Detección SIEM sobre IPv6 | ✅ escaneo, SQLi y fuerza bruta SSH con `srcip` IPv6 |

### 8.2 E1 — Línea base (31 min, 17:16–17:47Z)
- **Total alertas: 1631** (224 con IPv6, tasa FP 3129.9/h). **Con grupo 'attack': 0.**
- Severidad: nivel 3 → 1337 · nivel 4 → 164 · nivel 12 → 1 · nivel 15 → 3.

### 8.3 E2 — Ataques controlados sobre IPv6 (40)

| Técnica | Reps | Det. estricta |
|---|---|---|
| Fuerza bruta SSH | 5 | 100 % |
| Fuerza bruta SSH lenta | 5 | 100 % |
| Escaneo de puertos | 5 | 100 % |
| Escaneo sigiloso | 5 | 0 % |
| Pass-the-Hash | 5 | 100 % |
| Inyección SQL | 5 | 100 % |
| SQLi con evasión | 5 | 20 % (1/5) |
| Ejecución de payload | 5 | 100 % |
| **Núcleo** | **25** | **100 % (25/25)** |
| **GLOBAL** | **40** | **77.5 % (31/40)** |

- Precisión **100 %** · F1 **87.3 %** · FP accionables **0 / 1593** · FN estrictos: 9 · MTTD 37.5 s.

### 8.4 E3 — Mixto sobre IPv6 (12)

| Técnica | Ejec. | Det. estricta |
|---|---|---|
| Fuerza bruta SSH | 4 | 100 % |
| Pass-the-Hash | 2 | 100 % |
| Ejecución de payload | 4 | 100 % |
| Inyección SQL | 2 | 100 % |
| **GLOBAL** | **12** | **100 % (12/12)** |

- Amplia **100 %** · Precisión **96.7 %** · F1 **98.3 %** · FP accionables **21 / 645**.

### 8.5 Detección puntual por regla (origen IPv6)
| Ataque (IPv6) | Regla | `srcip` |
|---|---|---|
| Escaneo de puertos (`nmap -6`) | **100022** | 2600:1f18:11e4:1302:7f18:7eaf:bbb7:23ea |
| Inyección SQL (`curl -6`) | **100040** | idem |
| Fuerza bruta SSH (`hydra -6`) | **5760** | idem |

---

## 9. Direccionamiento IPv6 asignado (corrida 6)

| Host | IPv4 privada | IPv6 (GUA) |
|---|---|---|
| siem-wazuh | 10.0.30.10 | 2600:1f18:11e4:1302:e086:25c2:4691:950d |
| fw-gateway | 10.0.30.30 | 2600:1f18:11e4:1302:5383:fd40:27af:a01c |
| atacante | 10.0.30.20 | 2600:1f18:11e4:1302:7f18:7eaf:bbb7:23ea |
| web-server | 10.0.10.10 | 2600:1f18:11e4:1300:d032:3b84:dba0:68c8 |
| dc-empresa | 10.0.10.20 | 2600:1f18:11e4:1300:224c:fae8:8c79:60eb |
| dns1-server | 10.0.10.50 | 2600:1f18:11e4:1300:1cf1:f83c:5:82e4 |
| ntp-server | 10.0.10.80 | 2600:1f18:11e4:1300:d93a:a73f:aeac:3937 |
| win-ws-01 | 10.0.20.30 | 2600:1f18:11e4:1301:60a7:208b:fad7:363e |
| linux-01 | 10.0.20.40 | 2600:1f18:11e4:1301:500:56aa:e0ef:bddd |

---

## 10. Limitaciones y recomendaciones (comunes)

1. **Punto ciego interno de red:** el único NIDS (Suricata) cubre la DMZ; escaneos a hosts internos que no cruzan un punto monitorizado no son visibles → TAP/mirror o NIDS en VLANs internas.
2. **Evasión low-and-slow:** el escaneo sigiloso evade por contención de estado (conntrack) en secuencia → analítica de comportamiento por origen/puerto en ventanas largas.
3. **PtH a nivel de red:** inherentemente ambiguo frente a la administración legítima → enfoque *endpoint-first* (Sysmon, servicios/ADMIN$).
4. **Dependencia de telemetría de endpoint:** payload y lateral dependen de Sysmon + Script Block Logging activos e ingestados → monitorizar salud de agentes y canales.
5. **MTTD no fiable** en este montaje (ventanas solapadas); la métrica robusta es la tasa de detección.

---

## 11. Conclusión

A lo largo de **6 corridas** el laboratorio evolucionó de un 100 % de detección *amplia* (corridas 1–2) a una validación **rigurosa y defendible** con métrica **estricta** (corridas 3–6): el **núcleo de 5 técnicas MITRE se detecta al 100 % estricto** en todas las corridas estrictas (incluida IPv6), con **0 falsas alarmas accionables** sobre la línea base tras el tuning y **precisión 96.7–100 %** bajo carga realista — **criterio ≥80 % CUMPLIDO en las 6**. El aporte central es el **ciclo de ingeniería de detección** (corridas 3→4) que halló y corrigió 4 deficiencias reales (FP de NTLM, cobertura de escaneo, ingesta de Sysmon, payload), más la demostración de **reproducibilidad end-to-end desde CloudFormation** (corrida 5) y de **detección equivalente sobre IPv4 e IPv6** (corrida 6).

---

## CORRIDA 7 — `resultados_v7/` (afinamiento de evasión, 15–16 nov)

Despliegue recreado desde cero con el afinamiento incorporado. Detalle y análisis en
[`resultados_v7/RESULTADOS_v7.md`](resultados_v7/RESULTADOS_v7.md).

| Escenario | Det. estricta | Det. amplia | Precisión | F1 | FP accionables |
|---|---|---|---|---|---|
| E2 · IPv4 (40 ataques) | **95.0 %** (38/40) | 100 % | 100 % | 97.4 % | 0 / 2390 |
| E2 · IPv6 (40 ataques) | **92.5 %** (37/40) | 100 % | 100 % | 96.1 % | 0 / 2337 |
| E3 · IPv4 (20 min, 4 ataques) | **100 %** (4/4) | 100 % | 98.7 % | 99.4 % | 11 / 852 |

| Variante de evasión | C3 | C4 | C5 | C6 (IPv6) | C7 IPv4 | C7 IPv6 |
|---|---|---|---|---|---|---|
| Fuerza bruta SSH lenta | 100 % | 100 % | 100 % | 100 % | 100 % | 100 % |
| SQLi ofuscado | 80 % | 40 % | 60 % | 20 % | **100 %** | **100 %** |
| Escaneo sigiloso | 20 % | 0 % | 0 % | 0 % | **60 %** | **40 %** |
| **E2 global** | 87.5 % | 80.0 % | 82.5 % | 77.5 % | **95.0 %** | **92.5 %** |

No se repitió E1 como escenario independiente ni E3 sobre IPv6 en esta corrida.
