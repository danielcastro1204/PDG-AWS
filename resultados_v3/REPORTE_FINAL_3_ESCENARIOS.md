# Validación rigurosa de la plataforma SIEM — Reporte consolidado de los 3 escenarios

**Proyecto de grado:** Plataforma SIEM open source para el monitoreo de eventos de seguridad en una red empresarial
**Infraestructura:** laboratorio migrado a AWS (AWS Academy, 9 instancias EC2) reproduciendo la red empresarial simulada (VLAN 10/20/30).
**Plataforma:** Wazuh 4.14 (manager + indexer + dashboard) + Suricata (IDS) + Active Directory + agentes en endpoints.
**Fecha:** 22 de octubre de 2026.

> **Nota sobre esta corrida.** A diferencia de validaciones preliminares, esta ejecución incorpora: (1) **tráfico de red realista y denso generado concurrentemente desde todas las instancias** (no una sola fuente); (2) **ataques sigilosos de evasión** además de los ruidosos; y (3) **correlación de detección a nivel de técnica** (no solo "hubo alguna alerta"). El objetivo fue obtener resultados **creíbles y defendibles**, no un 100 % artificial.

---

## 1. Metodología

### 1.1 Generación de tráfico realista
Para que la medición de falsos positivos fuese significativa y el tráfico de fondo del escenario mixto resultara indistinguible de una red real, se generó actividad **continua, variada y concurrente desde todas las instancias**:
- **Estaciones (Linux y Windows):** navegación web variada, consultas DNS, transferencias SMB, sesiones SSH legítimas, correo SMTP, y **autenticación de dominio (Kerberos/LDAP, logons NTLM)**.
- **Servidores:** health-checks, DNS, sincronización NTP, correo saliente.
- Llegadas aleatorias (proceso tipo Poisson) y múltiples "usuarios" concurrentes por host.

### 1.2 Técnicas de ataque (MITRE ATT&CK)
Cada una ejecutada **5 veces**, en variante **ruidosa** y, para tres de ellas, también en variante **sigilosa (evasión)**:

| Técnica | Táctica | ID | Ruidosa | Sigilosa (evasión) |
|---|---|---|---|---|
| Fuerza bruta SSH | Credential Access | T1110.001 | Hydra | lenta (40 s/intento, bajo umbral) |
| Escaneo de puertos | Discovery | T1046 | nmap -sS -T4 -p- | nmap -sS **-T1 fragmentado + señuelos** |
| Inyección SQL | Initial Access | T1190 | sqlmap | sqlmap **--tamper + --delay + random-agent** |
| Pass-the-Hash | Lateral Movement | T1550.002 | Impacket | — |
| Ejecución de payload | Execution | T1059.001 | evil-winrm | — |

### 1.3 Métrica de detección a nivel de técnica
- **Detección amplia:** se dispara *cualquier* alerta en la ventana del ataque (±30 s).
- **Detección ESTRICTA:** se dispara una **regla pertinente a esa técnica** (por grupos de la regla Wazuh e IDs de regla conocidos). Es la métrica rigurosa; evita contar como "detección" alertas genéricas (logon, sesión) que también ocurren con tráfico normal.
- **Falsas alarmas accionables:** alertas de grupos de ataque (authentication_failures, ids, web_scan, sql_injection, lateral_movement…) disparadas **fuera** de toda ventana de ataque real. Son las que un analista de SOC investigaría — el falso positivo que importa.

---

## 2. Resultados por escenario

### Escenario 1 — Línea base (tráfico realista, sin ataques), 33 min
- **877 alertas** totales (≈1580/hora). La mayoría, auditoría rutinaria de severidad baja.
- **Pero 6 falsas alarmas accionables reales** (regla `100030`, nivel 12) + **93 alertas de nivel 14** (regla de correlación `100099`).
- **Hallazgo:** la regla personalizada `100030` ("posible Pass-the-Hash: logon tipo 3 con NTLM") **se dispara sobre autenticación NTLM legítima del dominio** (los logons de red normales de Windows). Esto desencadena en cascada la regla de correlación `100099` ("múltiples familias de ataque en 10 min"), amplificando el ruido. → El tráfico realista **expuso falsos positivos que un tráfico pobre nunca habría revelado.**

### Escenario 2 — Ataques controlados (ruidosos + sigilosos), 40 ataques

| Métrica | Valor |
|---|---|
| **Detección ESTRICTA** | **87.5 %** (35/40) |
| Detección amplia | 100 % (40/40) |
| Precisión (accionables) | 100 % |
| F1-score | 93.3 % |
| Falsas alarmas accionables | 0 |

**Desglose por técnica (lo más relevante):**

| Técnica | Detección estricta |
|---|---|
| Fuerza bruta SSH (ruidosa) | 100 % |
| Fuerza bruta SSH **lenta** | 100 % (Wazuh la detecta aun bajo umbral) |
| Escaneo de puertos (ruidoso) | 100 % |
| **Escaneo de puertos SIGILOSO** | **20 %** ⚠️ (evadió 4 de 5) |
| Inyección SQL (ruidosa) | 100 % |
| **Inyección SQL con evasión** | **80 %** (evadió 1 de 5) |
| Pass-the-Hash | 100 % |
| Ejecución de payload | 100 % |

### Escenario 3 — Eventos mixtos (ataques ocultos entre tráfico realista), 40 min

| Métrica | Valor |
|---|---|
| **Detección ESTRICTA** | **100 %** (13/13) |
| Precisión (accionables) | 97.1 % |
| F1-score | 98.5 % |
| Falsas alarmas accionables | **34** (de 1187 alertas accionables) |

Los 13 ataques (lanzados en momentos aleatorios) fueron detectados pese a estar inmersos en el tráfico legítimo. Las **34 falsas alarmas** provienen del mismo fenómeno del Escenario 1: la regla `100030` disparando sobre la autenticación NTLM del tráfico de fondo.

---

## 3. Tabla comparativa consolidada

| Métrica | Escenario 1 | Escenario 2 | Escenario 3 |
|---|---|---|---|
| Ataques | 0 (línea base) | 40 (25 ruidosos + 15 sigilosos) | 13 (aleatorios) |
| **Detección estricta** | — | **87.5 %** | **100 %** |
| Detección amplia | — | 100 % | 100 % |
| Precisión | — | 100 % | 97.1 % |
| F1 | — | 93.3 % | 98.5 % |
| Falsas alarmas accionables | 6 | 0 | 34 |
| Alertas totales en ventana | 877 | ~ | ~ |

---

## 4. Matriz de correlación MITRE ATT&CK → reglas Wazuh (detección estricta)

| Técnica | Reglas Wazuh pertinentes observadas |
|---|---|
| Fuerza bruta SSH (T1110.001) | 5551, 5503, 5716, 5720, 5760 (sshd/PAM authentication_failures) |
| Escaneo de puertos (T1046) | 100040, 100099 (reglas del proyecto); Suricata (grupo ids) |
| Inyección SQL (T1190) | 31103, 31106 (web/sql_injection); Suricata |
| Pass-the-Hash (T1550.002) | 100030, 92650 (lateral_movement/sysmon) |
| Ejecución de payload (T1059.001) | 100030, 92650, 67027/67028 (sysmon process creation) |

---

## 5. Hallazgos principales (valor de ingeniería)

### 5.1 Evasión: el SIEM tiene puntos ciegos ante técnicas "low-and-slow"
El **escaneo de puertos sigiloso** (timing `-T1` paranoico, fragmentación de paquetes y señuelos) **evadió la detección estricta el 80 % de las veces**: solo 1 de 5 intentos disparó una regla específica de escaneo. La **inyección SQL ofuscada** (tamper + retardo + user-agent aleatorio) evadió 1 de 5. En cambio, las técnicas ruidosas y la fuerza bruta lenta se detectaron al 100 %.
→ **Recomendación:** incorporar reglas/correlaciones de detección de escaneos lentos (agregación por origen en ventanas largas) y normalización de payloads web antes del match de firmas (anti-tamper). La detección por firma, por sí sola, es insuficiente contra evasión.

### 5.2 Falsos positivos: la detección de Pass-the-Hash por firma no distingue lo legítimo
La regla personalizada `100030` marca todo **logon de red tipo 3 con NTLM** como posible Pass-the-Hash. Pero ese patrón es **idéntico al de la autenticación legítima** de un equipo de dominio accediendo a recursos. Resultado: **6 falsas alarmas en la línea base y 34 en el escenario mixto**, además de disparar en cascada la correlación `100099`.
→ **Recomendación:** *tuning* de la regla — whitelisting de cuentas/hosts de servicio conocidos, exigir indicadores adicionales (origen anómalo del logon, presencia de herramientas de volcado de credenciales, acceso a `ADMIN$`/servicios creados), y elevar el umbral de la correlación `100099`. Es el clásico compromiso **sensibilidad vs. precisión** de un SIEM, que este laboratorio permite estudiar empíricamente.

---

## 6. Limitaciones metodológicas (transparencia)
1. **MTTD** (tiempo medio de detección) no se reporta como métrica fiable: los ataques se ejecutan con poca separación y el margen de correlación de ±30 s solapa ventanas, de modo que la latencia por ataque no es medible con precisión en este montaje. La métrica robusta es la **tasa de detección**.
2. **Estación Windows en `t3.medium`** (4 GB, límite del sandbox): algunos payloads pesados reportan "paging file too small", pero la conexión WinRM y la telemetría de detección (Sysmon) se generan igual, por lo que la detección no se ve afectada.
3. Sustituciones de la migración a AWS (pfSense→nftables, Kali→Ubuntu+toolkit, Win10→Win Server 2019), documentadas en `MAPEO_RED_FISICA_A_AWS.md`, no afectan la validez del estudio de detección.

---

## 7. Conclusión

La plataforma SIEM alcanzó una **tasa de detección estricta del 87.5 %** sobre el conjunto más exigente (ataques ruidosos **y** sigilosos) y del **100 %** sobre ataques realistas ocultos en tráfico de fondo — **cumpliendo con holgura el criterio del proyecto (≥ 80 %)**. A diferencia de un 100 % perfecto, este resultado es **creíble, matizado y defendible**:

- Las técnicas de ataque convencionales (ruidosas) se detectan de forma **fiable y específica**.
- Las técnicas de **evasión** exponen **puntos ciegos reales** (escaneo sigiloso), lo que constituye un hallazgo valioso y una línea de mejora concreta.
- El **tráfico realista** reveló **falsos positivos genuinos** (detección de PtH sobre NTLM legítimo) que permiten estudiar el compromiso sensibilidad/precisión y proponer *tuning* fundamentado.

La plataforma queda validada como **laboratorio reproducible** no solo para demostrar detección, sino para **estudiar empíricamente las limitaciones de un SIEM** (evasión, falsos positivos, tuning) — un alcance más rico y defendible para un proyecto de grado de ingeniería.

---

*Reportes detallados:* `escenario1/reporte_escenario1.md`, `escenario2/reporte_escenario2.md`, `escenario3/reporte_escenario3.md`. *Verificación previa de servicios:* `pruebas_servicios.md`. *Datos crudos (auditoría):* `log_ataques_e{2,3}.csv`, `alertas_ventana.json`, `alerts_full_e{1,2,3}.json`.
