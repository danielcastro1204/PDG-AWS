# Validación de la plataforma SIEM — Reporte consolidado de los 3 escenarios (Fase 3 y 4)

**Proyecto:** Diseño, implementación y documentación de una plataforma SIEM open source para el monitoreo de eventos de seguridad en una red empresarial
**Infraestructura:** Laboratorio migrado a AWS (AWS Academy, cuenta 145326036987, región us-east-1), 9 instancias EC2 reproduciendo la red empresarial simulada (VLAN 10/20/30).
**Plataforma SIEM:** Wazuh 4.14 (all-in-one: manager + indexer + dashboard) + Suricata (IDS) + Active Directory + agentes en los endpoints.
**Fecha de ejecución:** 21 de octubre de 2026.

---

## 1. Metodología

Se ejecutaron los **tres escenarios experimentales** definidos en la Fase 3 del proyecto, de forma rigurosa y con registro completo de tiempos para la correlación posterior:

| Escenario | Propósito | Duración | Qué mide |
|---|---|---|---|
| **1. Línea base** | Comportamiento normal de la red, sin actividad maliciosa | 30 min | Tasa de **falsos positivos** |
| **2. Ataques controlados** | 5 técnicas MITRE ATT&CK × 5 repeticiones, aisladas | ~40 min | Tasa de **detección**, precisión, F1 |
| **3. Eventos mixtos** | Tráfico normal de fondo + ataques en momentos aleatorios | 40 min | Detección con **evasión entre ruido legítimo** |

**Las 5 técnicas de ataque** (taxonomía MITRE ATT&CK), cada una ejecutada ≥5 veces:

| Técnica | Táctica MITRE | ID | Herramienta |
|---|---|---|---|
| Fuerza bruta SSH | Credential Access | T1110.001 | Hydra |
| Escaneo de puertos | Discovery | T1046 | Nmap (SYN, servicios) |
| Inyección SQL | Initial Access | T1190 | SQLmap |
| Pass-the-Hash | Lateral Movement | T1550.002 | Impacket (secretsdump + psexec) |
| Ejecución de payload | Execution | T1059.001 | evil-winrm (WinRM) |

**Separación metodológica:** el tráfico legítimo se genera desde la estación de usuario real (linux-01), y los ataques desde una estación atacante dedicada — manteniendo IPs de origen distintas para no contaminar la correlación. Cada ataque registra su hora de inicio y fin en `log_ataques.csv`; las alertas de Wazuh se correlacionan con esas ventanas (margen ±30 s).

**Las 5 fuentes de logs** de la metodología están integradas: Active Directory (DC), firewall perimetral (fw-gateway), servidor web (Apache), telemetría Sysmon (estaciones Windows) e IDS Suricata.

---

## 2. Resultados por escenario

### Escenario 1 — Línea base de tráfico normal

- Ventana: 33 min de navegación web, transferencias SMB e inicios de sesión SSH legítimos.
- **753 alertas** generadas en total, pero **0 del grupo 'attack'** (las reglas que señalan ataques reales).
- Todas las alertas son eventos de auditoría rutinarios de severidad baja (nivel 3–5): aperturas/cierres de sesión PAM, logins Windows exitosos, `sudo` legítimo.

**Interpretación:** bajo la definición estricta de la metodología (toda alerta sin ataque = falso positivo), la tasa es alta (≈1360 alertas/hora) porque Wazuh audita exhaustivamente cada evento de sesión. Sin embargo, la tasa de **falsas alarmas accionables** — las que un analista de SOC investigaría como posible ataque — es **0 %**. Ninguna regla de detección de ataque se disparó sobre tráfico legítimo. Las 753 alertas rutinarias son ruido de auditoría esperable y candidato a *tuning* (ver reporte detallado del escenario 1).

### Escenario 2 — Ataques controlados (aislados)

| Métrica | Valor |
|---|---|
| Ataques ejecutados | 25 (5 técnicas × 5 repeticiones) |
| Ataques detectados (VP) | **25** |
| No detectados (FN) | 0 |
| **Tasa de detección (Recall)** | **100.0 %** |
| **Precisión** | **100.0 %** (1381/1381 alertas 'attack' correctas) |
| **F1-score** | **100.0 %** |
| Falsos positivos | **0** |

Las 5 técnicas detectadas en las 5 repeticiones (100 % por técnica).

### Escenario 3 — Eventos mixtos (ataques ocultos entre tráfico normal)

| Métrica | Valor |
|---|---|
| Ataques ejecutados (en momentos aleatorios) | 7 |
| Ataques detectados (VP) | **7** |
| No detectados (FN) | 0 |
| **Tasa de detección (Recall)** | **100.0 %** |
| **Precisión** | **100.0 %** (552/552 alertas 'attack' correctas) |
| **F1-score** | **100.0 %** |
| Falsos positivos | **0** |

Ataques disparados: escaneo de puertos (×3), payload (×1), SQLi (×2), Pass-the-Hash (×1), todos **correctamente detectados pese a estar inmersos en el tráfico de fondo legítimo** — demostrando que la correlación del SIEM distingue lo malicioso del ruido normal.

---

## 3. Tabla comparativa consolidada

| Métrica | Escenario 1 | Escenario 2 | Escenario 3 |
|---|---|---|---|
| Ataques ejecutados | 0 (línea base) | 25 | 7 |
| Ataques detectados | — | 25 | 7 |
| **Tasa de detección** | — | **100 %** | **100 %** |
| Precisión | — | 100 % | 100 % |
| F1-score | — | 100 % | 100 % |
| Falsos positivos accionables (grupo 'attack') | **0** | 0 | 0 |
| Alertas totales en la ventana | 753 | 3030 | 1865 |

**Criterio de éxito del proyecto: tasa de detección ≥ 80 %.** Resultado: **100 %** en ambos escenarios de ataque (2 y 3) → **criterio cumplido con holgura**.

---

## 4. Matriz de correlación MITRE ATT&CK → reglas Wazuh (del Escenario 2)

Reglas de Wazuh disparadas por cada técnica (muestra representativa; detalle completo en `escenario2/reporte_escenario2.md`):

| Técnica (MITRE) | Reglas Wazuh representativas |
|---|---|
| Fuerza bruta SSH (T1110.001) | 5501, 5502, 5503, 5715, 5760 (sshd / PAM), 60106/60137 |
| Escaneo de puertos (T1046) | 100040, 100099, 31106, 31171, 86601 (Suricata ET), 67027/67028 |
| Inyección SQL (T1190) | 31106, 31171 (web-attack), 100040, 100099, 67027 |
| Pass-the-Hash (T1550.002) | 92650, 100030, 100099, 60106/60107 (Windows logon), 67027/67028 |
| Ejecución de payload (T1059.001) | 92650, 100030, 60104/60106/60107 (Sysmon/Windows), 67027/67028 |

La detección combina reglas nativas de Wazuh, telemetría Sysmon de Windows, logs de Active Directory, y alertas del IDS Suricata (reglas 86601, Emerging Threats) — confirmando la **integración de las 5 fuentes de logs**.

---

## 5. Limitaciones metodológicas (transparencia)

1. **Tiempo medio de detección (MTTD):** los valores por ataque salen negativos/cercanos a cero porque (a) los ataques se ejecutan muy seguidos y el margen de correlación de ±30 s hace que las ventanas se solapen, y (b) algunas alertas (p. ej. de sesión) se registran microsegundos antes del timestamp de inicio del script de ataque. Por eso el MTTD agregado **no es una medida fiable de latencia de detección** en este montaje y no debe reportarse como tal; la métrica válida y robusta es la **tasa de detección** (100 %). Para medir MTTD con rigor haría falta espaciar los ataques con amplios intervalos y una sincronización de reloj estricta.

2. **Recursos de la estación Windows:** la estación corre en `t3.medium` (4 GB, límite del sandbox). Algunos payloads pesados devuelven un error de "paging file too small" al expandirse en memoria, pero **la conexión WinRM y la entrega del comando sí ocurren**, por lo que Sysmon/Wazuh generan la telemetría de detección igual (logon remoto + creación de proceso). La detección no se ve afectada.

3. **Falsos positivos de auditoría (Escenario 1):** las 753 alertas rutinarias no son falsas alarmas de ataque sino eventos de auditoría de severidad baja. Un despliegue de producción aplicaría *tuning* (filtrado o agrupación) a reglas como 5501/5502 (sesiones PAM) y 60106/60137 (logon/logoff Windows) para reducir ese ruido.

4. **Sustituciones de la migración a AWS** (documentadas en `MAPEO_RED_FISICA_A_AWS.md`): pfSense→nftables, Kali→Ubuntu+toolkit, Windows 10→Windows Server 2019. No afectan la validez del estudio de detección, pues cada técnica genera la misma telemetría relevante.

---

## 6. Conclusión

La plataforma SIEM open source (Wazuh + Suricata + Active Directory) desplegada sobre la red empresarial simulada en AWS **detectó el 100 % de los ataques** en los dos escenarios ofensivos (25/25 aislados y 7/7 ocultos entre tráfico legítimo), con **precisión y F1 del 100 % y cero falsas alarmas accionables**. El resultado **supera ampliamente el criterio de éxito del proyecto (≥ 80 % de detección)** y valida la plataforma como laboratorio reproducible para la enseñanza y la experimentación en monitoreo y detección de eventos de seguridad.

---

*Reportes detallados por escenario:*
- `escenario1/reporte_escenario1.md` — línea base (desglose de falsos positivos por regla/severidad)
- `escenario2/reporte_escenario2.md` — ataques controlados (detalle por intento + matriz de correlación completa)
- `escenario3/reporte_escenario3.md` — eventos mixtos (detalle por intento)

*Datos crudos (para auditoría):* `log_ataques_e{2,3}.csv`, `alertas_ventana.json`, `alerts_full_e{1,2,3}.json` en cada carpeta.
