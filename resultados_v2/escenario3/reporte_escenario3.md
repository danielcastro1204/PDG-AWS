# Escenario 3 — Eventos mixtos (trafico normal + ataques)

- Total de ataques ejecutados: **7**
- Ataques detectados (Verdaderos Positivos): **7**
- Ataques no detectados (Falsos Negativos): **0**
- **Tasa de deteccion / Recall: 100.0%** (criterio de exito del proyecto: >= 80%)
- Tiempo medio de deteccion (MTTD): **0.0 s** (desde el inicio del ataque hasta la primera alerta correlacionada)
- Alertas de grupo 'attack' dentro de la ventana de prueba: **552** (verdaderas: 552, falsos positivos: **0**)
- **Precision (alertas 'attack' correctas / total alertas 'attack'): 100.0%**
- **F1-score: 100.0%**

## Desglose por tipo de ataque

| ataque            |   intentos |   detectados |   tasa_deteccion_% |
|:------------------|-----------:|-------------:|-------------------:|
| pass_the_hash     |          1 |            1 |                100 |
| payload_execution |          1 |            1 |                100 |
| portscan          |          3 |            3 |                100 |
| sql_injection     |          2 |            2 |                100 |

## Detalle por intento de ataque

| ataque            | mitre_id   | objetivo   | inicio               | detectado   |   ttd_seg | reglas_disparadas                                          |
|:------------------|:-----------|:-----------|:---------------------|:------------|----------:|:-----------------------------------------------------------|
| portscan          | T1046      | 10.0.10.20 | 2026-10-21T15:53:40Z | Si          |     -24.2 | 5501,5502,5715,60106,60107,60137,67027,67028,86601         |
| payload_execution | T1059.001  | 10.0.20.30 | 2026-10-21T16:02:55Z | Si          |     -19.5 | 100030,100099,5501,5502,5715,60106,60107,60137,67027,67028 |
| sql_injection     | T1190      | 10.0.10.10 | 2026-10-21T16:06:49Z | Si          |     -25.9 | 100040,100099,31106,31171,5501,5502,5715,60106,60137       |
| pass_the_hash     | T1550.002  | 10.0.10.20 | 2026-10-21T16:10:32Z | Si          |     -24.8 | 100030,5501,5502,5715,60106,60107,60137,67028,86601,92650  |
| portscan          | T1046      | 10.0.10.20 | 2026-10-21T16:13:58Z | Si          |     -16.1 | 5501,5502,5715,60106,60107,60137,86601                     |
| sql_injection     | T1190      | 10.0.10.10 | 2026-10-21T16:23:48Z | Si          |     -16.1 | 100040,100099,31106,31171,5501,5502,5715,60106,60107,60137 |
| portscan          | T1046      | 10.0.10.20 | 2026-10-21T16:26:03Z | Si          |     -17.1 | 5501,5502,5715,60104,60106,60107,60137,67028,86601         |

## Matriz de correlacion (tipo de ataque -> reglas Wazuh disparadas)

| ataque            | reglas_disparadas                                                   |
|:------------------|:--------------------------------------------------------------------|
| pass_the_hash     | 100030, 5501, 5502, 5715, 60106, 60107, 60137, 67028, 86601, 92650  |
| payload_execution | 100030, 100099, 5501, 5502, 5715, 60106, 60107, 60137, 67027, 67028 |
| portscan          | 5501, 5502, 5715, 60104, 60106, 60107, 60137, 67027, 67028, 86601   |
| sql_injection     | 100040, 100099, 31106, 31171, 5501, 5502, 5715, 60106, 60107, 60137 |
