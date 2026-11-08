# Escenario 3 — Eventos mixtos (trafico realista + ataques)

- Total de ataques ejecutados: **13**
- **Tasa de deteccion ESTRICTA (regla pertinente a la tecnica): 100.0%** (13/13) — metrica rigurosa, criterio del proyecto: >= 80%
- Tasa de deteccion amplia (cualquier alerta correlacionada): 100.0% (13/13)
- Falsos negativos (ataques no detectados, criterio estricto): **0**
- Tiempo medio de deteccion (MTTD estricto): -5.4 s (ver limitaciones: ventanas solapadas)
- Alertas accionables en la ventana: **1187** (correctas: 1153, falsas alarmas accionables: **34**)
- Precision (alertas accionables correctas): 97.1%
- F1-score: 98.5%

## Desglose por tipo de ataque (deteccion amplia vs estricta)

| ataque            |   intentos |   det_amplia |   det_estricta |   %_amplia |   %_estricta |
|:------------------|-----------:|-------------:|---------------:|-----------:|-------------:|
| bruteforce_ssh    |          3 |            3 |              3 |        100 |          100 |
| pass_the_hash     |          5 |            5 |              5 |        100 |          100 |
| payload_execution |          1 |            1 |              1 |        100 |          100 |
| sql_injection     |          4 |            4 |              4 |        100 |          100 |

## Detalle por intento de ataque

| ataque            | mitre_id   | objetivo   | inicio               | det_amplia   | det_estricta   | reglas_pertinentes       | reglas_disparadas                                                            |
|:------------------|:-----------|:-----------|:---------------------|:-------------|:---------------|:-------------------------|:-----------------------------------------------------------------------------|
| bruteforce_ssh    | T1110.001  | 10.0.20.40 | 2026-10-22T18:52:09Z | Si           | Si             | 5503,5760                | 100099,5501,5502,5503,5715,5760,60106,60137,67027,67028                      |
| pass_the_hash     | T1550.002  | 10.0.10.20 | 2026-10-22T18:53:28Z | Si           | Si             | 67027,92650              | 100099,5501,5502,60106,60107,60137,67027,67028,92650                         |
| pass_the_hash     | T1550.002  | 10.0.10.20 | 2026-10-22T18:56:30Z | Si           | Si             | 67027,92650              | 100099,5501,5502,5715,60106,60107,60137,67027,67028,92650                    |
| sql_injection     | T1190      | 10.0.10.10 | 2026-10-22T18:58:15Z | Si           | Si             | 100040,31106,31171       | 100040,100099,31106,31171,5501,5502,5715,60106,60137,67027,67028             |
| pass_the_hash     | T1550.002  | 10.0.10.20 | 2026-10-22T19:01:58Z | Si           | Si             | 100030,67027,86601,92650 | 100030,100099,5501,5502,5715,60106,60137,67027,67028,86601,92650             |
| sql_injection     | T1190      | 10.0.10.10 | 2026-10-22T19:05:38Z | Si           | Si             | 100040,31106,31171       | 100040,100099,31106,31171,5501,5502,5715,60106,60107,60137,67027,67028       |
| pass_the_hash     | T1550.002  | 10.0.10.20 | 2026-10-22T19:09:41Z | Si           | Si             | 67027,86601,92650        | 100099,5501,5502,5715,60106,60107,60137,67027,67028,86601,92650              |
| bruteforce_ssh    | T1110.001  | 10.0.20.40 | 2026-10-22T19:14:21Z | Si           | Si             | 5503,5760                | 100099,5501,5502,5503,5715,5760,60106,60107,60137,67027,67028                |
| sql_injection     | T1190      | 10.0.10.10 | 2026-10-22T19:17:23Z | Si           | Si             | 100040,31106,31171       | 100040,100099,31106,31171,5501,5502,5715,60106,60137,67027,67028             |
| bruteforce_ssh    | T1110.001  | 10.0.20.40 | 2026-10-22T19:20:02Z | Si           | Si             | 5503,5760                | 100099,5501,5502,5503,5715,5760,591,60106,60107,60137,67027,67028            |
| pass_the_hash     | T1550.002  | 10.0.10.20 | 2026-10-22T19:22:24Z | Si           | Si             | 67027,86601,92650        | 100099,5501,5502,5715,60106,60107,60137,67027,67028,86601,92650              |
| payload_execution | T1059.001  | 10.0.20.30 | 2026-10-22T19:23:54Z | Si           | Si             | 100030,67027             | 100030,100099,5501,5502,5715,60106,60107,60137,67027,67028                   |
| sql_injection     | T1190      | 10.0.10.10 | 2026-10-22T19:27:41Z | Si           | Si             | 100040,31106,31171,86601 | 100040,100099,31106,31171,5501,5502,5715,60106,60107,60137,67027,67028,86601 |

## Matriz de correlacion (tecnica -> reglas Wazuh PERTINENTES disparadas)

| ataque            | reglas_pertinentes          |
|:------------------|:----------------------------|
| bruteforce_ssh    | 5503, 5760                  |
| pass_the_hash     | 100030, 67027, 86601, 92650 |
| payload_execution | 100030, 67027               |
| sql_injection     | 100040, 31106, 31171, 86601 |
