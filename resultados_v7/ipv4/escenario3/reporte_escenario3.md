# E3 mixto IPv4 - ataques bajo carga (tuning)

- Total de ataques ejecutados: **4**
- **Tasa de deteccion ESTRICTA (regla pertinente a la tecnica): 100.0%** (4/4) — metrica rigurosa, criterio del proyecto: >= 80%
- Tasa de deteccion amplia (cualquier alerta correlacionada): 100.0% (4/4)
- Falsos negativos (ataques no detectados, criterio estricto): **0**
- Tiempo medio de deteccion (MTTD estricto): 71.0 s (ver limitaciones: ventanas solapadas)
- Alertas accionables en la ventana: **852** (correctas: 841, falsas alarmas accionables: **11**)
- Precision (alertas accionables correctas): 98.7%
- F1-score: 99.4%

## Desglose por tipo de ataque (deteccion amplia vs estricta)

| ataque        |   intentos |   det_amplia |   det_estricta |   %_amplia |   %_estricta |
|:--------------|-----------:|-------------:|---------------:|-----------:|-------------:|
| pass_the_hash |          1 |            1 |              1 |        100 |          100 |
| portscan      |          1 |            1 |              1 |        100 |          100 |
| sql_injection |          2 |            2 |              2 |        100 |          100 |

## Detalle por intento de ataque

| ataque        | mitre_id   | objetivo   | inicio               | det_amplia   | det_estricta   | reglas_pertinentes                             | reglas_disparadas                                                                                  |
|:--------------|:-----------|:-----------|:---------------------|:-------------|:---------------|:-----------------------------------------------|:---------------------------------------------------------------------------------------------------|
| sql_injection | T1190      | 10.0.10.10 | 2026-11-16T00:05:34Z | Si           | Si             | 100040,100041,100044,100045,100046,31171,86601 | 100040,100041,100044,100045,100046,100099,31171,5501,5502,5715,60104,60106,60107,60137,61109,86601 |
| pass_the_hash | T1550.002  | 10.0.10.20 | 2026-11-16T00:09:26Z | Si           | Si             | 92650                                          | 100030,5501,5502,5715,60104,60106,60107,60137,61109,67028,86601,92650                              |
| sql_injection | T1190      | 10.0.10.10 | 2026-11-16T00:13:12Z | Si           | Si             | 100040,100041,100044,100045,100046,31171       | 100040,100041,100044,100045,100046,100099,31171,5501,5502,5715,60104,60106,60107,60137,61109       |
| portscan      | T1046      | 10.0.10.20 | 2026-11-16T00:18:10Z | Si           | Si             | 100004,100023,86601                            | 100004,100023,5501,5502,5715,60104,60106,60107,60137,61109,86601                                   |

## Matriz de correlacion (tecnica -> reglas Wazuh PERTINENTES disparadas)

| ataque        | reglas_pertinentes                                   |
|:--------------|:-----------------------------------------------------|
| pass_the_hash | 92650                                                |
| portscan      | 100004, 100023, 86601                                |
| sql_injection | 100040, 100041, 100044, 100045, 100046, 31171, 86601 |
