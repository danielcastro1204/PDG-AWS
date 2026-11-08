# Reporte Escenario 1 — Linea base de trafico normal

- Ventana analizada: **2026-10-22T17:03:10Z** a **2026-10-22T17:36:28Z** (33 min)
- Total de alertas generadas: **877** (todas se consideran **falsos positivos**, al no existir actividad maliciosa)
- Tasa de falsos positivos: **1580.2 alertas/hora**
- De esas, con el grupo 'attack' (las mismas reglas que detectan ataques reales): **6**

## Alertas por nivel de severidad

| Nivel | Cantidad |
|---|---|
| 12 | 6 |
| 14 | 93 |
| 3 | 731 |
| 4 | 43 |
| 5 | 4 |

## Top reglas disparadas (posibles ajustes de tuning recomendados)

| Regla ID | Descripcion | Cantidad |
|---|---|---|
| 60137 | Windows User Logoff | 212 |
| 5501 | PAM: Login session opened. | 122 |
| 5502 | PAM: Login session closed. | 116 |
| 100099 | Multiples familias de ataque detectadas en ventana de 10 min (correlacion escenario mixto) | 93 |
| 60106 | Windows Logon Success | 83 |
| 67027 | A process was created. | 67 |
| 67028 | Special privileges assigned to new logon. | 62 |
| 60107 | Failed attempt to perform a privileged operation | 42 |
| 5715 | sshd: authentication success. | 37 |
| 86601 | Suricata: Alert - ET INFO NTLM Session Setup Request - Auth | 27 |
| 100030 | Posible autenticacion Pass-the-Hash: logon tipo 3 con NTLM (T1550.002) | 6 |
| 5402 | Successful sudo to ROOT executed. | 4 |
| 60104 | Windows audit failure event | 4 |
| 5403 | First time user executed sudo. | 1 |
| 591 | Log file rotated. | 1 |
