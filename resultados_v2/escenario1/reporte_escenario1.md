# Reporte Escenario 1 — Linea base de trafico normal

- Ventana analizada: **2026-10-21T14:07:14Z** a **2026-10-21T14:40:27Z** (33 min)
- Total de alertas generadas: **753** (todas se consideran **falsos positivos**, al no existir actividad maliciosa)
- Tasa de falsos positivos: **1360.2 alertas/hora**
- De esas, con el grupo 'attack' (las mismas reglas que detectan ataques reales): **0**

## Alertas por nivel de severidad

| Nivel | Cantidad |
|---|---|
| 3 | 712 |
| 4 | 37 |
| 5 | 4 |

## Top reglas disparadas (posibles ajustes de tuning recomendados)

| Regla ID | Descripcion | Cantidad |
|---|---|---|
| 5501 | PAM: Login session opened. | 262 |
| 5502 | PAM: Login session closed. | 183 |
| 5715 | sshd: authentication success. | 88 |
| 60137 | Windows User Logoff | 84 |
| 60106 | Windows Logon Success | 73 |
| 60107 | Failed attempt to perform a privileged operation | 36 |
| 86601 | Suricata: Alert - ET INFO NTLM Session Setup Request - Negotiate | 18 |
| 60104 | Windows audit failure event | 4 |
| 5402 | Successful sudo to ROOT executed. | 2 |
| 60228 | A scheduled task was created | 1 |
| 67028 | Special privileges assigned to new logon. | 1 |
| 67027 | A process was created. | 1 |
