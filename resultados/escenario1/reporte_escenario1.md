# Reporte Escenario 1 — Linea base de trafico normal

- Ventana analizada: **2026-10-21T02:59:15Z** a **2026-10-21T03:30:00Z** (31 min)
- Total de alertas generadas: **783** (todas se consideran **falsos positivos**, al no existir actividad maliciosa)
- Tasa de falsos positivos: **1527.8 alertas/hora**
- De esas, con el grupo 'attack' (las mismas reglas que detectan ataques reales): **0**

## Alertas por nivel de severidad

| Nivel | Cantidad |
|---|---|
| 3 | 734 |
| 4 | 45 |
| 5 | 4 |

## Top reglas disparadas (posibles ajustes de tuning recomendados)

| Regla ID | Descripcion | Cantidad |
|---|---|---|
| 5501 | PAM: Login session opened. | 270 |
| 5502 | PAM: Login session closed. | 192 |
| 5715 | sshd: authentication success. | 90 |
| 60137 | Windows User Logoff | 81 |
| 60106 | Windows Logon Success | 68 |
| 60107 | Failed attempt to perform a privileged operation | 45 |
| 86601 | Suricata: Alert - ET INFO NTLM Session Setup Request - Auth | 18 |
| 67027 | A process was created. | 10 |
| 60104 | Windows audit failure event | 4 |
| 5402 | Successful sudo to ROOT executed. | 2 |
| 591 | Log file rotated. | 1 |
| 67028 | Special privileges assigned to new logon. | 1 |
| 60108 | Session reconnected/disconnected to winstation | 1 |
