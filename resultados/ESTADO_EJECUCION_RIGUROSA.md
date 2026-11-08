# Estado de la ejecución rigurosa (3 escenarios) — para continuar

**Última actualización:** 20-21 de octubre de 2026, ~23:20 (hora local, UTC-5)
**Stack:** `siem-lab` sigue desplegado y corriendo en AWS Academy (cuenta 145326036987, us-east-1). Todas las 9 instancias `running`.

## Resumen de progreso

| Escenario | Estado | Notas |
|---|---|---|
| **1. Línea base** | ✅ **Completo** | 30 min, 783 alertas (0 de grupo 'attack'). Resultados en `resultados/escenario1/` |
| **2. Ataques controlados** | ⚠️ **Parcial** | 4/5 técnicas con 5 repeticiones limpias. El ataque 5 (payload/WinRM) falló en TODOS los intentos (ver bug abajo) |
| **3. Mixto** | ❌ **No iniciado** | Pendiente — esperando resolver el bug de WinRM primero, ya que `escenario3_mixto.sh` también dispara el ataque 5 |

## Lo que quedó correcto y usable de Escenario 2

En `log_ataques.csv` del atacante (snapshot guardado en `resultados/escenario2/log_ataques_e2_snapshot_*.csv`), **20 filas limpias** (5 repeticiones x 4 técnicas), todas ejecutadas correctamente:
- `bruteforce_ssh` (T1110.001) x5
- `portscan` (T1046) x5
- `sql_injection` (T1190) x5
- `pass_the_hash` (T1550.002) x5

Ventana: `2026-10-21T03:32:51Z` (inicio, en `/tmp/ventana_e2_ini.txt` de la sesión) hasta `2026-10-21T04:01:43Z` aprox. (antes de empezar los reintentos fallidos del ataque 5).

**Pendiente:** recolectar alertas y correr `calcular_metricas.py --escenario 2` sobre estas 20 filas (más las 5 de `payload_execution` una vez se resuelva el bug, o excluyéndolas documentando el motivo si no se resuelve).

## Bug real encontrado: WinRM intermitente en Win-WS-01 (ataque 5)

**Síntoma:** `evil-winrm` contra `10.0.20.30:5985` con las credenciales correctas (`EMPRESA\Administrator` / `P@ssw0rd`, verificadas funcionando) da:
```
Error: Cannot establish connection to remote endpoint. Check credentials and network.
Error: WinRM::WinRMAuthorizationError: WinRM::WinRMAuthorizationError
```

**Lo que se probó:**
- El puerto 5985 SÍ responde (`nc -zv` exitoso).
- Falla con `Administrator` Y con `user1` (otra cuenta de dominio) → no es un problema de la cuenta específica.
- Un intento **aislado** manual tuvo éxito una vez (`Connection successful`, `whoami` devolvió `empresa\administrator`), pero **inmediatamente después**, 10 intentos más (5 seguidos, luego 5 espaciados 45s) fallaron todos de la misma forma.
- El puerto SMB (445) hacia la estación **también** empezó a dar timeout (igual que al principio del día, antes de que arreglaras esto por RDP) — sugiere que el firewall/perfil de red de Windows se revirtió a un estado más restrictivo en algún momento (posible: Windows re-evalúa el "Network Location Awareness" y categoriza la red como "Public" en vez de "Domain", lo que activa reglas de firewall más estrictas incluso si el servicio WinRM sigue "escuchando" en el puerto).
- No se pudo reiniciar el servicio WinRM remotamente vía `impacket-psexec` porque SMB (445) también está bloqueado ahora mismo.

**Próximo paso (mañana):** entrar por RDP a `3.81.173.1` (Win-WS-01) y revisar:
```powershell
Get-NetConnectionProfile          # ¿la red aparece como "DomainAuthenticated" o "Public"?
Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction
Restart-Service WinRM -Force
winrm enumerate winrm/config/listener
Get-EventLog -LogName Security -Newest 20 | Where-Object {$_.EventID -in 4625,4672,4776}   # logons fallidos recientes
```
Si el perfil de red aparece como "Public", forzarlo a "Private" o "DomainAuthenticated" con:
```powershell
Set-NetConnectionProfile -InterfaceAlias (Get-NetAdapter | Where Status -eq Up).Name -NetworkCategory Private
```

## Cosas a verificar al retomar mañana

1. **Credenciales de AWS Academy habrán expirado de nuevo** (son temporales, duran unas horas). Hay que: iniciar el lab ("Start Lab" si aparece detenido), copiar AWS Details → AWS CLI, y pegar el bloque `[default]` nuevo.
2. **La IP pública del usuario puede haber cambiado** (pasó varias veces hoy). Verificar con `curl ifconfig.me` y comparar contra el `AdminIngressCidr` del stack; si no coincide, actualizar con `aws cloudformation update-stack` (ver comandos usados hoy en el historial).
3. **El lab de AWS Academy tiene un presupuesto de horas/sesión.** Si al volver las instancias ya no están `running` (se detuvieron solas), hay que iniciar el lab de nuevo; como las instancias EC2 normales (no Spot) no se destruyen automáticamente al pausar el lab salvo que termine la sesión completa, probablemente solo haga falta "Start Lab" y esperar a que vuelvan a estar accesibles (las IPs públicas pueden cambiar si se reinician).

## Pendientes para terminar (en orden)

1. Diagnosticar y arreglar WinRM en Win-WS-01 (ver arriba).
2. Completar las 5 repeticiones válidas del ataque 5 (payload) para Escenario 2.
3. Recolectar alertas y calcular métricas de Escenario 2 (`calcular_metricas.py --ataques log_ataques.csv --escenario 2 --alertas ... --titulo "Escenario 2 — Ataques controlados"`).
4. Ejecutar Escenario 3 (`escenarios/escenario3_mixto.sh 40`, ya corregido para disparar los ataques de verdad) desde el atacante, con `source ~/lab.env` primero.
5. Recolectar alertas de la ventana de Escenario 3 y calcular métricas con `--escenario 3`.
6. Escribir el reporte consolidado final de los 3 escenarios (`resultados/REPORTE_FINAL_3_ESCENARIOS.md`), citando también `escenario1/reporte_escenario1.md`.
7. (Opcional pero recomendado) Repetir Escenario 2 con el bug de WinRM ya resuelto, para tener un dataset 100% limpio sin reintentos manuales mezclados — documentar si se reutilizan los datos actuales o se corre todo de nuevo.
8. Cuando todo esté terminado y documentado: preguntar si se apaga el laboratorio (`./teardown.sh -y`) para no seguir gastando presupuesto del sandbox.

## Archivos ya generados hoy

- `resultados/escenario1/reporte_escenario1.md` — análisis de falsos positivos (línea base)
- `resultados/escenario1/alertas_ventana.json`, `alerts_full_e1.json`
- `resultados/escenario2/log_ataques_e2_snapshot_*.csv` — snapshot con las 20 filas limpias + 15 filas de payload fallido
- (De la corrida anterior, no tocar): `reporte_metricas.md`, `NOTAS_EJECUCION.md`, `log_ataques.csv`, `alerts.json`, `alertas_ventana.json` — primera corrida (menos rigurosa metodológicamente, sin separación de escenarios)

## Todos los bugs corregidos hoy (ya en el repo [PDG-AWS](https://github.com/danielcastro1204/PDG-AWS))

Ver `resultados/NOTAS_EJECUCION.md` para los primeros 11, más estos nuevos de la sesión de rigor metodológico:

12. `escenario3_mixto.sh` **nunca ejecutaba los ataques de verdad** (solo imprimía el nombre) — reescrito completo.
13. `run_all_attacks.sh` solo automatizaba 3 de 5 ataques — ahora automatiza los 5, capturando el hash NTLM una sola vez y reutilizándolo.
14. No existía servidor SMB en la migración (solo cliente) — se agregó Samba + cuenta de login en `web-server.sh`.
15. `escenario1_linea_base.sh` tenía IPs de la red física (192.168.x.x) y el login SSH nunca funcionaba (faltaba `sshpass`) — corregido.
16. `_lib_log_ataque.sh` ahora registra a qué escenario pertenece cada fila.
17. `calcular_metricas.py` ampliado con precisión, F1, MTTD y desglose por tipo de ataque; nuevo `analizar_linea_base.py` para el Escenario 1.
18. **(Sin resolver aún)** Bug/comportamiento intermitente de WinRM en Win-WS-01 — ver sección de arriba.
