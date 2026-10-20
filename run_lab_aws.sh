#!/usr/bin/env bash
# =============================================================================
# run_lab_aws.sh — Menú de operación del laboratorio (Fases 3 y 4) sobre AWS.
# Pensado para ejecutarse EN la estación atacante (10.0.30.20) como usuario
# 'attacker'. Orquesta los mismos escenarios y evaluación del proyecto físico,
# pero con el direccionamiento de AWS (ver ~/lab.env).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
[ -f "$HOME/lab.env" ] && source "$HOME/lab.env"

: "${SIEM_IP:=10.0.30.10}"
: "${DC_IP:=10.0.10.20}"
: "${WEB_URL:=http://10.0.10.10/index.php?id=1}"
: "${WIN_WS_IP:=10.0.20.30}"
: "${SSH_TARGET:=10.0.20.40}"
: "${SSH_USER:=usuario}"
ATAQUES_DIR="${HOME}/ataques";     [ -d "$ATAQUES_DIR" ] || ATAQUES_DIR="./ataques"
ESC_DIR="${HOME}/escenarios";      [ -d "$ESC_DIR" ] || ESC_DIR="./escenarios"
EVAL_DIR="${HOME}/evaluacion";     [ -d "$EVAL_DIR" ] || EVAL_DIR="./evaluacion"

menu() {
cat <<MENU
=====================================================================
  LABORATORIO SIEM (AWS) — OPERACIÓN (Fases 3 y 4)
  SIEM=${SIEM_IP}  DC=${DC_IP}  WEB=${WEB_URL}  WIN=${WIN_WS_IP}  SSH=${SSH_TARGET}
=====================================================================
  FASE 3 — Escenarios:
   1) Escenario 1: línea base de tráfico normal (min)
   2) Escenario 2: 5 ataques controlados x5 repeticiones (run_all_attacks.sh)
   3) Escenario 3: tráfico mixto (min)
   4) Ejecutar un ataque individual (1..5)

  FASE 4 — Evaluación:
   5) Traer alerts.json del SIEM por SSH y calcular métricas
   0) Salir
=====================================================================
MENU
}

while true; do
  menu; read -rp "Opción: " o
  case "$o" in
    1) read -rp "Duración (min) [30]: " M; M=${M:-30}; bash "$ESC_DIR/escenario1_linea_base.sh" "$M" ;;
    2) ( cd "$ATAQUES_DIR" && DC_IP="$DC_IP" WEB_URL="$WEB_URL" WIN_WS_IP="$WIN_WS_IP" SSH_TARGET="$SSH_TARGET" SSH_USER="$SSH_USER" ./run_all_attacks.sh ) ;;
    3) read -rp "Duración (min) [60]: " M; M=${M:-60}; bash "$ESC_DIR/escenario3_mixto.sh" "$M" ;;
    4) read -rp "¿Qué ataque? (1=bruteforce 2=portscan 3=pth 4=sqli 5=payload): " A
       case "$A" in
         1) "$ATAQUES_DIR/attack1_bruteforce_ssh.sh" "$SSH_TARGET" "$SSH_USER" ;;
         2) "$ATAQUES_DIR/attack2_portscan.sh" "$DC_IP" ;;
         3) read -rp "Hash NTLM: " H; "$ATAQUES_DIR/attack3_pass_the_hash.sh" "$DC_IP" Administrator "$H" ;;
         4) "$ATAQUES_DIR/attack4_sqli.sh" "$WEB_URL" ;;
         5) "$ATAQUES_DIR/attack5_payload_exec.sh" "$WIN_WS_IP" ;;
         *) echo "Ataque inválido" ;;
       esac ;;
    5) read -rp "Inicio (ISO8601 UTC, ej 2026-06-01T14:00:00Z): " I
       read -rp "Fin    (ISO8601 UTC): " F
       read -rp "Ruta de la key SSH del SIEM [~/.ssh/id_rsa]: " K; K=${K:-~/.ssh/id_rsa}
       echo ">> Copiando alerts.json desde el SIEM (${SIEM_IP})..."
       scp -o StrictHostKeyChecking=no -i "$K" "ubuntu@${SIEM_IP}:/var/ossec/logs/alerts/alerts.json" /tmp/alerts.json \
         || { echo "Usa 'sudo' remoto si falla permiso. Alternativa: copia manual."; }
       python3 "$EVAL_DIR/recolectar_alertas.py" --alerts-file /tmp/alerts.json --inicio "$I" --fin "$F" --out /tmp/alertas_ventana.json
       pip3 install -r "$EVAL_DIR/requirements.txt" --break-system-packages 2>/dev/null || pip3 install -r "$EVAL_DIR/requirements.txt" 2>/dev/null || true
       python3 "$EVAL_DIR/calcular_metricas.py" --ataques "$ATAQUES_DIR/log_ataques.csv" --alertas /tmp/alertas_ventana.json --out /tmp/reporte_metricas.md
       echo ">> Reporte en /tmp/reporte_metricas.md"; cat /tmp/reporte_metricas.md ;;
    0) exit 0 ;;
    *) echo "Opción inválida" ;;
  esac
  echo ""
done
