#!/usr/bin/env bash
# =============================================================================
# run_all_aws.sh — Orquestador END-TO-END del laboratorio SIEM en AWS.
#
# Un solo comando que, desde TU máquina (o AWS CloudShell), hace todo:
#   1. Despliega la infraestructura (llama a deploy.sh).
#   2. Espera a que el laboratorio esté REALMENTE listo (SIEM arriba + los
#      agentes Wazuh "Active" — eso confirma que DC, web, estaciones, etc.
#      terminaron su aprovisionamiento y sus reinicios).
#   3. Ejecuta los escenarios en la estación atacante (línea base + ataques
#      automatizables de la Fase 3, reutilizando run_all_attacks.sh).
#   4. Espera a que las alertas propaguen al SIEM.
#   5. Descarga alerts.json (del SIEM) y log_ataques.csv (del atacante) y
#      calcula las métricas (tasa de detección, falsos positivos, matriz).
#   6. Te deja el reporte en ./resultados/reporte_metricas.md y lo imprime.
#
# Requisitos: AWS CLI configurada (credenciales del lab), la clave .pem del
# key pair usado, python3 local, y ejecutarlo DESDE la carpeta AWS/.
#
# Uso:
#   ./run_all_aws.sh -i ~/Downloads/labsuser.pem -c TU_IP/32 [-p completa|minima]
#        [-k vockey] [--skip-deploy] [--baseline-min 10] [--espera-alertas 5]
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"; SCRIPT_DIR="$(pwd)"

KEYNAME="vockey"; KEYFILE=""; ADMIN_CIDR="0.0.0.0/0"; PERFIL="completa"
REGION="us-east-1"; STACK="siem-lab"
SKIP_DEPLOY="no"; BASELINE_MIN="10"; ESPERA_ALERTAS="5"
SSH_USER="ubuntu"; SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

while [ $# -gt 0 ]; do
  case "$1" in
    -k) KEYNAME="$2"; shift 2 ;;
    -i) KEYFILE="$2"; shift 2 ;;
    -c) ADMIN_CIDR="$2"; shift 2 ;;
    -p) PERFIL="$2"; shift 2 ;;
    -r) REGION="$2"; shift 2 ;;
    -s) STACK="$2"; shift 2 ;;
    --skip-deploy) SKIP_DEPLOY="si"; shift ;;
    --baseline-min) BASELINE_MIN="$2"; shift 2 ;;
    --espera-alertas) ESPERA_ALERTAS="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Argumento desconocido: $1"; exit 1 ;;
  esac
done

command -v aws >/dev/null || { echo "ERROR: falta AWS CLI."; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: falta python3."; exit 1; }
[ -n "$KEYNAME" ] || { echo "ERROR: falta -k NOMBRE_KEYPAIR."; exit 1; }
[ -n "$KEYFILE" ] && [ -f "$KEYFILE" ] || { echo "ERROR: falta -i RUTA_.pem válida."; exit 1; }
chmod 400 "$KEYFILE" 2>/dev/null || true
SSH="ssh $SSH_OPTS -i $KEYFILE"
SCP="scp $SSH_OPTS -i $KEYFILE"

banner(){ echo ""; echo "============================================================"; echo " $*"; echo "============================================================"; }
ip_por_tag(){ aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=$1" "Name=instance-state-name,Values=running,pending" \
  --query "Reservations[].Instances[].PublicIpAddress" --output text 2>/dev/null | tr -d '\n'; }

# ---------------------------------------------------------------------------
# FASE 1 — Desplegar
# ---------------------------------------------------------------------------
if [ "$SKIP_DEPLOY" = "no" ]; then
  banner "FASE 1/6 — Desplegando infraestructura (CloudFormation)"
  ./deploy.sh -k "$KEYNAME" -p "$PERFIL" -c "$ADMIN_CIDR" -r "$REGION" -s "$STACK"
else
  banner "FASE 1/6 — (omitida: --skip-deploy)"
fi

echo ">> Esperando a que las instancias tengan IP pública..."
for _ in $(seq 1 30); do
  SIEM_IP="$(ip_por_tag 'SIEM-Wazuh (VLAN30)')"
  ATK_IP="$(ip_por_tag 'Atacante (VLAN30 - sustituto Kali)')"
  [ -n "$SIEM_IP" ] && [ -n "$ATK_IP" ] && break
  sleep 10
done
[ -n "$SIEM_IP" ] && [ -n "$ATK_IP" ] || { echo "ERROR: no obtuve IPs públicas (SIEM/atacante)."; exit 1; }
echo "   SIEM=$SIEM_IP   Atacante=$ATK_IP"

# ---------------------------------------------------------------------------
# FASE 2 — Esperar a que el laboratorio esté listo (agentes Active)
# ---------------------------------------------------------------------------
banner "FASE 2/6 — Esperando aprovisionamiento (puede tardar 25-40 min)"

# 2a. Esperar a que el Wazuh Manager esté activo
echo ">> Esperando al Wazuh Manager en $SIEM_IP ..."
for _ in $(seq 1 120); do   # hasta ~40 min
  if $SSH ${SSH_USER}@${SIEM_IP} 'systemctl is-active --quiet wazuh-manager' 2>/dev/null; then
    echo "   Wazuh Manager ACTIVO."; break
  fi
  printf '.'; sleep 20
done

# 2b. Esperar a que un conjunto mínimo de agentes esté Active
#     (confirma que DC, web, estación Windows y Linux terminaron)
case "$PERFIL" in
  minima)   MIN_AGENTES=4 ;;   # dc, web, linux-01, win-ws-01 (+fw)
  *)        MIN_AGENTES=5 ;;
esac
echo ">> Esperando a que >= ${MIN_AGENTES} agentes estén 'Active'..."
for _ in $(seq 1 120); do
  ACTIVE="$($SSH ${SSH_USER}@${SIEM_IP} "sudo /var/ossec/bin/agent_control -l 2>/dev/null | grep -c Active" 2>/dev/null || echo 0)"
  ACTIVE="${ACTIVE//[^0-9]/}"; ACTIVE="${ACTIVE:-0}"
  echo "   Agentes Active: ${ACTIVE}/${MIN_AGENTES}"
  [ "$ACTIVE" -ge "$MIN_AGENTES" ] && break
  sleep 20
done
$SSH ${SSH_USER}@${SIEM_IP} 'sudo /var/ossec/bin/agent_control -l' 2>/dev/null || true

# ---------------------------------------------------------------------------
# FASE 3 — Escenario 1 (línea base) + Escenario 2 (ataques) en el atacante
# ---------------------------------------------------------------------------
banner "FASE 3/6 — Ejecutando escenarios en la estación atacante"
VENTANA_INI="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ">> Inicio de ventana de prueba (UTC): $VENTANA_INI"

echo ">> Escenario 1 (línea base) durante ${BASELINE_MIN} min..."
$SSH ${SSH_USER}@${ATK_IP} "sudo -u attacker bash -lc 'source ~/lab.env; cd ~/escenarios && ./escenario1_linea_base.sh ${BASELINE_MIN}'" 2>/dev/null || \
  echo "   (línea base terminó con avisos; continúo)"

echo ">> Escenario 2 (ataques automatizables: fuerza bruta SSH, escaneo, SQLi)..."
$SSH ${SSH_USER}@${ATK_IP} "sudo -u attacker bash -lc 'source ~/lab.env; cd ~/ataques && ./run_all_attacks.sh'" 2>/dev/null || \
  echo "   (los ataques terminaron con avisos; continúo)"

VENTANA_FIN="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ">> Fin de ventana de prueba (UTC): $VENTANA_FIN"
echo ""
echo "   NOTA: los casos Pass-the-Hash y ejecución de payload requieren un hash/"
echo "   credenciales capturados en el ejercicio y se lanzan aparte (ver"
echo "   run_lab_aws.sh, opción 4). Esta corrida automática cubre los demás."

# ---------------------------------------------------------------------------
# FASE 4 — Esperar propagación de alertas
# ---------------------------------------------------------------------------
banner "FASE 4/6 — Esperando propagación de alertas (${ESPERA_ALERTAS} min)"
sleep $(( ESPERA_ALERTAS * 60 ))

# ---------------------------------------------------------------------------
# FASE 5 — Recolectar datos (alerts.json del SIEM, log_ataques.csv del atacante)
# ---------------------------------------------------------------------------
banner "FASE 5/6 — Recolectando datos"
mkdir -p "${SCRIPT_DIR}/resultados"
echo ">> Copiando alerts.json del SIEM..."
$SSH ${SSH_USER}@${SIEM_IP} 'sudo cp /var/ossec/logs/alerts/alerts.json /tmp/alerts.json && sudo chmod 644 /tmp/alerts.json' 2>/dev/null || true
$SCP ${SSH_USER}@${SIEM_IP}:/tmp/alerts.json "${SCRIPT_DIR}/resultados/alerts.json" 2>/dev/null || echo "   (no se pudo copiar alerts.json)"
echo ">> Copiando log_ataques.csv del atacante..."
$SSH ${SSH_USER}@${ATK_IP} 'sudo cp /home/attacker/log_ataques.csv /tmp/log_ataques.csv && sudo chmod 644 /tmp/log_ataques.csv' 2>/dev/null || true
$SCP ${SSH_USER}@${ATK_IP}:/tmp/log_ataques.csv "${SCRIPT_DIR}/resultados/log_ataques.csv" 2>/dev/null || echo "   (no se pudo copiar log_ataques.csv)"

# ---------------------------------------------------------------------------
# FASE 6 — Evaluar y entregar
# ---------------------------------------------------------------------------
banner "FASE 6/6 — Calculando métricas (tasa de detección, falsos positivos)"
python3 -m pip install -q -r evaluacion/requirements.txt --break-system-packages 2>/dev/null || \
  python3 -m pip install -q -r evaluacion/requirements.txt 2>/dev/null || true

if [ -s "${SCRIPT_DIR}/resultados/alerts.json" ] && [ -s "${SCRIPT_DIR}/resultados/log_ataques.csv" ]; then
  python3 evaluacion/recolectar_alertas.py \
    --alerts-file "${SCRIPT_DIR}/resultados/alerts.json" \
    --inicio "$VENTANA_INI" --fin "$VENTANA_FIN" \
    --out "${SCRIPT_DIR}/resultados/alertas_ventana.json"
  python3 evaluacion/calcular_metricas.py \
    --ataques "${SCRIPT_DIR}/resultados/log_ataques.csv" \
    --alertas "${SCRIPT_DIR}/resultados/alertas_ventana.json" \
    --out "${SCRIPT_DIR}/resultados/reporte_metricas.md"
  echo ""; echo "################ REPORTE ################"
  cat "${SCRIPT_DIR}/resultados/reporte_metricas.md"
  echo "#########################################"
  echo ""
  echo ">> Resultados guardados en: ${SCRIPT_DIR}/resultados/"
else
  echo "ERROR: faltan datos (alerts.json o log_ataques.csv). Revisa conectividad SSH"
  echo "       y que los escenarios se ejecutaran. Puedes reintentar la evaluación con"
  echo "       run_lab_aws.sh (opción 5) desde el atacante."
fi

banner "COMPLETADO"
echo "Dashboard Wazuh: https://${SIEM_IP}  (usuario admin; pass en el SIEM: sudo cat /root/wazuh_passwords.txt)"
echo "Para apagar todo y no gastar presupuesto:  ./teardown.sh -y"
