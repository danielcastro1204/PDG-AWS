#!/usr/bin/env bash
# =============================================================================
# teardown.sh — Elimina el laboratorio (stack + bucket) para ahorrar presupuesto.
# Uso: ./teardown.sh [-r us-east-1] [-s siem-lab] [-b BUCKET] [-y]
#   -y  no pedir confirmación
# =============================================================================
set -euo pipefail
REGION="us-east-1"; STACK="siem-lab"; BUCKET=""; YES="no"
while getopts "r:s:b:yh" opt; do
  case "$opt" in
    r) REGION="$OPTARG" ;; s) STACK="$OPTARG" ;; b) BUCKET="$OPTARG" ;;
    y) YES="si" ;; h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) exit 1 ;;
  esac
done
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
[ -n "$BUCKET" ] || BUCKET="siem-lab-${ACCOUNT_ID}-${REGION}"

if [ "$YES" != "si" ]; then
  read -rp "Eliminar stack '${STACK}' y bucket '${BUCKET}' en ${REGION}? (escribe SI): " a
  [ "$a" = "SI" ] || { echo "Cancelado."; exit 0; }
fi

echo ">> Eliminando stack ${STACK}..."
aws cloudformation delete-stack --region "$REGION" --stack-name "$STACK"
aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$STACK" || true

echo ">> Vaciando y eliminando bucket ${BUCKET}..."
aws s3 rb "s3://${BUCKET}" --force 2>/dev/null || echo "   (bucket ya no existe o no se pudo borrar)"
echo ">> Laboratorio eliminado."
