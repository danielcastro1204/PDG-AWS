#!/usr/bin/env bash
# Escenario 1: Linea base de trafico normal (sin actividad maliciosa)
# Ejecutar SIMULTANEAMENTE en las estaciones Linux/Windows del segmento de
# usuarios (VLAN20) durante el tiempo definido en DURACION_MIN.
# Objetivo: medir la tasa de falsos positivos del SIEM.
set -euo pipefail
DURACION_MIN="${1:-30}"
SITIOS=(https://www.icesi.edu.co https://es.wikipedia.org https://www.python.org https://www.debian.org)
SMB_SERVER="${SMB_SERVER:-10.0.10.10}"
SMB_SHARE="${SMB_SHARE:-compartido}"
SMB_USER="${SMB_USER:-usuario}"
SMB_PASS="${SMB_PASS:-admin123}"
SSH_TEST_HOST="${SSH_TEST_HOST:-usuario@10.0.10.10}"
SSH_TEST_PASS="${SSH_TEST_PASS:-admin123}"

FIN=$(( $(date +%s) + DURACION_MIN*60 ))
echo "[+] Iniciando trafico normal por ${DURACION_MIN} min ($(date))"

while [ "$(date +%s)" -lt "$FIN" ]; do
  # 1. Navegacion web a sitios legitimos
  SITE=${SITIOS[$RANDOM % ${#SITIOS[@]}]}
  curl -s -m 5 -o /dev/null "$SITE" && echo "  [web] GET $SITE" || true

  # 2. Acceso SMB a recursos compartidos (transferencia de archivos)
  if command -v smbclient &>/dev/null; then
    TMPF="/tmp/siem_lab_smb_$$.txt"; echo "trafico normal $(date -u +%FT%TZ)" > "$TMPF"
    smbclient "//${SMB_SERVER}/${SMB_SHARE}" "${SMB_PASS}" -U "${SMB_USER}" \
      -c "ls; put ${TMPF} prueba_$$.txt; get prueba_$$.txt /tmp/siem_lab_smb_get_$$.txt; rm prueba_$$.txt" \
      &>/dev/null && echo "  [smb] Transferencia con //${SMB_SERVER}/${SMB_SHARE}" || true
    rm -f "$TMPF" "/tmp/siem_lab_smb_get_$$.txt"
  fi

  # 3. Inicio de sesion SSH legitimo (login + acceso a recurso)
  if [ -n "${SSH_TEST_HOST:-}" ] && command -v sshpass &>/dev/null; then
    sshpass -p "${SSH_TEST_PASS}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 "${SSH_TEST_HOST}" "whoami; ls /srv/compartido 2>/dev/null" &>/dev/null \
      && echo "  [ssh] login correcto a ${SSH_TEST_HOST}" || true
  fi

  sleep $(( (RANDOM % 20) + 10 ))
done
echo "[+] Trafico normal finalizado ($(date))."
