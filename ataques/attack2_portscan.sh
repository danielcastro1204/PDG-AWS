#!/usr/bin/env bash
# Ataque 2: Escaneo de puertos (MITRE T1046)
# Uso: ./attack2_portscan.sh <IP_OBJETIVO|RANGO>
set -euo pipefail
source "$(dirname "$0")/_lib_log_ataque.sh"
TARGET="${1:?Uso: $0 <IP_OBJETIVO_o_RANGO>}"

INICIO=$(log_inicio)
echo "[+] Escaneando puertos de ${TARGET}..."
# -sS (SYN scan) requiere privilegios de root (crea paquetes raw); el usuario
# 'attacker' del laboratorio tiene sudo NOPASSWD para esto.
# --max-retries/--host-timeout acotan el peor caso ante puertos filtrados
# (sin esto, un escaneo de los 65535 puertos puede tardar mucho más de lo
# esperado si hay descartes silenciosos, y sin generar ninguna salida visible
# mientras tanto).
sudo nmap -sS -sV -T4 -p- --max-retries 1 --host-timeout 5m "${TARGET}" -oN "/tmp/nmap_$(date +%s).log" || true
log_fin "portscan" "T1046" "${TARGET}" "${INICIO}" "1"
echo "[+] Ataque registrado en log_ataques.csv"
