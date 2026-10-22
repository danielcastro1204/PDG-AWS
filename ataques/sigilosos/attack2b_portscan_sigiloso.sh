#!/usr/bin/env bash
# Ataque 2b (SIGILOSO): Escaneo de puertos evasivo (MITRE T1046)
# A diferencia del escaneo ruidoso (-sS -T4 -p- a todos los puertos rapido),
# aqui se usa timing muy lento (-T1 paranoico), fragmentacion de paquetes (-f),
# senuelos (-D) y un conjunto reducido de puertos, para evadir la deteccion de
# escaneos por umbral de Suricata/Wazuh. Tecnica de evasion real documentada.
# Uso: ./attack2b_portscan_sigiloso.sh <IP>
set -uo pipefail
source "$(dirname "$0")/../_lib_log_ataque.sh"
TARGET="${1:?Uso: $0 <IP_OBJETIVO>}"

INICIO=$(log_inicio)
echo "[+] Escaneo SIGILOSO de ${TARGET} (-T1 paranoico, fragmentado, con senuelos)..."
# -T1: timing muy lento; -f: fragmenta; -D: senuelos (oculta el origen real);
# --scan-delay: separa los paquetes; puertos tipicos solamente.
sudo nmap -sS -T1 -f -D RND:5 --scan-delay 2s -p 22,80,135,139,389,443,445,3389,5985 \
  "${TARGET}" -oN "/tmp/nmap_sigiloso_$(date +%s).log" &>/dev/null || true
log_fin "portscan_sigiloso" "T1046" "${TARGET}" "${INICIO}" "1"
echo "[+] Ataque sigiloso registrado en log_ataques.csv"
