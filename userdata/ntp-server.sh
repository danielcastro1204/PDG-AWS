#!/usr/bin/env bash
# =============================================================================
# ntp-server.sh (AWS) — Servidor de hora (chrony) | VLAN10 -> 10.0.10.80
# Migración de Servidores/scripts/ntp-server.sh. Sirve hora a las 3 subredes.
# La precisión NTP es un SUPUESTO METODOLÓGICO del proyecto (correlación por
# ventanas de tiempo en Evaluacion/).
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"

set_hostname "ntp-server"; set_timezone; escribir_hosts_lab
apt-get update -qq
apt-get install -y -qq chrony

cat > /etc/chrony/chrony.conf <<'EOF'
# Fuente upstream (en AWS hay salida a Internet por el IGW)
pool pool.ntp.org iburst
# Reloj local como respaldo (laboratorio aislado) - stratum 10
local stratum 10
# Servir a las subredes del laboratorio
allow 10.0.0.0/16
allow fd00::/16
driftfile /var/lib/chrony/chrony.drift
rtcsync
logdir /var/log/chrony
EOF
systemctl enable chrony 2>/dev/null || true
systemctl restart chrony 2>/dev/null || warn "chrony no arrancó."
chronyc makestep 2>/dev/null || true

instalar_agente_wazuh "ntp-server"
log "NTP (chrony) sirviendo hora a 10.0.0.0/16."
