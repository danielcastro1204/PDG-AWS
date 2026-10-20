#!/usr/bin/env bash
# =============================================================================
# dhcpv4-server.sh (AWS) — Servidor DHCPv4 (Kea) | VLAN10 -> 10.0.10.30
# Migración de Servidores/scripts/dhcpv4-server.sh.
#
# NOTA AWS: en una VPC el direccionamiento lo entrega el DHCP de Amazon; este
# servicio se despliega con fines de FIDELIDAD/telemetría del proyecto (genera
# logs de servicio DHCP hacia el SIEM). No se declara autoritativo de la subred
# real para no interferir con la VPC: sirve un pool de demostración.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"

set_hostname "dhcpv4-server"; set_timezone; escribir_hosts_lab
apt-get update -qq
apt-get install -y -qq kea-dhcp4-server || apt-get install -y -qq isc-dhcp-server || true

if [ -d /etc/kea ]; then
  cat > /etc/kea/kea-dhcp4.conf <<'EOF'
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": [ "*" ] },
    "lease-database": { "type": "memfile", "persist": true, "name": "/var/lib/kea/kea-leases4.csv" },
    "valid-lifetime": 3600,
    "loggers": [ { "name": "kea-dhcp4", "output_options": [ { "output": "/var/log/kea-dhcp4.log" } ], "severity": "INFO" } ],
    "subnet4": [
      {
        "subnet": "10.0.20.0/24",
        "pools": [ { "pool": "10.0.20.150 - 10.0.20.200" } ],
        "option-data": [
          { "name": "routers", "data": "10.0.20.1" },
          { "name": "domain-name-servers", "data": "10.0.10.50, 10.0.10.60" },
          { "name": "domain-name", "data": "empresa.local" }
        ]
      }
    ]
  }
}
EOF
  mkdir -p /var/lib/kea /var/log; touch /var/log/kea-dhcp4.log
  systemctl enable kea-dhcp4-server 2>/dev/null || true
  systemctl restart kea-dhcp4-server 2>/dev/null || warn "Kea no arrancó (revisar journalctl -u kea-dhcp4-server)."
fi

instalar_agente_wazuh "dhcpv4-server"
wazuh_localfile "syslog" "/var/log/kea-dhcp4.log"
systemctl restart wazuh-agent 2>/dev/null || true
log "DHCPv4 (Kea) listo (pool demo 10.0.20.150-200)."
