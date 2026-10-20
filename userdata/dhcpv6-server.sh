#!/usr/bin/env bash
# =============================================================================
# dhcpv6-server.sh (AWS) — Servidor DHCPv6 (Kea) | VLAN10 -> 10.0.10.40
# Migración de Servidores/scripts/dhcpv6-server.sh (pool de demostración).
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"

set_hostname "dhcpv6-server"; set_timezone; escribir_hosts_lab
apt-get update -qq
apt-get install -y -qq kea-dhcp6-server || true

if [ -d /etc/kea ]; then
  cat > /etc/kea/kea-dhcp6.conf <<'EOF'
{
  "Dhcp6": {
    "interfaces-config": { "interfaces": [ "*" ] },
    "lease-database": { "type": "memfile", "persist": true, "name": "/var/lib/kea/kea-leases6.csv" },
    "valid-lifetime": 4000,
    "loggers": [ { "name": "kea-dhcp6", "output_options": [ { "output": "/var/log/kea-dhcp6.log" } ], "severity": "INFO" } ],
    "subnet6": [
      {
        "subnet": "fd00:20::/64",
        "pools": [ { "pool": "fd00:20::150 - fd00:20::200" } ],
        "option-data": [ { "name": "dns-servers", "data": "fd00:10::50, fd00:10::60" } ]
      }
    ]
  }
}
EOF
  mkdir -p /var/lib/kea /var/log; touch /var/log/kea-dhcp6.log
  systemctl enable kea-dhcp6-server 2>/dev/null || true
  systemctl restart kea-dhcp6-server 2>/dev/null || warn "Kea DHCP6 no arrancó."
fi

instalar_agente_wazuh "dhcpv6-server"
wazuh_localfile "syslog" "/var/log/kea-dhcp6.log"
systemctl restart wazuh-agent 2>/dev/null || true
log "DHCPv6 (Kea) listo (pool demo fd00:20::150-200)."
