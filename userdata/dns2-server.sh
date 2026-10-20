#!/usr/bin/env bash
# =============================================================================
# dns2-server.sh (AWS) — DNS secundario/esclavo BIND9 | VLAN10 -> 10.0.10.60
# Migración de Servidores/scripts/dns2-server.sh (adaptado a 10.0.x.y).
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
DOMAIN="${DOMAIN:-empresa.local}"
DNS1_IP="10.0.10.50"

set_hostname "dns2-server"; set_timezone; escribir_hosts_lab
apt-get update -qq
apt-get install -y -qq bind9 bind9utils dnsutils

cat > /etc/bind/named.conf.options <<EOF
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { any; };
    forwarders { 169.254.169.253; };
    dnssec-validation no;
    listen-on { any; };
};
EOF

cat > /etc/bind/named.conf.local <<EOF
zone "${DOMAIN}" {
    type slave;
    masters { ${DNS1_IP}; };
    file "/var/cache/bind/db.${DOMAIN}";
};
zone "10.0.10.in-addr.arpa" {
    type slave;
    masters { ${DNS1_IP}; };
    file "/var/cache/bind/db.10.0.10";
};
EOF

named-checkconf || warn "Revisar named.conf en DNS2."
systemctl enable named 2>/dev/null || systemctl enable bind9 2>/dev/null || true
systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null || true
instalar_agente_wazuh "dns2-server"
log "DNS2 (BIND9 esclavo de ${DNS1_IP}) listo."
