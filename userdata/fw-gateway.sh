#!/usr/bin/env bash
# =============================================================================
# fw-gateway.sh (AWS) — Firewall perimetral  | VLAN30 -> 10.0.30.30
# SUSTITUTO de pfSense del laboratorio físico (Gestion/scripts/pfsense-config.sh).
#
# pfSense no es desplegable de forma fiable ni automática en el sandbox de AWS
# Academy (es FreeBSD y requiere AMI de Netgate/BYOL + confirmación por consola).
# Se sustituye por un firewall Linux con nftables cuya BITÁCORA se reenvía por
# syslog al Wazuh Manager (10.0.30.10:514) — exactamente la integración que el
# proyecto documentaba para pfSense. Aporta la FUENTE DE LOG #2 (firewall).
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"

SIEM_IP="${SIEM_IP:-10.0.30.10}"

set_hostname "fw-gateway"
set_timezone
escribir_hosts_lab

apt-get update -qq
apt-get install -y -qq nftables rsyslog curl

# --- nftables con registro (logging) de conexiones -------------------------
# Política permisiva de reenvío (el filtrado real entre segmentos lo hacen los
# Security Groups de AWS); el valor de esta VM es GENERAR LOGS de firewall.
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    # Registrar intentos a puertos sensibles (visibilidad de firewall)
    tcp dport {22, 23, 3389, 445, 1433, 3306} ct state new log prefix "FW-NEW-CONN: " level info
    tcp flags & (fin|syn|rst|ack) == syn ct state new log prefix "FW-SYN: " level info limit rate 20/second
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ct state new log prefix "FW-FWD: " level info limit rate 20/second
  }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
systemctl enable nftables
systemctl restart nftables
log "nftables activo con reglas de logging."

# --- rsyslog: reenviar los logs de firewall (kern/nft) al Wazuh Manager ------
cat > /etc/rsyslog.d/60-fw-to-wazuh.conf <<EOF
# Reenvío de logs del firewall al SIEM Wazuh (equivalente al 'remote syslog'
# que pfSense enviaba a ${SIEM_IP}:514 en el laboratorio físico).
:msg, contains, "FW-" @${SIEM_IP}:514
kern.*                 @${SIEM_IP}:514
EOF
systemctl restart rsyslog
log "Firewall reenviando syslog a ${SIEM_IP}:514 (fuente de log #2)."

# --- También instalamos el agente Wazuh (telemetría del propio host) ---------
instalar_agente_wazuh "fw-gateway"

echo "============================================================"
echo " FIREWALL-GATEWAY listo (sustituto de pfSense)"
echo " Logs de firewall -> syslog UDP/514 -> Wazuh ${SIEM_IP}"
echo "============================================================"
