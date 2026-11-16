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
    # NOTA de TUNING: se registran EXCLUSIVAMENTE los puertos "canario" (abajo).
    # Antes se registraba TODO SYN (FW-SYN) y las conexiones a puertos clave
    # (FW-NEW-CONN, incluidos 22/SSH y 445/SMB legitimos): bajo carga, ese
    # volumen inundaba el kern.log y el canal del agente se retrasaba, sepultando
    # los SYN canario de un escaneo low-and-slow (que llegaban tarde, fuera de la
    # ventana del ataque). Al registrar SOLO los puertos canario -sin servicio
    # legitimo ni trafico de internet- el kern.log queda casi vacio y CADA SYN de
    # reconocimiento se entrega al instante -> deteccion fiable del sigiloso.
    # TUNING escaneo SIGILOSO: puertos "canario" sin servicio legitimo en el lab.
    # Se registra CUALQUIER paquete a estos puertos por DESTINO (SIN condicion de
    # flags TCP). Causa raiz hallada de la evasion: nmap -f fragmenta el SYN en
    # trozos de 8 bytes; el PRIMER fragmento lleva los puertos (offset 0-7) pero el
    # byte de flags TCP esta en el byte 13 (fragmento posterior), de modo que una
    # condicion 'tcp flags syn' NUNCA casa un SYN fragmentado -> el escaneo sigiloso
    # no generaba log. Al casar solo por 'tcp dport' (presente en el primer
    # fragmento) se captura tambien el SYN fragmentado. Estos puertos no tienen
    # servicio legitimo ni trafico de internet (el SG solo expone el 22), asi que
    # cualquier paquete a ellos es reconocimiento puro -> senal casi pura, 0 FP.
    tcp dport {21, 23, 111, 135, 139, 1433, 3306, 3389, 5900, 8080} log prefix "FW-SCAN: " level info limit rate 50/second
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    # Solo puertos canario tambien en forward (escaneos a hosts internos).
    tcp dport {21, 23, 111, 135, 139, 1433, 3306, 3389, 5900, 8080} log prefix "FW-SCAN: " level info limit rate 50/second
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

# --- Entrega FIABLE de los logs del firewall por el canal del AGENTE (TCP 1514)
# Ademas del reenvio por syslog UDP (que bajo carga alta pierde paquetes), el
# agente Wazuh lee /var/log/kern.log (donde nftables escribe los eventos
# FW-SCAN). El canal del agente es TCP con cola, sin perdida -> la deteccion de
# escaneo (reglas 100003/100004/100022/100023) es robusta aun con el SIEM bajo
# mucha carga de eventos.
if ! grep -q "/var/log/kern.log" /var/ossec/etc/ossec.conf; then
  cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
  awk '/<\/ossec_config>/ && !d {print "  <localfile>"; print "    <log_format>syslog</log_format>"; print "    <location>/var/log/kern.log</location>"; print "  </localfile>"; d=1} {print}' \
    /var/ossec/etc/ossec.conf.bak > /var/ossec/etc/ossec.conf
  systemctl restart wazuh-agent || true
  log "Agente Wazuh del FW leyendo /var/log/kern.log (entrega fiable de logs de escaneo)."
fi

echo "============================================================"
echo " FIREWALL-GATEWAY listo (sustituto de pfSense)"
echo " Logs de firewall -> syslog UDP/514 -> Wazuh ${SIEM_IP}"
echo "============================================================"
