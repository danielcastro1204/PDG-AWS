#!/usr/bin/env bash
# =============================================================================
# web-server.sh (AWS) — Servidor Web Apache + IDS Suricata | VLAN10 -> 10.0.10.10
# Migración de Servidores/scripts/web-server.sh + Suricata/install_suricata.sh.
#
# Fuentes de log que aporta al SIEM:
#   #3 Logs del servidor web (Apache access/error)
#   #5 Alertas del IDS Suricata (eve.json)
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"

VM_IP="${VM_IP:-10.0.10.10}"
DOMAIN="${DOMAIN:-empresa.local}"
INSTALL_SURICATA="${INSTALL_SURICATA:-true}"
IFACE="$(detectar_iface)"; IFACE="${IFACE:-ens5}"

set_hostname "web-server"
set_timezone
escribir_hosts_lab

# --- Paquetes base + Apache ---------------------------------------------------
apt-get update -qq
apt-get install -y -qq curl wget gnupg lsb-release ca-certificates apt-transport-https net-tools vim apache2 dnsutils swaks ntpdate sshpass 2>/dev/null || apt-get install -y -qq curl wget net-tools apache2 dnsutils
systemctl enable apache2; systemctl start apache2

# --- Logging detallado (igual que en el lab físico) ---------------------------
cat > /etc/apache2/conf-available/siem-logging.conf <<'EOF'
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %D" combined_extended
LogLevel info
EOF
a2enconf siem-logging 2>/dev/null || true
a2enmod headers 2>/dev/null || true

# --- Sitio web del proyecto (incluye endpoint vulnerable para SQLi del Esc.2) -
cat > /var/www/html/index.html <<EOF
<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>Servidor Web - Proyecto SIEM | ${DOMAIN}</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0d1117;color:#c9d1d9;display:flex;min-height:100vh;align-items:center;justify-content:center}
.c{max-width:720px;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px}
h1{color:#f0f6fc}.k{color:#58a6ff;font-family:monospace}</style></head><body>
<div class="c"><h1>Servidor Web &middot; ${DOMAIN}</h1>
<p>Laboratorio SIEM (Wazuh + Active Directory) migrado a AWS &mdash; VLAN 10 (Servidores).</p>
<p>IP: <span class="k">${VM_IP}</span> &middot; DC: <span class="k">10.0.10.20</span> &middot; SIEM: <span class="k">10.0.30.10</span></p>
<p>Los accesos a esta página se reenvían al SIEM (Apache access/error + Suricata).</p></div></body></html>
EOF

# Endpoint PHP deliberadamente simple para que sqlmap genere eventos (Escenario 2)
apt-get install -y -qq php libapache2-mod-php 2>/dev/null || true
cat > /var/www/html/index.php <<'PHPEOF'
<?php
// Laboratorio: parámetro reflejado para generar tráfico de prueba de SQLi.
// NO usar en producción. Solo registra el intento en el log de Apache.
$id = isset($_GET['id']) ? $_GET['id'] : '1';
echo "<h1>Portal corporativo</h1><p>Consulta id=".htmlspecialchars($id)."</p>";
error_log("Consulta recibida id=".$id);
?>
PHPEOF

cat > /etc/apache2/sites-available/empresa-siem.conf <<EOF
<VirtualHost *:80>
    ServerName web-server.${DOMAIN}
    DocumentRoot /var/www/html
    ErrorLog  \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined_extended
    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF
a2ensite empresa-siem 2>/dev/null || true
a2dissite 000-default 2>/dev/null || true
systemctl restart apache2
log "Apache configurado (logs en /var/log/apache2/)."

# --- Samba (recurso compartido) + login SSH de prueba -------------------------
# Usados por escenarios/escenario1_linea_base.sh para generar trafico normal
# de "transferencia de archivos SMB" e "inicios de sesion" (metodologia del
# proyecto, Fase 3 / Escenario 1), con credenciales debiles a proposito (igual
# que el resto del laboratorio).
if ! id usuario &>/dev/null; then
  useradd -m -s /bin/bash usuario
  echo "usuario:admin123" | chpasswd
fi
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
mkdir -p /etc/ssh/sshd_config.d
rm -f /etc/ssh/sshd_config.d/90-lab.conf
echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/00-lab.conf
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

apt-get install -y -qq samba 2>/dev/null || true
mkdir -p /srv/compartido
chown usuario:usuario /srv/compartido
cat >> /etc/samba/smb.conf <<'EOF'

[compartido]
   path = /srv/compartido
   browsable = yes
   writable = yes
   guest ok = no
   valid users = usuario
EOF
(echo "admin123"; echo "admin123") | smbpasswd -s -a usuario 2>/dev/null || true
systemctl enable smbd 2>/dev/null || true
systemctl restart smbd 2>/dev/null || true

# --- Agente Wazuh + monitoreo de logs Apache ---------------------------------
instalar_agente_wazuh "web-server"
wazuh_localfile "apache" "/var/log/apache2/access.log"
wazuh_localfile "apache" "/var/log/apache2/error.log"

# --- Suricata (IDS) -----------------------------------------------------------
if [ "$INSTALL_SURICATA" = "true" ]; then
  info "Instalando Suricata sobre interfaz ${IFACE}..."
  add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
  apt-get update -qq
  apt-get install -y -qq suricata jq
  suricata-update update-sources 2>/dev/null || true
  suricata-update enable-source et/open 2>/dev/null || warn "No se pudo habilitar ET Open."
  suricata-update 2>/dev/null || warn "suricata-update falló."
  sed -i "s/^  - interface: .*/  - interface: ${IFACE}/" /etc/suricata/suricata.yaml 2>/dev/null || true
  sed -i 's#HOME_NET: .*#HOME_NET: "[10.0.0.0/16]"#' /etc/suricata/suricata.yaml 2>/dev/null || true
  systemctl enable suricata
  systemctl restart suricata
  sleep 3
  systemctl is-active --quiet suricata && log "Suricata activo en ${IFACE}." || warn "Suricata no arrancó (journalctl -u suricata)."
  wazuh_localfile "json" "/var/log/suricata/eve.json"
  systemctl restart wazuh-agent 2>/dev/null || true
fi

log "web-server listo (Apache + Suricata + agente Wazuh)."
