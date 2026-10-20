#!/usr/bin/env bash
# =============================================================================
# smtp-server.sh (AWS) — Correo Postfix + Dovecot | VLAN10 -> 10.0.10.70
# Migración de Servidores/scripts/smtp-server.sh (versión de laboratorio).
# Genera tráfico/logs de correo para la línea base (Escenario 1).
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
DOMAIN="${DOMAIN:-empresa.local}"
TEST_USER="correo1"; TEST_PASS="Correo123!"

set_hostname "smtp-server"; set_timezone; escribir_hosts_lab
apt-get update -qq
apt-get install -y -qq openssl

# Preconfigurar Postfix no interactivo
debconf-set-selections <<EOF
postfix postfix/mailname string ${DOMAIN}
postfix postfix/main_mailer_type string 'Internet Site'
EOF
apt-get install -y -qq postfix dovecot-core dovecot-imapd dovecot-pop3d mailutils

# Certificado TLS autofirmado para el servicio de correo
mkdir -p /etc/ssl/smtp
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout /etc/ssl/smtp/smtp.key -out /etc/ssl/smtp/smtp.crt \
  -subj "/CN=smtp.${DOMAIN}" 2>/dev/null || true

postconf -e "myhostname = smtp.${DOMAIN}"
postconf -e "mydestination = \$myhostname, localhost, ${DOMAIN}"
postconf -e "inet_interfaces = all"
postconf -e "mynetworks = 127.0.0.0/8 10.0.0.0/16"
postconf -e "home_mailbox = Maildir/"
postconf -e "smtpd_tls_cert_file=/etc/ssl/smtp/smtp.crt"
postconf -e "smtpd_tls_key_file=/etc/ssl/smtp/smtp.key"

# Cuenta de prueba
if ! id "$TEST_USER" &>/dev/null; then
  useradd -m -s /usr/sbin/nologin "$TEST_USER"
  echo "${TEST_USER}:${TEST_PASS}" | chpasswd
fi

systemctl enable postfix dovecot 2>/dev/null || true
systemctl restart postfix dovecot 2>/dev/null || warn "Postfix/Dovecot no arrancaron."

instalar_agente_wazuh "smtp-server"
wazuh_localfile "syslog" "/var/log/mail.log"
systemctl restart wazuh-agent 2>/dev/null || true
log "SMTP (Postfix+Dovecot) listo. Cuenta prueba: ${TEST_USER}/${TEST_PASS}"
