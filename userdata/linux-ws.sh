#!/usr/bin/env bash
# =============================================================================
# linux-ws.sh (AWS) — Estación de trabajo Ubuntu | VLAN20 -> 10.0.20.40 / .41
# Migración de Workstations/scripts/linux-desktop.sh (sin GUI: headless en nube).
#
# Aporta: agente Wazuh + auditd (telemetría host Linux) y es el OBJETIVO del
# ataque de fuerza bruta SSH (Escenario 2). Se crea un usuario con contraseña
# débil presente en la wordlist de attack1_bruteforce_ssh.sh para que el ataque
# sea detectable (regla 100010 / T1110.001).
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"

VM_HOSTNAME="${VM_HOSTNAME:-linux-01}"
VM_DNS="${VM_DNS:-10.0.10.20}"

set_hostname "$VM_HOSTNAME"
set_timezone
escribir_hosts_lab

apt-get update -qq
apt-get install -y -qq curl wget gnupg lsb-release apt-transport-https ca-certificates \
  net-tools ufw unzip openssh-server auditd audispd-plugins samba-client sshpass \
  dnsutils swaks ntpdate 2>/dev/null || \
  apt-get install -y -qq curl wget net-tools unzip openssh-server auditd samba-client sshpass dnsutils

# --- Usuario objetivo de fuerza bruta SSH (Escenario 2) ----------------------
# Contraseña "admin123" (presente en la wordlist del ataque) para que Hydra
# produzca fallos + un acierto que dispare las reglas de correlación de Wazuh.
if ! id usuario &>/dev/null; then
  useradd -m -s /bin/bash usuario
  echo "usuario:admin123" | chpasswd
fi
# Permitir autenticación por contraseña en SSH (necesario para el ataque).
# NOTA: las AMI de Ubuntu Cloud Image traen /etc/ssh/sshd_config.d/60-cloudimg-
# settings.conf con "PasswordAuthentication no". sshd usa el PRIMER valor que
# encuentra (no el último) al procesar sshd_config y sus Include, así que un
# override nuestro debe leerse ANTES que ese archivo (orden alfabético) para
# que realmente tenga efecto: 00-lab.conf, no 90-lab.conf.
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
mkdir -p /etc/ssh/sshd_config.d
rm -f /etc/ssh/sshd_config.d/90-lab.conf
echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/00-lab.conf
systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# --- auditd: reglas de monitoreo (idénticas al laboratorio físico) -----------
cat > /etc/audit/rules.d/99-siem-lab.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -k sudo_commands
-a always,exit -F arch=b64 -S connect -k network_connect
-w /usr/bin/passwd -p x -k password_change
-w /etc/cron.d -p wa -k cron
EOF
systemctl enable auditd 2>/dev/null || true
augenrules --load 2>/dev/null || true
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true

# --- Agente Wazuh ------------------------------------------------------------
instalar_agente_wazuh "$VM_HOSTNAME"
# Monitorear el log de autenticación (fuerza bruta SSH)
wazuh_localfile "syslog" "/var/log/auth.log"
systemctl restart wazuh-agent 2>/dev/null || true

# --- Firewall UFW (permitir SSH para el ataque; resto por SG de AWS) ---------
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true
ufw allow 22/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

echo "============================================================"
echo " ${VM_HOSTNAME} listo (agente Wazuh + auditd + SSH)."
echo " Usuario objetivo fuerza bruta: usuario / admin123"
echo "============================================================"
