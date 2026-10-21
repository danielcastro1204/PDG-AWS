#!/usr/bin/env bash
# =============================================================================
# attacker.sh (AWS) — Estación atacante | VLAN30 -> 10.0.30.20
# SUSTITUTO de Kali Linux (Gestion/scripts/kali-attacker.sh).
#
# AWS no ofrece AMI gratuita de Kali en el sandbox; se usa Ubuntu 22.04 y se
# instala el MISMO conjunto de herientas de pentesting que usaban los 5 ataques
# del proyecto (nmap, hydra, sqlmap, impacket, crackmapexec/netexec, metasploit,
# evil-winrm...). Se conservan verbatim los scripts de ataque en /opt/lab/ataques.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"

ATTACKER_USER="attacker"; ATTACKER_PASS="attacker"
DC_IP="${DC_IP:-10.0.10.20}"; WEB_IP="${WEB_IP:-10.0.10.10}"
WIN_WS_IP="${WIN_WS_IP:-10.0.20.30}"; SSH_TARGET="${SSH_TARGET:-10.0.20.40}"

set_hostname "atacante"
set_timezone
escribir_hosts_lab

apt-get update -qq
# Herramientas disponibles directamente en los repos de Ubuntu.
# NOTA: 'seclists' es un paquete de los repos de Kali, no existe en Ubuntu —
# si se incluye en esta lista, apt-get falla ENTERO (no solo ese paquete) y
# cae al fallback reducido de abajo, que no trae 'ruby' (necesario para
# evil-winrm, usado por attack5_payload_exec.sh). Se instala aparte, opcional.
apt-get install -y -qq \
  nmap hydra sqlmap nikto john hashcat smbclient netcat-traditional socat \
  gobuster dnsrecon whatweb wfuzz curl wget git python3-pip python3-venv pipx \
  ruby ruby-dev build-essential libssl-dev 2>/dev/null || \
  apt-get install -y -qq nmap hydra sqlmap nikto john smbclient netcat-traditional curl wget git python3-pip pipx ruby ruby-dev build-essential libssl-dev
apt-get install -y -qq seclists 2>/dev/null || true

# Impacket + NetExec (sucesor de crackmapexec) vía pipx (aislado)
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
pipx install impacket 2>/dev/null || pip3 install impacket --break-system-packages 2>/dev/null || true
pipx install netexec 2>/dev/null || true
# Compatibilidad de nombres con los scripts del proyecto (impacket-psexec, crackmapexec)
ln -sf /usr/local/bin/psexec.py        /usr/local/bin/impacket-psexec 2>/dev/null || true
ln -sf /usr/local/bin/secretsdump.py   /usr/local/bin/impacket-secretsdump 2>/dev/null || true
ln -sf /usr/local/bin/nxc              /usr/local/bin/crackmapexec 2>/dev/null || true

# evil-winrm (gem) — usado por attack5_payload_exec.sh
gem install evil-winrm 2>/dev/null || true

# Metasploit Framework (instalador oficial omnibus)
if ! command -v msfconsole &>/dev/null; then
  info "Instalando Metasploit Framework..."
  curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
    -o /tmp/msfinstall 2>/dev/null && chmod +x /tmp/msfinstall && /tmp/msfinstall 2>/dev/null || warn "Metasploit no se pudo instalar automáticamente."
fi

# --- Usuario atacante (sudo sin contraseña, como en el lab físico) -----------
if ! id "$ATTACKER_USER" &>/dev/null; then
  useradd -m -s /bin/bash "$ATTACKER_USER"
  echo "${ATTACKER_USER}:${ATTACKER_PASS}" | chpasswd
  usermod -aG sudo "$ATTACKER_USER"
fi
echo "${ATTACKER_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${ATTACKER_USER}
chmod 440 /etc/sudoers.d/${ATTACKER_USER}

# --- Copiar los scripts de ataque y escenarios ($HOME del atacante) ----------
install -d -o "$ATTACKER_USER" -g "$ATTACKER_USER" "/home/${ATTACKER_USER}/ataques" "/home/${ATTACKER_USER}/escenarios" "/home/${ATTACKER_USER}/evaluacion"
cp -r "${LAB_DIR}/ataques/." "/home/${ATTACKER_USER}/ataques/" 2>/dev/null || true
cp -r "${LAB_DIR}/escenarios/." "/home/${ATTACKER_USER}/escenarios/" 2>/dev/null || true
cp -r "${LAB_DIR}/evaluacion/." "/home/${ATTACKER_USER}/evaluacion/" 2>/dev/null || true
chmod +x /home/${ATTACKER_USER}/ataques/*.sh /home/${ATTACKER_USER}/escenarios/*.sh 2>/dev/null || true
chown -R "${ATTACKER_USER}:${ATTACKER_USER}" "/home/${ATTACKER_USER}"

# --- Variables de objetivo del laboratorio (las leen run_all_attacks.sh y los
#     escenarios por entorno; así los scripts del proyecto quedan sin tocar) ---
cat > "/home/${ATTACKER_USER}/lab.env" <<EOF
# Objetivos del laboratorio (esquema AWS). 'source ~/lab.env' antes de atacar.
export DC_IP="${DC_IP}"
export WEB_URL="http://${WEB_IP}/index.php?id=1"
export WIN_WS_IP="${WIN_WS_IP}"
export SSH_TARGET="${SSH_TARGET}"
export SSH_USER="usuario"
export REPETICIONES="5"
export DOMAIN_ADMIN="EMPRESA/Administrator"
export DOMAIN_ADMIN_PASS="P@ssw0rd"
# IP PUBLICA de linux-01 (Escenario 3: trafico de fondo real en la estacion de
# usuario, por SSH, en vez de generarlo desde el atacante). Vacio = fallback
# local dentro de escenario3_mixto.sh. Editala manualmente si hace falta:
export LINUX_WS_PUBLIC_IP=""
EOF
cat > "/home/${ATTACKER_USER}/.profile_lab" <<EOF
# === Laboratorio SIEM (AWS) — Estación atacante 10.0.30.20 ===
# Objetivos:
#   DC Windows      : ${DC_IP}
#   Web (SQLi)      : ${WEB_IP}  ->  http://${WEB_IP}/index.php?id=1
#   Win workstation : ${WIN_WS_IP}
#   Linux (SSH)     : ${SSH_TARGET}
#   SIEM Wazuh      : 10.0.30.10
# Uso rápido:
#   source ~/lab.env && cd ~/ataques && ./run_all_attacks.sh
EOF
echo "source ~/lab.env 2>/dev/null; cat ~/.profile_lab" >> "/home/${ATTACKER_USER}/.bashrc"
chown "${ATTACKER_USER}:${ATTACKER_USER}" "/home/${ATTACKER_USER}/lab.env" "/home/${ATTACKER_USER}/.profile_lab"

echo "============================================================"
echo " ATACANTE listo (sustituto Kali). Usuario: attacker/attacker"
echo " Ejecutar: sudo su - attacker; source ~/lab.env; cd ~/ataques; ./run_all_attacks.sh"
echo "============================================================"
