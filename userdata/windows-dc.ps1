# =============================================================================
# windows-dc.ps1 (AWS) — Controlador de Dominio Windows Server 2019
# VLAN10 -> 10.0.10.20   Dominio: empresa.local
#
# Migración de Servidores/scripts/windows-dc.ps1 + windows-dc-second.ps1.
#
# En AWS la IP fija la asigna la ENI (PrivateIpAddress del template), así que no
# se reconfigura IP. Los REINICIOS que Vagrant orquestaba con vagrant-reload se
# resuelven aquí con una máquina de estados: EC2Launch re-ejecuta esta user-data
# en cada arranque (<persist>true</persist>) y el script avanza de fase leyendo
# C:\siem-state.txt. Fases: RENAME -> PROMOTE -> POSTAD -> DONE.
#
# Credenciales del laboratorio (débiles a propósito; entorno aislado de pruebas):
#   Administrator del dominio : P@ssw0rd   (usada por las estaciones para unirse)
#   user1                     : Proyecto.2026*
#   wazuh-svc                 : AgenteSIEM.26*
# =============================================================================
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Evitar doble ejecución simultánea (EC2Launch + tarea programada)
$mtx = New-Object System.Threading.Mutex($false, "Global\SiemLabProvision")
if (-not $mtx.WaitOne(0)) { Write-Host "Otra ejecución en curso; se omite."; exit 0 }

$SIEM_IP   = if ($env:SIEM_IP) { $env:SIEM_IP } else { "10.0.30.10" }
$DOMAIN    = if ($env:DOMAIN)  { $env:DOMAIN }  else { "empresa.local" }
$NETBIOS   = "EMPRESA"
$HOSTNAME  = "dc-empresa"
$VPC_RESOLVER = "169.254.169.253"
$LAB_ADMIN_PASS = "P@ssw0rd"
$SAFE_MODE_PASS = ConvertTo-SecureString $LAB_ADMIN_PASS -AsPlainText -Force
$STATE_FILE = "C:\siem-state.txt"
$WAZUH_AGENT_VER = "4.9.2"

$SELF_PATH = "C:\lab\userdata\windows-dc.ps1"
$TASK_NAME = "SiemLabProvision"

function Get-State { if (Test-Path $STATE_FILE) { (Get-Content $STATE_FILE -Raw).Trim() } else { "RENAME" } }
function Set-State($s) { Set-Content -Path $STATE_FILE -Value $s -Force }
function Log($m) { Write-Host ("[DC][" + (Get-State) + "] " + $m) }

# --- Reinicios robustos (independiente de EC2Launch v1/v2) -------------------
# Persistimos las variables necesarias a nivel de máquina y registramos una
# tarea programada que re-ejecuta este script en cada arranque hasta DONE.
foreach ($v in @("SIEM_IP","DOMAIN")) {
  $val = [Environment]::GetEnvironmentVariable($v, "Process")
  if ($val) { [Environment]::SetEnvironmentVariable($v, $val, "Machine") }
}
function Register-ResumeTask {
  if (-not (Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue)) {
    $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$SELF_PATH`""
    $t = New-ScheduledTaskTrigger -AtStartup
    $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TASK_NAME -Action $a -Trigger $t -Principal $p -Force | Out-Null
  }
}
function Unregister-ResumeTask { Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue }
if (Test-Path $SELF_PATH) { Register-ResumeTask }

$state = Get-State
Log "Iniciando fase: $state"

# -----------------------------------------------------------------------------
switch ($state) {

  "RENAME" {
    Set-TimeZone -Id "SA Pacific Standard Time" -ErrorAction SilentlyContinue
    if ($env:COMPUTERNAME -ne $HOSTNAME) {
      Log "Renombrando equipo a $HOSTNAME..."
      Rename-Computer -NewName $HOSTNAME -Force
    }
    Set-State "PROMOTE"
    Log "Reiniciando para aplicar hostname..."
    Restart-Computer -Force
  }

  "PROMOTE" {
    Log "Instalando roles AD DS + DNS..."
    Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools -ErrorAction Stop
    Set-State "POSTAD"
    Log "Promoviendo a bosque/controlador de dominio $DOMAIN (reinicio automático al terminar)..."
    Import-Module ADDSDeployment
    Install-ADDSForest `
      -DomainName $DOMAIN `
      -DomainNetbiosName $NETBIOS `
      -DomainMode "WinThreshold" `
      -ForestMode "WinThreshold" `
      -InstallDns:$true `
      -SafeModeAdministratorPassword $SAFE_MODE_PASS `
      -Force:$true
    # Install-ADDSForest reinicia solo; en el próximo arranque corre la fase POSTAD.
  }

  "POSTAD" {
    Log "Esperando a que Active Directory esté disponible..."
    $ready = $false
    for ($i=1; $i -le 30; $i++) {
      try { Import-Module ActiveDirectory -ErrorAction Stop; Get-ADDomain -ErrorAction Stop | Out-Null; $ready=$true; break }
      catch { Start-Sleep -Seconds 10 }
    }
    if (-not $ready) { throw "AD no disponible tras la promoción." }
    Log "Active Directory operativo."

    # DNS: forwarder al resolver de la VPC (salida a Internet) y adaptador -> sí mismo
    try { Add-DnsServerForwarder -IPAddress $VPC_RESOLVER -ErrorAction SilentlyContinue } catch {}
    $ifIndex = (Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1).ifIndex
    Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses @("127.0.0.1") -ErrorAction SilentlyContinue

    # Contraseña conocida del Administrator del dominio (para que las estaciones
    # puedan unirse con Administrator / P@ssw0rd, como en el laboratorio físico).
    try {
      Set-ADAccountPassword -Identity "Administrator" -NewPassword $SAFE_MODE_PASS -Reset -ErrorAction SilentlyContinue
      Set-ADUser -Identity "Administrator" -PasswordNeverExpires $true -ErrorAction SilentlyContinue
      Log "Contraseña del Administrator del dominio fijada."
    } catch { Write-Warning "No se pudo fijar la contraseña del Administrator: $_" }

    # OUs
    foreach ($ou in @("Usuarios","Computers")) {
      try { Get-ADOrganizationalUnit -Identity "OU=$ou,DC=empresa,DC=local" -ErrorAction Stop | Out-Null }
      catch { New-ADOrganizationalUnit -Name $ou -Path "DC=empresa,DC=local" -ProtectedFromAccidentalDeletion $false }
    }

    # Usuarios del proyecto
    $ouUsuarios = "OU=Usuarios,DC=empresa,DC=local"
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'user1'" -ErrorAction SilentlyContinue)) {
      New-ADUser -Name "user1" -SamAccountName "user1" -UserPrincipalName "user1@$DOMAIN" `
        -AccountPassword (ConvertTo-SecureString "Proyecto.2026*" -AsPlainText -Force) `
        -Enabled $true -Path $ouUsuarios -ChangePasswordAtLogon $false
    }
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'wazuh-svc'" -ErrorAction SilentlyContinue)) {
      New-ADUser -Name "wazuh-svc" -SamAccountName "wazuh-svc" -UserPrincipalName "wazuh-svc@$DOMAIN" `
        -AccountPassword (ConvertTo-SecureString "AgenteSIEM.26*" -AsPlainText -Force) `
        -Enabled $true -Path $ouUsuarios -PasswordNeverExpires $true -ChangePasswordAtLogon $false
    }

    # Registros DNS A
    Add-DnsServerResourceRecordA -ZoneName $DOMAIN -Name "dc-empresa" -IPv4Address "10.0.10.20" -ErrorAction SilentlyContinue
    Add-DnsServerResourceRecordA -ZoneName $DOMAIN -Name "web-server" -IPv4Address "10.0.10.10" -ErrorAction SilentlyContinue

    # Zona inversa
    try { Add-DnsServerPrimaryZone -NetworkId "10.0.10.0/24" -ReplicationScope "Domain" -DynamicUpdate "Secure" -ErrorAction SilentlyContinue } catch {}

    # GPO de auditoría
    try {
      Import-Module GroupPolicy -ErrorAction SilentlyContinue
      if (-not (Get-GPO -Name "SIEM-Auditoria-Seguridad" -ErrorAction SilentlyContinue)) { New-GPO -Name "SIEM-Auditoria-Seguridad" | Out-Null }
      New-GPLink -Name "SIEM-Auditoria-Seguridad" -Target "DC=empresa,DC=local" -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    # Auditoría avanzada (fuente de log #1: autenticación AD)
    $subs = @("Logon","Logoff","Account Lockout","User Account Management","Security Group Management",
              "Process Creation","Process Termination","Directory Service Access","Directory Service Changes",
              "Credential Validation","Kerberos Authentication Service","Kerberos Service Ticket Operations")
    foreach ($s in $subs) { auditpol /set /subcategory:"$s" /success:enable /failure:enable 2>$null | Out-Null }
    wevtutil sl Security /ms:104857600 | Out-Null

    # Firewall AD + RDP
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

    # --- Agente Wazuh ---
    Log "Instalando agente Wazuh (manager $SIEM_IP)..."
    $msi = "C:\Windows\Temp\wazuh-agent.msi"
    $url = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_AGENT_VER-1.msi"
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
      Start-Process msiexec.exe -ArgumentList @("/i","`"$msi`"","/qn","WAZUH_MANAGER=$SIEM_IP",
        "WAZUH_REGISTRATION_SERVER=$SIEM_IP","WAZUH_AGENT_NAME=dc-empresa",
        "WAZUH_MANAGER_PORT=1514","WAZUH_REGISTRATION_PORT=1515") -Wait
      Set-Service -Name WazuhSvc -StartupType Automatic -ErrorAction SilentlyContinue
      Start-Service WazuhSvc -ErrorAction SilentlyContinue
      Log "Agente Wazuh instalado."
    } catch { Write-Warning "No se pudo instalar el agente Wazuh: $_" }

    Set-State "DONE"
    Log "============================================================"
    Log " CONTROLADOR DE DOMINIO CONFIGURADO (empresa.local)"
    Log " DC=10.0.10.20  Admin=Administrator/P@ssw0rd  SIEM=$SIEM_IP"
    Log "============================================================"
  }

  "DONE" { Log "El DC ya está configurado. Nada que hacer." }
}

# Al terminar, retirar la tarea de reanudación para no re-ejecutar en cada arranque.
if ((Get-State) -eq "DONE") { Unregister-ResumeTask }
