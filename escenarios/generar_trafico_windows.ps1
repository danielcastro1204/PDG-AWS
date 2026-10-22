# =============================================================================
# generar_trafico_windows.ps1 — Trafico de red realista desde la estacion
# Windows miembro de dominio. Emula a un empleado usando un equipo corporativo:
# navegacion web, acceso a recursos compartidos SMB, autenticacion de dominio
# (Kerberos/LDAP contra el DC), consultas DNS y actividad de proceso normal.
# Genera telemetria Sysmon + logs de Windows + eventos de AD legitimos, para
# que la medicion de falsos positivos sea significativa.
#
# Uso:  powershell -ExecutionPolicy Bypass -File generar_trafico_windows.ps1 [DURACION_MIN]
# =============================================================================
param([int]$DuracionMin = 30)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$fin = (Get-Date).AddMinutes($DuracionMin)

$DC_IP   = if ($env:DC_IP)  { $env:DC_IP }  else { "10.0.10.20" }
$WEB_IP  = if ($env:WEB_IP) { $env:WEB_IP } else { "10.0.10.10" }
$DOMAIN  = if ($env:DOMAIN) { $env:DOMAIN } else { "empresa.local" }

$sitios = @(
  "https://www.icesi.edu.co","https://es.wikipedia.org","https://www.microsoft.com",
  "https://www.google.com","https://www.github.com","https://www.python.org",
  "https://outlook.office365.com","https://www.cloudflare.com"
)
$dominios = @("google.com","microsoft.com","github.com","windowsupdate.com",
  "office365.com","wikipedia.org","amazonaws.com","icesi.edu.co")
$webPaths = @("/","/index.php?id=1","/index.php?id=5","/index.php?id=42","/index.php?id=2")

function Log($m) { Write-Host ("  [{0}][win-ws-01] {1}" -f (Get-Date -Format HH:mm:ss), $m) }
function Activo { (Get-Date) -lt $fin }
function Espera { Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 22) }

Log "Inicio trafico realista Windows ($DuracionMin min)"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

while (Activo) {
  switch (Get-Random -Minimum 0 -Maximum 10) {
    {$_ -in 0,1,2} {
      $s = $sitios | Get-Random
      try { Invoke-WebRequest -Uri $s -UseBasicParsing -TimeoutSec 8 | Out-Null; Log "web $s" } catch {}
    }
    {$_ -in 3,4} {
      $p = $webPaths | Get-Random
      try { Invoke-WebRequest -Uri ("http://{0}{1}" -f $WEB_IP,$p) -UseBasicParsing -TimeoutSec 5 | Out-Null; Log "portal $p" } catch {}
    }
    5 {
      $d = $dominios | Get-Random
      Resolve-DnsName -Name $d -Server $DC_IP -QuickTimeout | Out-Null; Log "dns $d"
    }
    6 {
      # Acceso a recurso compartido del DC (SYSVOL/NETLOGON) y del web-server
      Get-ChildItem "\\$DC_IP\SYSVOL" | Out-Null
      Get-ChildItem ("\\{0}\compartido" -f $WEB_IP) | Out-Null
      Log "smb share"
    }
    7 {
      # Autenticacion / consulta de dominio (Kerberos + LDAP contra el DC)
      klist | Out-Null
      nltest /dsgetdc:$DOMAIN | Out-Null
      ([ADSISearcher]"(objectClass=user)").FindAll() | Out-Null
      Log "auth dominio (kerberos/ldap)"
    }
    8 {
      # Actividad de proceso normal de un usuario
      Get-Process | Out-Null; Get-Service | Where-Object Status -eq Running | Out-Null
      cmd /c "whoami /groups" | Out-Null
      Log "actividad local"
    }
    9 {
      gpupdate /target:computer | Out-Null; Log "gpupdate"
    }
  }
  Espera
}
Log "Trafico realista Windows finalizado."
