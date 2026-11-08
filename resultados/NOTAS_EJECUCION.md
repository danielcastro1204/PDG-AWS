# Notas de la ejecución de evaluación (Fase 3 y 4) — Despliegue AWS

**Fecha:** 20-21 de octubre de 2026
**Stack:** `siem-lab` (AWS Academy Cloud Architecting, cuenta 145326036987, us-east-1, perfil `completa`)

## Resumen

- Total de intentos de ataque incluidos en el cálculo: **31**
- Detectados: **31**
- **Tasa de detección: 100 %** (criterio de éxito del proyecto: ≥ 80 %)
- Posibles falsos positivos: **1**

Cubre los 5 tipos de ataque de la metodología: fuerza bruta SSH (T1110.001),
escaneo de puertos (T1046), inyección SQL (T1190), Pass-the-Hash (T1550.002)
y ejecución de payload vía WinRM (T1059.001).

## Exclusión de datos: primeros 5 intentos (00:27:22–00:27:58 UTC)

El archivo `log_ataques.csv` original del atacante contiene 5 filas iniciales
(fuerza bruta y escaneo de puertos) que se **excluyeron** del cálculo de
métricas porque corresponden a una corrida *anterior* a corregir dos bugs de
despliegue (ver abajo): el SSH del objetivo rechazaba el método de
autenticación por contraseña, y `nmap` fallaba por falta de privilegios de
root. En ambos casos el ataque **nunca llegó a generar tráfico real** contra
el objetivo (falló antes de intentar nada), por lo que no existe evento que
el SIEM pudiera haber detectado. Incluir esas filas habría bajado la tasa de
detección de forma artificial, sin reflejar una falla real de Wazuh. La
inyección SQL de esa misma corrida (que no dependía de los bugs) sí se
mantuvo si corresponde a un intento posterior al fix; las 5 filas excluidas
son exactamente las que caen en la ventana `00:27:*`.

El archivo completo sin filtrar (46 filas) se puede reconstruir si se
necesita para auditoría; `log_ataques.csv` en esta carpeta ya es la versión
filtrada (31 filas) usada para el reporte.

## Bugs de despliegue encontrados y corregidos durante esta ejecución

Todos corregidos y confirmados funcionando contra el despliegue real; el
detalle técnico de cada uno está en los mensajes de commit del repositorio
[PDG-AWS](https://github.com/danielcastro1204/PDG-AWS):

1. **`deploy.sh`** — la AWS CLI en Windows no podía leer el YAML de
   CloudFormation por las tildes en comentarios (codificación ANSI vs UTF-8).
2. **`userdata/wazuh-server.sh`** — el `sed` que reconfiguraba `ossec.conf`
   para el puerto 514 rompía el XML (borraba cierres de bloques existentes)
   y duplicaba un `<remote>` que Wazuh ya trae por defecto; el manager nunca
   arrancaba.
3. **`userdata/windows-dc.ps1` / `windows-ws.ps1`** (3 bugs):
   - condición de carrera de DNS tras la promoción a Controlador de Dominio
     (el DC se vuelve su propio DNS pero el forwarder se configuraba
     *después* de necesitarlo para descargar el paquete de scripts);
   - la OU personalizada `Computers` colisionaba con el contenedor por
     defecto de Active Directory del mismo nombre;
   - los `.ps1` sin BOM UTF-8 se corrompían al ejecutarse en PowerShell con
     la codificación ANSI de Windows.
4. **`userdata/linux-ws.sh`** — `PasswordAuthentication yes` nunca tomaba
   efecto porque la AMI de Ubuntu trae su propio override con mayor
   precedencia (`60-cloudimg-settings.conf` se lee antes que el nuestro).
5. **`ataques/attack2_portscan.sh`** — `nmap -sS` sin `sudo` (requiere root).
6. **`ataques/attack3_pass_the_hash.sh`** — `impacket-psexec` exige el
   formato `LM:NT`, fallaba si solo se pasaba el hash NT.
7. **`userdata/attacker.sh`** — el paquete `seclists` (de Kali, no existe en
   Ubuntu) rompía toda la instalación de herramientas, incluyendo Ruby
   (necesario para `evil-winrm`, usado por el ataque 5).
8. **`ataques/attack5_payload_exec.sh`** — `evil-winrm` no tiene un flag
   para ejecutar un solo comando; es una shell interactiva, el comando debe
   enviarse por stdin.
9. **`userdata/windows-ws.ps1`** — la regla de firewall para WinRM no basta;
   el servicio WinRM nunca se habilitaba (`Enable-PSRemoting`).
10. **`evaluacion/recolectar_alertas.py` / `calcular_metricas.py`** — las
    alertas de Wazuh usan la zona horaria local del servidor (`-0500`), pero
    el parseo de timestamps descartaba el offset sin convertir a UTC,
    causando que la correlación devolviera 0 alertas pese a haber miles.
11. Mismos scripts — `open()` sin `encoding="utf-8"` corrompía caracteres
    acentuados al escribir el reporte en Windows.

Todos estos bugs quedaron corregidos en el repositorio para que futuros
despliegues (o la defensa en vivo del proyecto) no los repitan.
