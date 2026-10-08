# SEC-010 — Proceso sospechoso (PowerShell codificado / ejecución desde carpeta temporal; incluye SEC-010-TEMP)

## Qué significa
Sysmon registró (evento 1) un `powershell.exe`/`pwsh.exe` lanzado con `-EncodedCommand` y un base64 largo — **SEC-010** — o un proceso ejecutado desde `\Temp\`, `\AppData\Local\Temp\` o `\Users\Public\` — **SEC-010-TEMP**. Ambos son comunes en malware, pero **también en instaladores y actualizadores legítimos** (esperar falsos positivos en la observación).

## Cómo verificar
1. En la alerta: imagen (`target`), línea de comandos (`detail`), usuario y proceso padre (en el evento de Sysmon).
2. Decodificar el comando: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<base64>'))` (en un entorno seguro).
3. ¿Hay un instalador/actualización en curso? ¿El binario tiene firma válida (`Get-AuthenticodeSignature`)? Hash en un servicio de reputación.
4. Cruzar con SEC-008 (Defender), SEC-004 (persistencia) y SEC-006 (archivos).

## Contención
Si es malicioso: terminar el proceso (`Stop-Process`), aislar el servidor, preservar el binario y la memoria si es posible, y no reiniciar hasta recoger evidencia.

## Erradicación
Identificar el vector de entrada (descarga, adjunto, RDP, web shell), eliminar persistencia y credenciales comprometidas (plan *compromiso de cuenta*).

## Recuperación
Restaurar desde respaldo limpio si hay duda. Añadir a `excepto` los patrones legítimos confirmados para reducir ruido.

## A quién avisar
Responsable de seguridad; administrador de sistemas.
