# SEC-004 — Servicio o tarea programada nueva

## Qué significa
Se instaló un servicio (evento 7045, canal System) o se creó una tarea programada (4698, canal Security). Los atacantes los usan para ejecutar código de forma persistente; también los generan instaladores y actualizaciones legítimas.

## Cómo verificar
1. En la alerta: nombre, ruta del ejecutable (`detail`) y cuenta que lo ejecuta.
2. ¿Ruta fuera de `C:\Windows`, `C:\Program Files*` o `D:\Apps`? (p. ej. `C:\Users\Public`, `%TEMP%`) → sospechoso.
3. ¿Coincide con una instalación o actualización conocida? Comprobar firma digital: `Get-AuthenticodeSignature <ruta>`.
4. Servicio: `Get-CimInstance Win32_Service -Filter "Name='<nombre>'"`; tarea: `Get-ScheduledTask -TaskName <nombre> | Select -Expand Actions`.

## Contención
Si es sospechoso: detener y deshabilitar (`Stop-Service`/`Set-Service -StartupType Disabled`, `Disable-ScheduledTask`), **sin borrar** el binario (evidencia). Aislar el servidor si hay indicios de compromiso.

## Erradicación
Conservar copia del binario y su hash (`Get-FileHash`), analizarlo (antivirus/VirusTotal por hash), revisar cómo llegó (SEC-003, SEC-006, SEC-010) y eliminar la persistencia.

## Recuperación
Eliminar el servicio (`sc.exe delete`) o la tarea una vez preservada la evidencia; revisar otros servicios/tareas recientes.

## A quién avisar
Administrador de sistemas; responsable de seguridad si no hay una explicación legítima.
