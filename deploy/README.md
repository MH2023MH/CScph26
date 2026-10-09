# Despliegue de SecurityAgent (srv-copahue2)

> Estado: los scripts se **ejecutan de extremo a extremo en un Windows Server 2025 limpio** en cada cambio (workflow
> `Windows integration`, job `windows-installer`, script `deploy/ci/Test-InstallFlow.ps1`): instalación real, cuenta virtual,
> ACL, firewall, API, alertas reales, integridad, CLI y desinstalación. Eso **no sustituye** la prueba en srv-copahue2
> (Fase 8): allí hay IIS, SQL Server, Sysmon, Cloudflare y otras apps que el runner de CI no tiene. Probar siempre primero con
> `-WhatIf`, luego en una VM, y recién después en el servidor.
>
> `Test-InstallFlow.ps1` instala y desinstala de verdad, crea cuentas, servicios y tareas de prueba: **solo en una VM descartable
> o en el runner de CI, nunca en el servidor**.

## 1. Publicar
```powershell
dotnet publish src/SecurityAgent.Worker -c Release -r win-x64 --self-contained false -o publish
```
Requiere el runtime **.NET 8 (ASP.NET Core Runtime)** instalado en el servidor.

## 2. Preparar la configuración
Copiar `appsettings.Production.example.json` a `appsettings.Production.json`, completar los secretos y guardarlo **fuera de git**
(está en `.gitignore`). Secretos: token de la API, SMTP, webhook de Teams, clave HMAC del manifiesto, token del destino de logs.

- Token de la API: aleatorio de **32 o más caracteres** (p. ej. `[Convert]::ToBase64String((1..32 | % { Get-Random -Max 256 }))`). Con el valor de ejemplo o uno corto la API no arranca (el monitor sí).
- `StatusApi:AllowedClients` **reemplaza** la lista por defecto; cada entrada debe ser una IP o CIDR válido.
- `Integrity:HmacKey`: sin ella (o con la de ejemplo) el manifiesto no está firmado y `problems` lo advierte: quien pueda escribir en la carpeta podría regenerarlo.
- `BlockLimits` (opcional): topes de seguridad del responder en `enforce` (por defecto 20 bloqueos nuevos por minuto y 500 activos).

## 3. Instalar
```powershell
.\Install-SecurityAgent.ps1 -PublishDir .\publish -ConfigFile .\appsettings.Production.json `
    -SqlLogDir 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log' -AdvisorAddress 192.168.X.X -WhatIf
```
Quitar `-WhatIf` para aplicar (el script usa `ConfirmImpact=High`: en una sesión no interactiva hay que añadir `-Confirm:$false`).
El script: crea la carpeta, copia archivos, registra la fuente `SecurityAgent` en el registro de eventos de Windows (la cuenta del
servicio no puede crearla y sin ella se perderían sus logs), crea el servicio con cuenta virtual
`NT SERVICE\SecurityAgent`, aplica ACL (el servicio solo **lee** binarios/reglas/config; solo escribe en `data\` y `logs\`),
concede lectura sobre las fuentes (incluido el grupo *Event Log Readers* para los logs Security y System; sobre `D:\Apps` solo
**listar carpetas**, no leer los archivos de las demás apps), genera el manifiesto de integridad y arranca el servicio. Las ACL se aplican
**antes** de copiar nada, para que la configuración con secretos nunca exista con permisos heredados.

Los .ps1 llevan BOM UTF-8 a propósito: Windows PowerShell 5.1 lee como ANSI los que no lo tienen y rompe los acentos
(`ScriptEncodingTests` lo vigila).

## 4. Verificar integridad en cualquier momento
```powershell
D:\Apps\SecurityAgent\SecurityAgent.Worker.exe --verify-manifest      # código de salida 0 = íntegro, 2 = violado
```
Tras una actualización legítima hay que regenerar el manifiesto (`--make-manifest`); el instalador ya lo hace.

## 4a. Carga sostenida
`Test-InstallFlow.ps1 -SoakSeconds 600` (en una VM descartable o con el workflow manual `Soak`) instala el servicio, le inyecta tráfico IIS
hostil (~1 700 líneas/s), eventos de seguridad reales y cambios de archivos, y comprueba: sin reinicios, RAM < 512 MB, CPU < 25 %, latido
< 30 s, la API responde, `agent.db` acotada y el agente se pone al día. El CI de Windows lo ejecuta 40 s en cada cambio.

## 4b. Diagnóstico
```powershell
D:\Apps\SecurityAgent\SecurityAgent.Worker.exe --stats                  # eventos por fuente, alertas por regla, bloqueos, cursores
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='SecurityAgent' } -MaxEvents 20
```
`GET /api/v1/status` incluye `problems`: fuentes que el agente no puede leer (canal de Event Log inexistente o sin permiso, carpeta
vigilada que no existe, etc.). Una fuente ilegible nunca falla en silencio: aparece ahí, en el Event Log de Windows y el
`SecurityAdvisor` lo menciona al verificar el latido.

## 5. Desbloquear una IP (rollback, principio 3)
```powershell
D:\Apps\SecurityAgent\SecurityAgent.Worker.exe --unblock-ip 203.0.113.50
D:\Apps\SecurityAgent\SecurityAgent.Worker.exe --list-blocks
```

## 6. Decisiones abiertas que condicionan el modo `enforce` (Fase 10)
- **Privilegios para bloquear.** Crear reglas de Windows Firewall exige un token de administrador; la cuenta virtual de mínimos
  privilegios **no puede** hacerlo. En modo `observe` no hace falta. Antes de pasar alguna regla a `enforce` hay que elegir:
  (a) un ayudante privilegiado mínimo (p. ej. tarea programada como SYSTEM que solo ejecuta bloquear/desbloquear una IP validada),
  o (b) ejecutar el servicio con una cuenta con permisos de firewall, aceptando el mayor riesgo. Hasta decidir, el responder
  registra el error en la alerta ("error al bloquear ...") y no bloquea.
- **Destino de logs externos** (principio 7): `LogShipping:Enabled=false` hasta definirlo. Mientras tanto el estado
  `log_shipping = "disabled"` es visible en `/api/v1/status`. Opciones ya implementadas: `Http` (POST NDJSON) y `File` (JSONL en un recurso compartido).
- **Sysmon**: su configuración depende de la versión instalada; se incorpora en la Fase 8.
