# Despliegue de SecurityAgent (srv-copahue2)

> Estado: scripts **escritos pero no ejecutados en Windows**. El criterio de salida de la Fase 7 ("probados en una VM de prueba")
> queda pendiente. Probar siempre primero con `-WhatIf`, luego en una VM, y recién después en el servidor (Fase 8).

## 1. Publicar
```powershell
dotnet publish src/SecurityAgent.Worker -c Release -r win-x64 --self-contained false -o publish
```
Requiere el runtime **.NET 8 (ASP.NET Core Runtime)** instalado en el servidor.

## 2. Preparar la configuración
Copiar `appsettings.Production.example.json` a `appsettings.Production.json`, completar los secretos y guardarlo **fuera de git**
(está en `.gitignore`). Secretos: token de la API, SMTP, webhook de Teams, clave HMAC del manifiesto, token del destino de logs.

## 3. Instalar
```powershell
.\Install-SecurityAgent.ps1 -PublishDir .\publish -ConfigFile .\appsettings.Production.json `
    -SqlLogDir 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log' -AdvisorAddress 192.168.X.X -WhatIf
```
Quitar `-WhatIf` para aplicar. El script: crea la carpeta, copia archivos, crea el servicio con cuenta virtual
`NT SERVICE\SecurityAgent`, aplica ACL (el servicio solo **lee** binarios/reglas/config; solo escribe en `data\` y `logs\`),
concede lectura sobre las fuentes, genera el manifiesto de integridad y arranca el servicio.

## 4. Verificar integridad en cualquier momento
```powershell
D:\Apps\SecurityAgent\SecurityAgent.Worker.exe --verify-manifest      # código de salida 0 = íntegro, 2 = violado
```
Tras una actualización legítima hay que regenerar el manifiesto (`--make-manifest`); el instalador ya lo hace.

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
