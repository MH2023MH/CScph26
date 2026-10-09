#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Prueba de extremo a extremo del instalador en un Windows REAL (máquina de CI o VM de pruebas).
.DESCRIPTION
  Ejecuta deploy\Install-SecurityAgent.ps1 de verdad (primero con -WhatIf), comprueba el servicio con su cuenta virtual,
  las ACL, la API de estado, la detección de eventos reales (cuenta nueva, servicio, tarea, cambio de archivo), la
  verificación de integridad, los comandos de CLI y la desinstalación. Sale con código 1 si algo falla.
  CAMBIA el equipo (crea una cuenta local de prueba, un servicio, una tarea y un servicio de Windows): úsese SOLO en una VM
  desechable o en CI, nunca en srv-copahue2.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PublishDir,
    [string]$WorkDir = 'C:\cscph26-test',
    [string]$ServiceName = 'SecurityAgent',
    [int]$ApiPort = 8750
)

$ErrorActionPreference = 'Stop'
$script:failures = New-Object System.Collections.Generic.List[string]
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installScript = Join-Path $repo 'deploy\Install-SecurityAgent.ps1'
$uninstallScript = Join-Path $repo 'deploy\Uninstall-SecurityAgent.ps1'
$install = Join-Path $WorkDir 'SecurityAgent'
$apps = Join-Path $WorkDir 'apps'
$account = "NT SERVICE\$ServiceName"
$token = 'ci-' + [guid]::NewGuid().ToString('N')
$hmac = 'hmac-' + [guid]::NewGuid().ToString('N')
$exe = Join-Path $install 'SecurityAgent.Worker.exe'

function Step([string]$name) { Write-Host ""; Write-Host "=== $name ===" -ForegroundColor Cyan }
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  OK    $msg" } else { Write-Host "  FALLO $msg" -ForegroundColor Red; $script:failures.Add($msg) }
}
function Wait-Until([scriptblock]$Condition, [int]$TimeoutSec = 60, [int]$EverySec = 2) {
    $end = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $end) {
        try { if (& $Condition) { return $true } } catch { }
        Start-Sleep -Seconds $EverySec
    }
    return $false
}

Add-Type -AssemblyName System.Net.Http
$http = New-Object System.Net.Http.HttpClient
$http.Timeout = [TimeSpan]::FromSeconds(10)
function Call-Api([string]$path, [string]$bearer = $token, [string]$method = 'GET') {
    $req = New-Object System.Net.Http.HttpRequestMessage -ArgumentList (New-Object System.Net.Http.HttpMethod($method)), "http://127.0.0.1:$ApiPort$path"
    if ($bearer) { $req.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $bearer) }
    try {
        $resp = $http.SendAsync($req).GetAwaiter().GetResult()
        $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return [pscustomobject]@{ Code = [int]$resp.StatusCode; Body = $body }
    } catch { return [pscustomobject]@{ Code = 0; Body = $_.Exception.Message } }
}
function Api-Json([string]$path) {
    $r = Call-Api $path
    if ($r.Code -ne 200) { return $null }
    return $r.Body | ConvertFrom-Json
}
function Alerts-For([string]$rule) {
    $j = Api-Json "/api/v1/alerts?rule=$rule&limit=50"
    if ($null -eq $j) { return @() }
    return @($j.items)
}

function Show-Diagnostics {
    Write-Host ""; Write-Host "--- DIAGNÓSTICO ---" -ForegroundColor Yellow
    Get-Service $ServiceName -ErrorAction SilentlyContinue | Format-List Name, Status, StartType
    Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue | Format-List Name, State, StartName, PathName, ExitCode
    Write-Host "--- Estado de la API (si el servicio sigue activo) ---"
    $r = Call-Api '/api/v1/status'
    Write-Host ("HTTP " + $r.Code + "  " + $r.Body)
    Write-Host "--- Resumen de agent.db (--stats) ---"
    if (Test-Path $exe) { & $exe --stats | Out-Host }
    try {
        Write-Host "--- Registro de la aplicación SecurityAgent (Windows Application log) ---"
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $ServiceName } -MaxEvents 60 -ErrorAction Stop |
            Sort-Object TimeCreated | ForEach-Object { "{0:HH:mm:ss} {1,-11} {2}" -f $_.TimeCreated, $_.LevelDisplayName, ($_.Message -replace '\s+', ' ') } | Out-Host
    } catch { Write-Host "Sin eventos de $ServiceName." }
}

function Invoke-Flow {
    # ------------------------------------------------------------------ Preparación
    Step 'Preparación'
    if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path (Join-Path $apps 'shop') | Out-Null
    Set-Content (Join-Path $apps 'shop\web.config') '<configuration/>'
    foreach ($g in '{0CCE9215-69AE-11D9-BED3-505054503030}', '{0CCE9235-69AE-11D9-BED3-505054503030}', '{0CCE9237-69AE-11D9-BED3-505054503030}', '{0CCE9227-69AE-11D9-BED3-505054503030}') {
        & auditpol.exe /set /subcategory:$g /success:enable /failure:enable | Out-Null
    }
    $config = @{
        SecurityAgent = @{
            Store               = @{ DatabasePath = (Join-Path $install 'data\agent.db') }
            StatusApi           = @{ Token = $token; Listen = "http://127.0.0.1:$ApiPort"; AllowedClients = @('127.0.0.1') }
            Integrity           = @{ HmacKey = $hmac; Interval = '00:00:05' }
            Collectors          = @{
                EventLog = @{ Channels = @('Security', 'System') }
                Iis      = @{ Root = 'C:\no-existe-iis' }
                Files    = @{ Roots = @($apps) }
            }
            PollInterval        = '00:00:02'
            MaintenanceInterval = '00:00:30'
            Audits              = @{ StartDelay = '00:00:05' }
        }
    }
    $cfgFile = Join-Path $WorkDir 'appsettings.Production.json'
    $config | ConvertTo-Json -Depth 8 | Set-Content -Path $cfgFile -Encoding UTF8
    Check (Test-Path (Join-Path $PublishDir 'SecurityAgent.Worker.exe')) 'el paquete publicado contiene SecurityAgent.Worker.exe'

    # ------------------------------------------------------------------ Ensayo (-WhatIf)
    Step 'Instalador con -WhatIf (no debe cambiar nada)'
    & $installScript -PublishDir $PublishDir -InstallDir $install -ConfigFile $cfgFile -AppsRoot $apps -IisLogRoot 'C:\no-existe-iis' -AdvisorAddress 127.0.0.1 -ApiPort $ApiPort -WhatIf | Out-Host
    Check (-not (Test-Path $install)) 'WhatIf no creó la carpeta de instalación'
    Check ($null -eq (Get-Service $ServiceName -ErrorAction SilentlyContinue)) 'WhatIf no creó el servicio'

    # ------------------------------------------------------------------ Instalación real
    Step 'Instalación real'
    & $installScript -PublishDir $PublishDir -InstallDir $install -ConfigFile $cfgFile -AppsRoot $apps -IisLogRoot 'C:\no-existe-iis' -AdvisorAddress 127.0.0.1 -ApiPort $ApiPort -Confirm:$false | Out-Host

    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    Check ($null -ne $svc) 'el servicio existe'
    Check ($svc.StartName -eq $account) "el servicio corre con la cuenta virtual $account (actual: $($svc.StartName))"
    Check ($svc.StartMode -eq 'Auto') 'inicio automático'
    Check (Wait-Until { (Get-Service $ServiceName).Status -eq 'Running' } 30) 'el servicio está en ejecución'
    Check (Test-Path (Join-Path $install 'rules\SEC-001.yaml')) 'las reglas se copiaron junto al binario'
    Check (Test-Path (Join-Path $install 'integrity.manifest.json')) 'existe el manifiesto de integridad'
    Check (Test-Path (Join-Path $install 'data')) 'existe la carpeta data'

    # ------------------------------------------------------------------ ACL y permisos
    Step 'ACL y permisos'
    $W = [System.Security.AccessControl.FileSystemRights]
    $rootAcl = (Get-Acl $install).Access
    $mine = @($rootAcl | Where-Object { $_.IdentityReference.Value -eq $account })
    Check ($mine.Count -gt 0) 'la cuenta del servicio tiene permisos en la carpeta de instalación'
    Check (($mine | Where-Object { ($_.FileSystemRights -band $W::Write) -ne 0 -or ($_.FileSystemRights -band $W::Modify) -eq $W::Modify }).Count -eq 0) 'la cuenta del servicio NO puede escribir en binarios ni reglas (solo lectura y ejecución)'
    Check (@($rootAcl | Where-Object { $_.IdentityReference.Value -match 'Everyone|BUILTIN\\Users|Authenticated Users' }).Count -eq 0) 'Users/Everyone no tienen acceso a la carpeta de instalación'
    Check ((Get-Acl $install).AreAccessRulesProtected) 'la herencia está desactivada en la carpeta de instalación'
    $dataAcl = @((Get-Acl (Join-Path $install 'data')).Access | Where-Object { $_.IdentityReference.Value -eq $account })
    Check (($dataAcl | Where-Object { ($_.FileSystemRights -band $W::Modify) -eq $W::Modify }).Count -gt 0) 'la cuenta del servicio puede modificar data\'
    $cfgAcl = @((Get-Acl (Join-Path $install 'appsettings.Production.json')).Access)
    Check (@($cfgAcl | Where-Object { $_.IdentityReference.Value -match 'Everyone|BUILTIN\\Users' }).Count -eq 0) 'el archivo de secretos no es legible por Users'
    Check (@(Get-LocalGroupMember -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$ServiceName" }).Count -eq 1) 'la cuenta pertenece a Event Log Readers'
    $fw = Get-NetFirewallRule -DisplayName "CScph26 StatusApi ($ServiceName)" -ErrorAction SilentlyContinue
    Check ($null -ne $fw) 'existe la regla de firewall del puerto de la API'
    if ($fw) {
        $pf = $fw | Get-NetFirewallPortFilter
        $af = $fw | Get-NetFirewallAddressFilter
        Check ($pf.LocalPort -eq "$ApiPort") 'la regla abre solo el puerto de la API'
        Check (($af.RemoteAddress -join ',') -eq '127.0.0.1') 'la regla solo admite la IP del asesor'
    }

    # ------------------------------------------------------------------ API de estado
    Step 'API de estado'
    $apiUp = Wait-Until { $r = Call-Api '/api/v1/status'; $r.Code -eq 200 -and ($r.Body | ConvertFrom-Json).heartbeat_at } 60
    Check $apiUp 'la API responde y el agente ya late'
    $status = Api-Json '/api/v1/status'
    if ($status) {
        Check ($status.rules.Count -ge 11) "el estado lista las reglas del catálogo ($($status.rules.Count))"
        Check (@($status.rules | Where-Object { $_.mode -ne 'observe' }).Count -eq 0) 'todas las reglas están en observe'
        Check ($status.log_shipping -eq 'disabled') 'el envío de logs figura como disabled (sin destino configurado)'
        Check (Wait-Until { (Api-Json '/api/v1/status').integrity -eq 'ok' } 30) 'integridad OK: la clave HMAC y los permisos de lectura de la cuenta de servicio son coherentes'
        $status = Api-Json '/api/v1/status'
        Write-Host ("  Problemas de recolección informados por el agente: " + (@($status.problems) -join ' | '))
        Check (@($status.problems | Where-Object { $_ -match 'eventlog:(Security|System)|^fs:' }).Count -eq 0) 'los canales Security y System y la carpeta vigilada se leen sin problemas (si falla, el motivo está en la línea anterior)'
    }
    Check ((Call-Api '/api/v1/status' '').Code -eq 401) 'sin token: 401'
    Check ((Call-Api '/api/v1/status' 'otro-token').Code -eq 401) 'token incorrecto: 401'
    Check ((Call-Api '/api/v1/status' $token 'POST').Code -in 404, 405) 'POST no está permitido'
    Check ((Call-Api '/api/v1/events/no-existe').Code -eq 404) 'ID inexistente: 404'

    # ------------------------------------------------------------------ Detección real con la cuenta de servicio
    Step 'Detección de eventos reales'
    try {
        & net.exe user cscph26ci 'Xx9!ciTemp1' /add | Out-Host
        & net.exe localgroup Administrators cscph26ci /add | Out-Host
        & sc.exe create CScph26CiSvc binPath= 'C:\Windows\System32\cmd.exe' start= demand | Out-Host
        Set-Content (Join-Path $apps 'shop\web.config') '<configuration><!-- cambio --></configuration>'

        Check (Wait-Until { (Alerts-For 'SEC-003').Count -ge 1 } 90) 'SEC-003: alerta por cuenta creada / agregada a Administradores (lee el log Security como cuenta virtual)'
        Check (Wait-Until { (Alerts-For 'SEC-004').Count -ge 1 } 90) 'SEC-004: alerta por servicio nuevo (log System)'
        Check (Wait-Until { (Alerts-For 'SEC-006').Count -ge 1 } 60) 'SEC-006: alerta por cambio de web.config (FileSystemWatcher)'

        $a = (Alerts-For 'SEC-003') | Select-Object -First 1
        if ($a) {
            Check ($a.mode -eq 'observe') 'la alerta se registró en modo observe'
            Check ($a.severity -eq 'critica') 'SEC-003 tiene severidad crítica'
            Check ($a.event_ids.Count -ge 1 -and (Call-Api "/api/v1/events/$($a.event_ids[0])").Code -eq 200) 'el evento citado por la alerta existe en la API (evidencia)'
            Check ((Call-Api "/api/v1/events/$($a.id)").Code -eq 200) 'la alerta se puede consultar por su ID'
        }
    } finally {
        & net.exe localgroup Administrators cscph26ci /delete | Out-Null
        & net.exe user cscph26ci /delete | Out-Null
        & sc.exe delete CScph26CiSvc | Out-Null
    }

    # ------------------------------------------------------------------ Integridad
    Step 'Integridad del agente'
    & $exe --verify-manifest | Out-Host
    Check ($LASTEXITCODE -eq 0) '--verify-manifest: código 0 con la instalación intacta'
    $ruleFile = Join-Path $install 'rules\SEC-001.yaml'
    $original = [System.IO.File]::ReadAllText($ruleFile)
    try {
        [System.IO.File]::WriteAllText($ruleFile, $original + "`n# alterado`n")
        & $exe --verify-manifest | Out-Host
        Check ($LASTEXITCODE -eq 2) '--verify-manifest: código 2 tras modificar una regla'
        Check (Wait-Until { (Api-Json '/api/v1/status').integrity -eq 'violated' } 45) 'la API informa integridad violated'
        Check (Wait-Until { @((Alerts-For 'SELF-INTEGRITY') | Where-Object { $_.severity -eq 'critica' }).Count -ge 1 } 45) 'alerta crítica SELF-INTEGRITY'
    } finally {
        [System.IO.File]::WriteAllText($ruleFile, $original)
    }
    Check (Wait-Until { (Api-Json '/api/v1/status').integrity -eq 'ok' } 45) 'restaurada la regla, la integridad vuelve a OK'

    # ------------------------------------------------------------------ CLI y doble llave
    Step 'CLI: bloqueos y aprobación de enforce'
    & $exe --list-blocks | Out-Host
    Check ($LASTEXITCODE -eq 0) '--list-blocks'
    & $exe --unblock-ip 203.0.113.99 | Out-Host
    Check ($LASTEXITCODE -eq 0) '--unblock-ip con una IP sin bloqueo (idempotente)'
    & $exe --unblock-ip 'no-es-ip' | Out-Host
    Check ($LASTEXITCODE -eq 1) '--unblock-ip rechaza una entrada inválida'
    & $exe --set-mode SEC-001 enforce | Out-Host
    Check ($LASTEXITCODE -eq 0) '--set-mode SEC-001 enforce guarda la aprobación'
    $rule = Api-Json '/api/v1/rules/SEC-001'
    Check ($rule.mode -eq 'observe' -and $rule.file_mode -eq 'observe') 'doble llave: con el YAML en observe la regla sigue en observe aunque haya aprobación'
    & $exe --set-mode SEC-001 observe | Out-Host

    # ------------------------------------------------------------------ Recursos
    Step 'Límites de recursos'
    $proc = Get-Process -Name 'SecurityAgent.Worker' -ErrorAction SilentlyContinue | Select-Object -First 1
    Check ($null -ne $proc) 'el proceso del servicio está en ejecución'
    if ($proc) { Check ($proc.PriorityClass -eq 'BelowNormal') "prioridad baja (actual: $($proc.PriorityClass))" }

    # ------------------------------------------------------------------ Desinstalación
    Step 'Desinstalación'
    & $uninstallScript -InstallDir $install -Confirm:$false | Out-Host
    Check (Wait-Until { $null -eq (Get-Service $ServiceName -ErrorAction SilentlyContinue) } 30) 'el servicio fue eliminado'
    Check ($null -eq (Get-NetFirewallRule -DisplayName "CScph26 StatusApi ($ServiceName)" -ErrorAction SilentlyContinue)) 'se retiró la regla de firewall de la API'
    Check (@(Get-LocalGroupMember -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$ServiceName" }).Count -eq 0) 'se retiró la cuenta de Event Log Readers'
    Check (Test-Path (Join-Path $install 'data\agent.db')) 'la base de datos se conserva (sin -RemoveFiles)'
}

try { Invoke-Flow }
catch {
    Write-Host "EXCEPCIÓN: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    $script:failures.Add("excepción: $($_.Exception.Message)")
}

Show-Diagnostics
# limpieza best-effort por si el flujo se interrumpió (cmd /c evita que PowerShell trate la salida de error como excepción)
$ErrorActionPreference = 'Continue'
cmd.exe /c "net user cscph26ci /delete >nul 2>nul"
cmd.exe /c "sc.exe delete CScph26CiSvc >nul 2>nul"

Write-Host ""
if ($script:failures.Count -eq 0) { Write-Host "TODAS LAS COMPROBACIONES PASARON" -ForegroundColor Green; exit 0 }
Write-Host "$($script:failures.Count) comprobación(es) fallida(s):" -ForegroundColor Red
$script:failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
exit 1
