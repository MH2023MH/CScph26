#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Instala (o actualiza) el servicio SecurityAgent en srv-copahue2 con privilegios mínimos.
.DESCRIPTION
  - Carpeta propia (por defecto D:\Apps\SecurityAgent); no toca IIS, puertos, App Pools ni bases de otras apps (principio 6).
  - Cuenta de servicio virtual "NT SERVICE\<nombre>": sin contraseña, sin acceso interactivo, sin permisos de administrador.
  - ACL estrictas: la cuenta del servicio solo LEE binarios, reglas y configuración; solo escribe en data\ y logs\.
  - Crea el manifiesto de integridad (SHA-256 de binarios, reglas y configuración) tras copiar los archivos.
  - Soporta -WhatIf (no cambia nada) y -Verbose.
  NOTA: este script NO ha sido ejecutado todavía en Windows (la Fase 7 se desarrolló sin una VM de prueba).
  Pruébelo primero con -WhatIf y luego en una VM antes de usarlo en srv-copahue2 (Fase 8).
.PARAMETER PublishDir
  Salida de: dotnet publish src/SecurityAgent.Worker -c Release -r win-x64 --self-contained false -o <PublishDir>
.PARAMETER ConfigFile
  appsettings.Production.json ya preparado (contiene secretos: SMTP, webhook, token, clave HMAC). Se copia con ACL restringida.
.PARAMETER AdvisorAddress
  IP del equipo del sistema 2. Si se indica, se abre el puerto de la API de estado SOLO para esa IP.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$PublishDir,
    [string]$InstallDir = 'D:\Apps\SecurityAgent',
    [string]$ServiceName = 'SecurityAgent',
    [string]$ConfigFile = '',
    [string]$IisLogRoot = 'C:\inetpub\logs\LogFiles',
    [string]$SqlLogDir = '',
    [string]$AppsRoot = 'D:\Apps',
    [string]$AdvisorAddress = '',
    [int]$ApiPort = 8750,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$exeName = 'SecurityAgent.Worker.exe'
$account = "NT SERVICE\$ServiceName"

function Invoke-Step {
    param([string]$Description, [scriptblock]$Action)
    if ($PSCmdlet.ShouldProcess($InstallDir, $Description)) {
        Write-Verbose $Description
        & $Action
    }
}

function Assert-ExitCode {
    param([string]$What)
    if ($LASTEXITCODE -ne 0) { throw "$What falló (código $LASTEXITCODE)" }
}

# ---- Validaciones ----
if (-not (Test-Path (Join-Path $PublishDir $exeName))) { throw "No se encontró $exeName en $PublishDir" }
if ($ConfigFile -ne '' -and -not (Test-Path $ConfigFile)) { throw "No existe el archivo de configuración: $ConfigFile" }
$drive = Split-Path -Qualifier $InstallDir
if (-not (Test-Path $drive)) { throw "La unidad $drive no existe" }

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

# ---- 1. Detener el servicio si es una actualización ----
if ($existing -and $existing.Status -ne 'Stopped') {
    Invoke-Step "Detener el servicio $ServiceName" {
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}

# ---- 2. Carpetas y archivos ----
Invoke-Step "Crear carpetas en $InstallDir" {
    New-Item -ItemType Directory -Force -Path $InstallDir, (Join-Path $InstallDir 'data'), (Join-Path $InstallDir 'logs') | Out-Null
}
Invoke-Step "Copiar binarios y reglas desde $PublishDir (data\ y logs\ no se tocan)" {
    Get-ChildItem -Path $PublishDir -Force | Where-Object { $_.Name -notin @('data', 'logs') } |
        Copy-Item -Destination $InstallDir -Recurse -Force
}
if ($ConfigFile -ne '') {
    Invoke-Step "Copiar la configuración de producción" {
        Copy-Item -Path $ConfigFile -Destination (Join-Path $InstallDir 'appsettings.Production.json') -Force
    }
}

# ---- 2b. Fuente del registro de eventos de Windows (la cuenta del servicio no tiene permiso para crearla) ----
Invoke-Step "Registrar la fuente '$ServiceName' en el registro de eventos de Windows (Application)" {
    if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {
        New-EventLog -LogName Application -Source $ServiceName
    }
}

# ---- 3. Servicio con cuenta virtual ----
if (-not $existing) {
    Invoke-Step "Crear el servicio $ServiceName" {
        New-Service -Name $ServiceName -BinaryPathName ('"{0}"' -f (Join-Path $InstallDir $exeName)) `
            -DisplayName 'CScph26 SecurityAgent' `
            -Description 'Monitor de seguridad de srv-copahue2: detecta y alerta; los bloqueos son acotados y reversibles.' `
            -StartupType Automatic | Out-Null
    }
}
Invoke-Step "Configurar la cuenta virtual $account y la recuperación automática" {
    & sc.exe config $ServiceName obj= $account | Out-Null; Assert-ExitCode 'sc config obj'
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null; Assert-ExitCode 'sc failure'
}

# ---- 4. ACL (principio 4 y 8) ----
Invoke-Step "Aplicar ACL estrictas en $InstallDir" {
    & icacls.exe $InstallDir /inheritance:r | Out-Null; Assert-ExitCode 'icacls inheritance'
    & icacls.exe $InstallDir /grant:r 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' "${account}:(OI)(CI)RX" | Out-Null
    Assert-ExitCode 'icacls base'
    foreach ($sub in @('data', 'logs')) {
        & icacls.exe (Join-Path $InstallDir $sub) /grant:r "${account}:(OI)(CI)M" | Out-Null; Assert-ExitCode "icacls $sub"
    }
    $cfg = Join-Path $InstallDir 'appsettings.Production.json'
    if (Test-Path $cfg) {
        & icacls.exe $cfg /inheritance:r /grant:r 'NT AUTHORITY\SYSTEM:F' 'BUILTIN\Administrators:F' "${account}:R" | Out-Null
        Assert-ExitCode 'icacls config'
    }
}

# ---- 5. Permisos de LECTURA sobre las fuentes (nunca escritura) ----
Invoke-Step "Permitir a $account leer el Event Log (grupo Event Log Readers)" {
    & net.exe localgroup 'Event Log Readers' $account /add 2>&1 | Out-Null   # si ya es miembro, net devuelve error 2: se ignora
}
foreach ($src in @(@{ Path = $IisLogRoot; Why = 'logs de IIS' }, @{ Path = $SqlLogDir; Why = 'ERRORLOG de SQL Server' }, @{ Path = $AppsRoot; Why = 'archivos de las apps (SEC-006)' })) {
    if ($src.Path -ne '' -and (Test-Path $src.Path)) {
        Invoke-Step "Conceder lectura sobre $($src.Why): $($src.Path)" {
            & icacls.exe $src.Path /grant "${account}:(OI)(CI)RX" | Out-Null; Assert-ExitCode "icacls $($src.Why)"
        }
    } else {
        Write-Warning "Se omite $($src.Why): ruta no indicada o inexistente ($($src.Path))"
    }
}

# ---- 6. Manifiesto de integridad ----
Invoke-Step "Generar el manifiesto de integridad" {
    & (Join-Path $InstallDir $exeName) --make-manifest; Assert-ExitCode 'make-manifest'
}

# ---- 7. Puerto de la API de estado solo para el equipo del sistema 2 ----
if ($AdvisorAddress -ne '') {
    Invoke-Step "Abrir TCP $ApiPort solo para $AdvisorAddress" {
        $rule = "CScph26 StatusApi ($ServiceName)"
        Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP -LocalPort $ApiPort `
            -RemoteAddress $AdvisorAddress -Action Allow | Out-Null
    }
}

# ---- 8. Arranque ----
if (-not $NoStart) {
    Invoke-Step "Iniciar el servicio $ServiceName" {
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
}
Write-Host "Listo. Siguiente: revisar el estado con la API (/api/v1/status) y confirmar que todas las reglas están en 'observe'."
