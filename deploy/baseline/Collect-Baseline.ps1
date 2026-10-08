#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Fase 1: inventario de línea base de srv-copahue2. SOLO LECTURA: no cambia ninguna configuración.
.DESCRIPTION
  Recoge sistema, parches, cuentas, red y firewall, servicios y tareas, IIS, SQL Server, Defender, auditoría,
  actividad de inicios de sesión, apps de D:\Apps, respaldos y certificados. Deja un archivo de texto por área
  y un .zip en la carpeta de salida.
  NO lee contenido de archivos de configuración ni contraseñas; sí registra nombres de cuentas, IP y rutas:
  el resultado es SENSIBLE. No lo subas a git ni lo compartas en canales abiertos.
  Puede tardar varios minutos (lectura del registro de seguridad y reglas de firewall).
  Este script no se ha ejecutado todavía en Windows (solo se validó su sintaxis): revisa 00-resumen.txt al terminar.
.PARAMETER SqlInstance
  Instancia para sqlcmd (por defecto la instancia predeterminada: '.'). Para una nombrada: 'localhost\NOMBRE'.
.PARAMETER SkipSql
  No ejecutar consultas con sqlcmd (la información del registro de Windows se recoge igualmente).
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $env:TEMP ("baseline-{0}-{1:yyyyMMdd-HHmm}" -f $env:COMPUTERNAME, (Get-Date))),
    [string]$AppsRoot = 'D:\Apps',
    [string]$SqlInstance = '.',
    [int]$EventDays = 7,
    [int]$MaxEvents = 20000,
    [switch]$SkipSql
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("Servidor: $env:COMPUTERNAME   Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')   Usuario: $env:USERNAME")
$summary.Add("")

function Save-Section {
    param([string]$Name, [scriptblock]$Block)
    $file = Join-Path $OutDir ("{0}.txt" -f $Name)
    Write-Host "Recogiendo $Name ..."
    try {
        $out = & $Block 2>&1 | Out-String -Width 220
        Set-Content -Path $file -Value $out -Encoding UTF8
        $summary.Add("OK     $Name")
    } catch {
        Set-Content -Path $file -Value ("ERROR: " + $_.Exception.Message) -Encoding UTF8
        $summary.Add("ERROR  $Name : $($_.Exception.Message)")
    }
}

# ---------------------------------------------------------------- 01 Sistema
Save-Section '01-sistema' {
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime | Format-List
    Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, PartOfDomain, Manufacturer, Model, NumberOfLogicalProcessors, @{n='RAM_GB';e={[math]::Round($_.TotalPhysicalMemory / 1GB, 1)}} | Format-List
    Get-TimeZone | Format-List Id, DisplayName, BaseUtcOffset
    "PowerShell: $($PSVersionTable.PSVersion)"
    "--- Últimos parches instalados ---"
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, Description, InstalledOn | Format-Table -AutoSize
    Get-Service wuauserv | Format-Table Name, Status, StartType
    "--- Runtimes .NET instalados ---"
    if (Get-Command dotnet -ErrorAction SilentlyContinue) { dotnet --list-runtimes } else { 'dotnet no está en el PATH' }
}

# ---------------------------------------------------------------- 02 Discos
Save-Section '02-discos' {
    Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } |
        Select-Object DriveLetter, FileSystemLabel, FileSystem, @{n='Total_GB';e={[math]::Round($_.Size / 1GB, 1)}}, @{n='Libre_GB';e={[math]::Round($_.SizeRemaining / 1GB, 1)}} |
        Format-Table -AutoSize
}

# ---------------------------------------------------------------- 03 Cuentas
Save-Section '03-cuentas' {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, PasswordRequired | Format-Table -AutoSize
    # Por SID: los nombres de los grupos cambian según el idioma de Windows.
    $groups = @(
        @{ Sid = 'S-1-5-32-544'; Label = 'Administradores' },
        @{ Sid = 'S-1-5-32-555'; Label = 'Usuarios de escritorio remoto' },
        @{ Sid = 'S-1-5-32-573'; Label = 'Lectores del registro de eventos' },
        @{ Sid = 'S-1-5-32-551'; Label = 'Operadores de copia de seguridad' }
    )
    foreach ($g in $groups) {
        "--- Grupo: $($g.Label) ---"
        try {
            $grp = Get-LocalGroup -SID $g.Sid
            Get-LocalGroupMember -Group $grp.Name | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize
        } catch { "No disponible: $($_.Exception.Message)" }
    }
    "--- Política de contraseñas y bloqueo de cuentas ---"
    net accounts
}

# ---------------------------------------------------------------- 04 Red y firewall
Save-Section '04-red-y-firewall' {
    "--- Direcciones IP ---"
    Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize
    "--- Puertos TCP en escucha (con proceso) ---"
    $procs = @{}
    Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, @{n='Proceso';e={$procs[[int]$_.OwningProcess]}} | Format-Table -AutoSize
    "--- Perfiles del Firewall de Windows ---"
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName | Format-Table -AutoSize
    "--- Reglas de ENTRADA habilitadas que PERMITEN, con puerto (puede tardar) ---"
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | ForEach-Object {
        $pf = $_ | Get-NetFirewallPortFilter
        $af = $_ | Get-NetFirewallAddressFilter
        [pscustomobject]@{
            Nombre      = $_.DisplayName
            Perfil      = $_.Profile
            Protocolo   = $pf.Protocol
            PuertoLocal = ($pf.LocalPort -join ',')
            Remoto      = ($af.RemoteAddress -join ',')
        }
    } | Where-Object { $_.PuertoLocal -and $_.PuertoLocal -ne 'Any' } | Sort-Object PuertoLocal | Format-Table -AutoSize
    "--- Escritorio remoto (RDP) ---"
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdp = "$ts\WinStations\RDP-Tcp"
    "fDenyTSConnections (0 = RDP habilitado): " + (Get-ItemProperty $ts).fDenyTSConnections
    "UserAuthentication (1 = NLA exigido):    " + (Get-ItemProperty $rdp).UserAuthentication
    "PortNumber:                              " + (Get-ItemProperty $rdp).PortNumber
    "--- SMB y administración remota ---"
    Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature | Format-List
    Get-SmbShare | Select-Object Name, Path, Description | Format-Table -AutoSize
    Get-Service WinRM | Format-Table Name, Status, StartType
}

# ---------------------------------------------------------------- 05 Servicios y 06 tareas
Save-Section '05-servicios' {
    Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -or $_.StartMode -eq 'Auto' } | Sort-Object Name |
        Select-Object Name, State, StartMode, StartName, PathName | Format-Table -AutoSize -Wrap
}

Save-Section '06-tareas-programadas' {
    Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
        $acciones = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
        [pscustomobject]@{ Ruta = $_.TaskPath; Tarea = $_.TaskName; Estado = $_.State; Usuario = $_.Principal.UserId; Accion = $acciones }
    } | Format-List
}

# ---------------------------------------------------------------- 07 IIS
Save-Section '07-iis' {
    if (-not (Get-Module -ListAvailable WebAdministration)) { 'IIS (módulo WebAdministration) no está instalado'; return }
    Import-Module WebAdministration
    "--- Sitios ---"
    Get-Website | Select-Object Name, State, PhysicalPath, @{n='Enlaces';e={($_.Bindings.Collection | ForEach-Object { "$($_.protocol)://$($_.bindingInformation)" }) -join '; '}} | Format-List
    "--- App Pools ---"
    Get-ChildItem IIS:\AppPools | Select-Object Name, State, managedRuntimeVersion, @{n='Identidad';e={$_.processModel.identityType}}, @{n='Usuario';e={$_.processModel.userName}} | Format-Table -AutoSize
    "--- Registro de IIS por sitio (formato, campos, carpeta, tamaño actual) ---"
    foreach ($s in (Get-Website)) {
        $dir = [Environment]::ExpandEnvironmentVariables($s.logFile.directory)
        $size = 'carpeta no encontrada'
        if (Test-Path $dir) {
            $m = Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum
            $size = "{0} MB en {1} archivos" -f [math]::Round($m.Sum / 1MB, 1), $m.Count
        }
        [pscustomobject]@{ Sitio = $s.Name; Carpeta = $dir; Formato = $s.logFile.logFormat; Campos = $s.logFile.logExtFileFlags; Rotacion = $s.logFile.period; Tamano = $size } | Format-List
    }
    "--- Campos personalizados del log (¿CF-Connecting-IP?) ---"
    try {
        "Por defecto del servidor:"
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/logFile/customFields' -Name Collection |
            Select-Object logFieldName, sourceName, sourceType | Format-Table -AutoSize
        foreach ($s in (Get-Website)) {
            "Sitio $($s.Name):"
            Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/site[@name='$($s.Name)']/logFile/customFields" -Name Collection |
                Select-Object logFieldName, sourceName, sourceType | Format-Table -AutoSize
        }
    } catch { "No se pudo leer: $($_.Exception.Message)" }
    "--- Enlaces SSL ---"
    Get-ChildItem IIS:\SslBindings | Select-Object IPAddress, Port, Host, Thumbprint | Format-Table -AutoSize
    "--- Túnel de Cloudflare ---"
    $cf = Get-Service cloudflared* -ErrorAction SilentlyContinue
    if ($cf) { $cf | Format-Table Name, Status, StartType } else { 'No hay servicio cloudflared en este servidor' }
}

# ---------------------------------------------------------------- 08 SQL Server
Save-Section '08-sql-server' {
    $root = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
    $names = Get-ItemProperty "$root\Instance Names\SQL" -ErrorAction SilentlyContinue
    if (-not $names) { 'No se encontró SQL Server en el registro'; return }
    foreach ($p in ($names.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
        $inst = $p.Name
        $id = $p.Value
        "=== Instancia: $inst (id $id) ==="
        $setup = Get-ItemProperty "$root\$id\Setup" -ErrorAction SilentlyContinue
        "Edición:         $($setup.Edition)"
        "Versión:         $($setup.Version)"
        "Nivel de parche: $($setup.PatchLevel)"
        "Ruta de datos:   $($setup.SQLDataRoot)"
        $srv = Get-ItemProperty "$root\$id\MSSQLServer" -ErrorAction SilentlyContinue
        "LoginMode (1 = solo Windows, 2 = mixto):          $($srv.LoginMode)"
        "AuditLevel (0 ninguno, 1 correctos, 2 fallidos, 3 ambos): $($srv.AuditLevel)"
        "Carpeta de respaldos por defecto: $($srv.BackupDirectory)"
        $tcp = Get-ItemProperty "$root\$id\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -ErrorAction SilentlyContinue
        "Puerto TCP: $($tcp.TcpPort)  (puertos dinámicos: $($tcp.TcpDynamicPorts))"
        $log = Join-Path $setup.SQLDataRoot 'Log\ERRORLOG'
        "ERRORLOG: $log   existe: $(Test-Path $log)"
        if (Test-Path $log) {
            $i = Get-Item $log
            "   tamaño: $([math]::Round($i.Length / 1MB, 2)) MB   modificado: $($i.LastWriteTime)"
            try {
                $fs = [System.IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
                $b = New-Object byte[] 2
                [void]$fs.Read($b, 0, 2)
                $fs.Close()
                "   primeros 2 bytes: $($b -join ' ')   (255 254 = UTF-16 con BOM, lo esperado)"
            } catch { "   no se pudo leer la cabecera: $($_.Exception.Message)" }
        }
        if ($srv.BackupDirectory -and (Test-Path $srv.BackupDirectory)) {
            "--- Archivos más recientes en la carpeta de respaldos ---"
            Get-ChildItem $srv.BackupDirectory -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending |
                Select-Object -First 8 FullName, Length, LastWriteTime | Format-Table -AutoSize
        }
    }
    "--- Consultas con sqlcmd (autenticación de Windows, solo SELECT) ---"
    $sqlcmd = Get-Command sqlcmd -ErrorAction SilentlyContinue
    if ($SkipSql) {
        'Omitido por -SkipSql'
    } elseif (-not $sqlcmd) {
        'sqlcmd no está instalado: se omiten las consultas (con la información del registro basta para la Fase 1).'
    } else {
        $q = @"
SET NOCOUNT ON;
SELECT CAST(SERVERPROPERTY('Edition') AS nvarchar(100)) AS Edicion, CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(50)) AS Version, CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(50)) AS Nivel;
SELECT d.name AS BaseDeDatos, d.recovery_model_desc AS Recuperacion, MAX(b.backup_finish_date) AS UltimoRespaldoCompleto FROM sys.databases d LEFT JOIN msdb.dbo.backupset b ON b.database_name = d.name AND b.type = 'D' WHERE d.database_id > 4 GROUP BY d.name, d.recovery_model_desc ORDER BY d.name;
SELECT name AS Login, type_desc AS Tipo, is_disabled AS Deshabilitado FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%' ORDER BY name;
SELECT sp.name AS MiembroSysadmin FROM sys.server_role_members rm JOIN sys.server_principals sp ON sp.principal_id = rm.member_principal_id WHERE rm.role_principal_id = SUSER_ID('sysadmin');
"@
        sqlcmd -S $SqlInstance -E -C -l 10 -t 20 -W -Q $q
    }
}

# ---------------------------------------------------------------- 09 Defender
Save-Section '09-defender' {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        'Microsoft Defender no está disponible (¿otro antivirus?). Productos registrados:'
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue | Select-Object displayName
        return
    }
    Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime | Format-List
    $pref = Get-MpPreference
    "--- Exclusiones configuradas ---"
    "Rutas:       " + ($pref.ExclusionPath -join '; ')
    "Extensiones: " + ($pref.ExclusionExtension -join '; ')
    "Procesos:    " + ($pref.ExclusionProcess -join '; ')
    "--- Directivas que desactivan Defender ---"
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue | Select-Object DisableAntiSpyware, DisableAntiVirus | Format-List
    "--- IDs de evento registrados en los últimos 30 días (para confirmar los IDs de SEC-008) ---"
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; StartTime = (Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue |
        Group-Object Id | Sort-Object { [int]$_.Name } | Select-Object Count, Name | Format-Table -AutoSize
    "--- Últimas detecciones ---"
    Get-MpThreatDetection | Select-Object -Last 10 InitialDetectionTime, ThreatID, ProcessName, Resources | Format-List
}

# ---------------------------------------------------------------- 10 Auditoría y registros
Save-Section '10-auditoria-y-registros' {
    "--- Auditoría de inicios de sesión (subcategoría Logon, por GUID) ---"
    auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /r
    "--- Directiva de auditoría completa ---"
    auditpol /get /category:*
    "--- Registros de eventos: tamaño y retención ---"
    Get-WinEvent -ListLog Security, System, Application | Select-Object LogName, LogMode, @{n='Max_MB';e={[math]::Round($_.MaximumSizeInBytes / 1MB, 0)}}, RecordCount | Format-Table -AutoSize
    "--- Sysmon ---"
    $sm = Get-Service Sysmon* -ErrorAction SilentlyContinue
    if ($sm) { $sm | Format-Table Name, Status } else { 'Sysmon no está instalado' }
    Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Select-Object LogName, IsEnabled, RecordCount | Format-List
    "--- Línea de comandos en eventos de proceso 4688 (1 = activada) ---"
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
}

# ---------------------------------------------------------------- 11 Actividad de inicios de sesión
Save-Section '11-actividad-de-logon' {
    $start = (Get-Date).AddDays(-$EventDays)
    function Get-LogonSummary {
        param([int]$Id, [string]$Label, [string]$GroupProperty, [scriptblock]$Filter)
        "--- $Label (últimos $EventDays días; máx. $MaxEvents eventos) ---"
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Id; StartTime = $start } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        if (-not $ev) { 'Sin eventos (¿auditoría desactivada o sin actividad?)'; return }
        "Eventos leídos: $($ev.Count)"
        $ev | ForEach-Object {
            $x = [xml]$_.ToXml()
            $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            [pscustomobject]@{ Ip = $d['IpAddress']; Usuario = $d['TargetUserName']; Tipo = $d['LogonType'] }
        } | Where-Object { & $Filter $_ } | Group-Object $GroupProperty | Sort-Object Count -Descending | Select-Object -First 25 Count, Name | Format-Table -AutoSize
    }
    Get-LogonSummary -Id 4625 -Label 'FALLIDOS (4625) por IP de origen' -GroupProperty 'Ip' -Filter { param($r) $true }
    Get-LogonSummary -Id 4625 -Label 'FALLIDOS (4625) por cuenta probada' -GroupProperty 'Usuario' -Filter { param($r) $true }
    Get-LogonSummary -Id 4624 -Label 'CORRECTOS por RDP (tipo 10), por IP de origen (candidatas a IP de administración)' -GroupProperty 'Ip' -Filter { param($r) $r.Tipo -eq '10' }
    Get-LogonSummary -Id 4624 -Label 'CORRECTOS por red (tipo 3), por IP de origen' -GroupProperty 'Ip' -Filter { param($r) $r.Tipo -eq '3' -and $r.Ip -and $r.Ip -ne '-' }
}

# ---------------------------------------------------------------- 12 Apps
Save-Section '12-apps' {
    if (-not (Test-Path $AppsRoot)) { "No existe $AppsRoot"; return }
    Get-ChildItem $AppsRoot -Directory | ForEach-Object {
        $files = @(Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue)
        $last = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        [pscustomobject]@{
            App                   = $_.Name
            Archivos              = $files.Count
            MB                    = [math]::Round((($files | Measure-Object Length -Sum).Sum) / 1MB, 1)
            UltimaModificacion    = $last.LastWriteTime
            WebConfig             = @($files | Where-Object { $_.Name -eq 'web.config' }).Count
            AppSettingsProduction = @($files | Where-Object { $_.Name -eq 'appsettings.Production.json' }).Count
        }
    } | Format-Table -AutoSize
    "--- Permisos de $AppsRoot ---"
    icacls $AppsRoot
}

# ---------------------------------------------------------------- 13 Respaldos
Save-Section '13-respaldos' {
    "--- Tareas programadas cuyo nombre sugiere respaldo ---"
    Get-ScheduledTask | Where-Object { $_.TaskName -match 'backup|respaldo|bak' } | Select-Object TaskPath, TaskName, State | Format-Table -AutoSize
    "--- Servicios de respaldo ---"
    Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'backup|veeam|acronis|cobian' -or $_.DisplayName -match 'backup|respaldo' } | Select-Object Name, State, PathName | Format-Table -AutoSize
    "--- Windows Server Backup ---"
    if (Get-Command Get-WBSummary -ErrorAction SilentlyContinue) { Get-WBSummary | Format-List } else { 'Windows Server Backup no está instalado' }
    "--- Copias de volumen (VSS) ---"
    vssadmin list shadowstorage
}

# ---------------------------------------------------------------- 14 Certificados
Save-Section '14-certificados' {
    foreach ($store in 'My', 'WebHosting') {
        "--- LocalMachine\$store ---"
        Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue | Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey | Format-Table -AutoSize
    }
}

# ---------------------------------------------------------------- Cierre
$summary.Add("")
$summary.Add("Carpeta de salida: $OutDir")
Set-Content -Path (Join-Path $OutDir '00-resumen.txt') -Value $summary -Encoding UTF8
try {
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath ($OutDir + '.zip') -Force
    Write-Host "Listo. Archivos en $OutDir y comprimido en $OutDir.zip"
} catch {
    Write-Warning "No se pudo crear el .zip: $($_.Exception.Message). Los archivos están en $OutDir"
}
Write-Host "Revisa 00-resumen.txt: cada área debe decir OK. El resultado es sensible: no lo subas a git."
