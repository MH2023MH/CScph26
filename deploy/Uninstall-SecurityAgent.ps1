#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Desinstala el servicio SecurityAgent y retira todo bloqueo que haya puesto en el firewall.
.DESCRIPTION
  Por defecto CONSERVA la carpeta de instalación (incluida data\agent.db y logs\) para análisis posterior.
  Use -RemoveFiles para borrarla. Soporta -WhatIf. NO ha sido ejecutado todavía en Windows.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$InstallDir = 'D:\Apps\SecurityAgent',
    [string]$ServiceName = 'SecurityAgent',
    [switch]$RemoveFiles
)
$ErrorActionPreference = 'Stop'
$account = "NT SERVICE\$ServiceName"

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Detener y eliminar el servicio')) {
        if ($svc.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force; $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
        & sc.exe delete $ServiceName | Out-Null
    }
}

if ($PSCmdlet.ShouldProcess('Windows Firewall', 'Eliminar reglas CScph26 (bloqueos y puerto de la API)')) {
    Get-NetFirewallRule -DisplayName 'CScph26-block-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -DisplayName "CScph26 StatusApi ($ServiceName)" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

if ($PSCmdlet.ShouldProcess('Event Log Readers', "Quitar $account")) {
    & net.exe localgroup 'Event Log Readers' $account /delete 2>&1 | Out-Null
}

if ($RemoveFiles -and (Test-Path $InstallDir)) {
    if ($PSCmdlet.ShouldProcess($InstallDir, 'Eliminar la carpeta de instalación (incluye agent.db y logs)')) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
    }
}
Write-Host 'Desinstalación completada.'
