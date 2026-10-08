# SEC-008 — Defender detecta malware o se desactiva

## Qué significa
Microsoft Defender Antivirus registró una detección de malware (1116), un error crítico al actuar (1119) o la desactivación de la protección en tiempo real/análisis (5001, 5010, 5012). Severidad crítica. *Los IDs deben confirmarse con datos reales en la Fase 8.*

## Cómo verificar
1. En la alerta: nombre de la amenaza (`target`), ruta (`detail`) y usuario.
2. `Get-MpThreatDetection | Select -Last 10`; `Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusSignatureLastUpdated`.
3. Si se desactivó: ¿quién y cuándo? (evento 5007 y los de cambio de directiva). Una desactivación sin cambio planificado se trata como intrusión.

## Contención
Si es malware: confirmar que Defender lo puso en cuarentena (`Get-MpThreat`); aislar el servidor si el archivo estaba en uso o hubo ejecución (SEC-010). Reactivar la protección en tiempo real (`Set-MpPreference -DisableRealtimeMonitoring $false`) y verificar que ninguna directiva la apaga.

## Erradicación
Análisis completo (`Start-MpScan -ScanType FullScan`), revisar persistencia (SEC-003/004), origen del archivo (descarga, usuario, app) y credenciales expuestas.

## Recuperación
Restaurar desde respaldo limpio si hay duda; actualizar firmas (`Update-MpSignature`).

## A quién avisar
Responsable de seguridad de inmediato; administrador de sistemas.
