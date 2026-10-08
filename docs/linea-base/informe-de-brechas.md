# Informe de brechas — srv-copahue2

> Rellenar **fuera del repositorio** o sin datos sensibles (sin nombres de cuenta ni IP reales).
> Fecha: ____  Responsable: ____  Edición de Windows Server: ____  Edición de SQL Server: ____

## Resumen ejecutivo
- Estado general (3 líneas): ____
- Brechas de riesgo **alto**: ____ · **medio**: ____ · **bajo**: ____
- ¿Hay indicios de actividad hostil ya en curso (archivo `11-actividad-de-logon`)? ____

## Hallazgos
| # | Área | Hallazgo | Evidencia (archivo) | Riesgo | Recomendación | Responsable | Plazo |
|---|---|---|---|---|---|---|---|
| 1 | | | | alto/medio/bajo | | | |
| 2 | | | | | | | |

## Áreas a cubrir (marcar al terminar)
- [ ] Parches y versión de Windows · [ ] Cuentas y grupos privilegiados · [ ] Exposición de red (RDP, SQL, SMB) y firewall
- [ ] NLA y políticas de contraseña/bloqueo · [ ] IIS (App Pools, logs, certificados) · [ ] SQL Server (auditoría de logins, `sa`, modo mixto)
- [ ] Defender (exclusiones, firmas) · [ ] Auditoría de Windows (4625/4624) y tamaño de registros · [ ] Respaldos y prueba de restauración
- [ ] Cloudflare/túnel · [ ] Resultado CIS-CAT o Policy Analyzer (adjuntar resumen)

## Decisiones de §10 cerradas con esta línea base
- [ ] Edición de Windows Server y de SQL Server
- [ ] IP de administración para la lista blanca
- [ ] Ubicación de respaldos a vigilar (`Audits:Backups:Targets`)
- [ ] Registro de `CF-Connecting-IP` en IIS
- [ ] IDs de eventos de Defender confirmados (SEC-008)
