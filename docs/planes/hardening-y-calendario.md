# Línea base de hardening y calendario de revisiones

## 1. Línea base
- **Referencia:** CIS Benchmark para la edición de Windows Server de srv-copahue2 (Nivel 1) y baselines de Microsoft Security Compliance Toolkit. Herramienta de evaluación: CIS-CAT Lite.
- **Estado:** el informe de brechas inicial lo produce la **Fase 1** (requiere acceso de administrador al servidor y conocer la edición de Windows/SQL Server; ver decisiones abiertas de §10).
- **Controles verificados automáticamente por el agente** (auditoría `hardening`, cada 24 h): firewall de Windows activo en los tres perfiles, NLA exigido en RDP, SMBv1 deshabilitado, Defender no desactivado por directiva y auditoría de inicios de sesión fallidos habilitada. No sustituye a CIS-CAT: detecta regresiones entre evaluaciones.

## 2. Calendario
| Frecuencia | Revisión | Responsable |
|---|---|---|
| Diaria (automática) | Auditorías `hardening`, `certificates`, `backups`; estado del agente (`/api/v1/status`: latido, integridad, envío de logs) | SecurityAgent |
| Semanal | Alertas de la semana y falsos positivos; bloqueos activos; espacio en `D:` | Administrador de sistemas |
| Mensual | Parches de Windows/.NET/SQL Server; usuarios y grupos privilegiados; revisión de la lista blanca y `deploy-windows.yaml` | Administrador de sistemas |
| Trimestral | Evaluación CIS-CAT completa y comparación con la línea base; **prueba de restauración de respaldos**; simulacro de incidente; rotación de secretos (token de la API, SMTP, webhook, clave HMAC) | Administrador + responsable de seguridad |
| Anual | Revisión del catálogo de reglas y de este plan; evaluar auditoría/pentest externa | Responsable de seguridad |

## 3. Cambios planificados
Todo cambio en `D:\Apps` fuera de las ventanas de `rules/deploy-windows.yaml` genera SEC-006. Declarar la ventana **antes** de desplegar.
Tras actualizar el propio agente, regenerar el manifiesto de integridad (el instalador lo hace).
