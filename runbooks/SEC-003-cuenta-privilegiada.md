# SEC-003 — Cuenta creada o agregada a un grupo privilegiado

## Qué significa
Se creó una cuenta local (evento 4720) o se agregó un miembro a un grupo local privilegiado (4732, p. ej. *Administrators*). Es una técnica clásica de persistencia tras un compromiso. Severidad crítica: **no se bloquea automáticamente**, requiere revisión humana.

## Cómo verificar
1. En la alerta: quién lo hizo (`actor`), qué cuenta/grupo (`target`) y cuándo.
2. ¿Corresponde a un cambio planificado (alta de un administrador, instalación de software que crea una cuenta de servicio)? Contrastar con el registro de cambios.
3. Listar el estado actual: `Get-LocalGroupMember Administrators`, `Get-LocalUser | Select Name,Enabled,LastLogon`.

## Contención
Si no está justificado: deshabilitar la cuenta (`Disable-LocalUser <nombre>`), quitarla del grupo (`Remove-LocalGroupMember`) y cerrar sus sesiones (`query user`, `logoff <id>`). Considerar el servidor comprometido hasta aclararlo.

## Erradicación
Identificar **quién** creó la cuenta y desde dónde (eventos 4624 previos del actor), qué más hizo (SEC-004, SEC-006, SEC-010 cercanas en el tiempo) y retirar los mecanismos de persistencia encontrados. Plan *compromiso de cuenta*.

## Recuperación
Rotar credenciales de las cuentas administrativas, revisar tareas programadas y servicios nuevos, restaurar desde un respaldo limpio si no se puede garantizar la integridad.

## A quién avisar
Responsable de seguridad de inmediato; administrador de sistemas; dirección si se confirma un incidente.
