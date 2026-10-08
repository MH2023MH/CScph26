# SEC-002 — Fuerza bruta SQL Server

## Qué significa
Una IP acumuló 4 o más inicios de sesión fallidos contra SQL Server (error 18456 en el ERRORLOG) en 5 minutos. Suele ser un ataque contra `sa` u otros usuarios comunes, o una aplicación con una contraseña caducada.

## Cómo verificar
1. En la alerta, ver la IP y los usuarios probados. Si es una IP interna y el usuario es el de una app, probablemente es una cadena de conexión con contraseña vieja (falso positivo; las IP internas están en la lista blanca).
2. Si es externa: **SQL Server no debería ser alcanzable desde fuera**. Comprobar el puerto 1433 en el firewall/router.
3. Revisar si hubo logins exitosos posteriores del mismo origen: `EXEC xp_readerrorlog 0, 1, N'Login succeeded'` (solo si la auditoría de inicios correctos está activa) o la auditoría de SQL.

## Contención
- `enforce`: bloqueo de la IP 1 h. Manual: regla de Windows Firewall que bloquee la IP.
- Deshabilitar el login `sa` si no se usa (`ALTER LOGIN sa DISABLE`) y exigir autenticación de Windows donde se pueda.

## Erradicación
Cerrar la exposición del puerto 1433, rotar contraseñas de logins SQL si hubo éxito, revisar `sys.sql_logins` y permisos `sysadmin`.

## Recuperación
Verificar que las aplicaciones siguen conectando; retirar el bloqueo si afectó a un origen legítimo.

## A quién avisar
Administrador de bases de datos y de sistemas; responsable de seguridad si hubo acceso exitoso.
