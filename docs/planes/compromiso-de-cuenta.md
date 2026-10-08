# Plan: compromiso de cuenta o credenciales

Cuándo usarlo: éxito de inicio de sesión tras fuerza bruta (SEC-001/002), cuenta nueva o privilegios inesperados (SEC-003), credenciales filtradas (repositorio, correo, logs) o actividad anómala de un usuario/servicio.

## 1. Contener (primeros 30 minutos)
1. Deshabilitar la cuenta o cambiar su contraseña desde una máquina de confianza.
2. Cerrar sesiones activas: `query user /server:srv-copahue2`, `logoff <id>`; revocar tokens/sesiones de las apps que usa la cuenta.
3. Si es una cuenta de servicio o de base de datos: rotar la contraseña **y** actualizarla en la app que la usa (`appsettings.Production.json`) coordinando una ventana para no tumbar la app.
4. Si el atacante tuvo privilegios de administrador: asumir que todas las credenciales del servidor están expuestas (cuentas locales, secretos en `appsettings`, cadenas de conexión, tokens de la API de estado, SMTP, webhooks, clave HMAC).

## 2. Investigar
- Alcance: ¿qué hizo la cuenta? Eventos 4624/4625/4648/4672 y 4720/4732 por usuario y por IP de origen; actividad en SQL y en IIS.
- Origen: ¿desde dónde se autenticó? ¿La IP está en la lista blanca (¿es un equipo interno comprometido?)?
- Persistencia: SEC-004 (servicios/tareas), SEC-006 (archivos), claves de registro `Run`, cuentas nuevas.

## 3. Erradicar y recuperar
- Rotar **todas** las credenciales potencialmente expuestas (orden: administración → servicio/BD → apps → terceros).
- Eliminar persistencia hallada; revisar membresías de grupos privilegiados.
- Activar o reforzar MFA donde exista soporte (RDP vía Cloudflare Access/VPN, paneles admin).
- Regenerar el manifiesto de integridad del agente tras cambios legítimos y verificar que `--verify-manifest` da OK.

## 4. Después
- Informe con línea de tiempo y causa raíz (¿contraseña débil, reutilizada, filtrada, phishing?).
- Revisar la política de contraseñas y bloqueo de cuentas; añadir/afinar reglas si el ataque no fue visible.
