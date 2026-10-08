# SEC-005 — App Pool detenido o en bucle de reinicios

## Qué significa
IIS deshabilitó un App Pool tras fallos rápidos repetidos (evento WAS 5002, 3 veces en 10 minutos). Puede ser un fallo de la aplicación, una dependencia caída (SQL, disco `D:` lleno) o un ataque que provoca crasheos.

## Cómo verificar
1. En la alerta: nombre del App Pool (`target`).
2. Event Viewer → Application: errores de la app y de `.NET Runtime`/`ASP.NET` en esos minutos.
3. ¿Hubo despliegue reciente? ¿Espacio libre en `D:`? ¿SQL Server accesible?
4. Cruzar con SEC-007 (tráfico anómalo contra esa app) y SEC-006 (cambios de archivos).

## Contención
Corregir la causa y reiniciar **solo ese App Pool** (`Start-WebAppPool` / `Restart-WebAppPool -Name <nombre>`). **No usar `iisreset`** (afecta a las demás apps).

## Erradicación
Si el origen es un ataque: bloquear la IP (SEC-007) y revisar la entrada vulnerable; si es un bug: corregir y desplegar.

## Recuperación
Confirmar `/api/health` de la app y que no vuelve a deshabilitarse. Registrar la causa.

## A quién avisar
Responsable de la aplicación afectada; administrador de sistemas. Si coincide con tráfico hostil: responsable de seguridad.
