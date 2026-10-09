# SEC-007 — Ataques y escaneo en logs de IIS (incluye SEC-007-404)

## Qué significa
Una IP generó peticiones con firmas de ataque (recorrido de directorios `../`, inyección SQL/XSS, rutas de otras plataformas como `wp-login.php` o `/.env`, o el User-Agent de una herramienta de escaneo) — **SEC-007** — o una ráfaga de 30 respuestas 404 en 2 minutos — **SEC-007-404**, típico de escaneo de rutas.

## Cómo verificar
1. En la alerta: IP y peticiones citadas. ¿Alguna obtuvo respuesta 200/500 en vez de 404? Un 200 en `/.env` o un 500 tras una inyección es grave.
2. ¿La IP es un monitor legítimo o un cliente de prueba? ¿Una app propia tiene una ruta que contiene la palabra (falso positivo)? Ajustar con `excepto` (Fase 10).
3. **Detrás de Cloudflare Tunnel** la IP del log es la del túnel (127.0.0.1). Hay que registrar `CF-Connecting-IP` como campo personalizado de IIS para atribuir al cliente real; sin él estas reglas no pueden identificar al atacante (y el bloqueo del firewall local no frena tráfico que entra por el túnel: usar las reglas de Cloudflare WAF).
   Solo se acepta `CF-Connecting-IP` cuando la conexión viene del propio servidor (loopback o una dirección propia, que es donde corre `cloudflared`); si un equipo de la red interna llega a IIS por fuera del túnel, la IP atribuida es la suya, no la de la cabecera (que podría ser falsa).

## Contención
- `enforce`: bloqueo temporal de la IP en Windows Firewall (solo útil si la IP conecta directamente al servidor).
- Tráfico por Cloudflare: bloquear la IP/ASN en Cloudflare (WAF o reglas de IP).

## Erradicación
Revisar la app atacada: validación de entradas, actualizaciones, rutas expuestas innecesariamente; revisar si alguna petición tuvo éxito (200/500) y sus efectos (SEC-006, SEC-010).

## Recuperación
Quitar el bloqueo si fue un falso positivo; documentar el patrón nuevo para afinar las reglas.

## A quién avisar
Responsable de la aplicación; responsable de seguridad si hubo respuestas 200/500 a peticiones maliciosas.
