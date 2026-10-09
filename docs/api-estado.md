# Contrato de la API de estado (v1, solo lectura)

Única puerta del sistema 2 (`SecurityAdvisor`) y del dashboard hacia el sistema 1. Los tipos están en
`src/SecurityAgent.StatusContract` (sin dependencias); el servidor en `src/SecurityAgent.StatusApi`.

## Seguridad

| Control | Comportamiento |
|---|---|
| Solo lectura | Solo existen rutas `GET`. Cualquier `POST/PUT/PATCH/DELETE` devuelve error (probado). |
| Token | `Authorization: Bearer <token>`. Mínimo 32 caracteres aleatorios; sin token, con el valor de ejemplo (`CAMBIAR…`) o demasiado corto la API **no arranca** (el monitor sí: el motivo aparece en `problems` y en el Event Log). Se comparan resúmenes SHA-256 en tiempo constante (no se filtra la longitud). 401 si falta o es inválido (también para rutas inexistentes). |
| Red interna | Solo clientes en `AllowedClients` (CIDR/IP); otros reciben 403 aunque el token sea válido. Si se configura, **reemplaza** la lista por defecto (`127.0.0.1`, `::1`, `192.168.0.0/16`). Una entrada mal escrita deshabilita la API (no tumba el monitor). Kestrel escucha por defecto solo en `127.0.0.1`; `Listen` se ajusta a la IP interna. |
| Registro de accesos | Cada petición, y cada rechazo, se registra (IP, método, ruta, estado). Método y ruta los elige quien llama, por lo que se limpian de caracteres de control; los rechazos se limitan a 20 por minuto (el resto se cuenta). Nunca se registra el token. |
| Secretos | Los eventos se guardan sin secretos evidentes en `target` y `detail` (contraseñas, tokens y claves en consultas de URL o líneas de comandos, credenciales en URL): se sustituyen por `***`. Las reglas se evalúan antes, sobre el original. |
| Transporte | **HTTP sin cifrar**: el token viaja en claro por la red interna. Mitigación actual: `AllowedClients` + regla de firewall solo para la IP del asesor. Pendiente decidir TLS (certificado interno). |
| Datos externos | Actor, objeto, mensaje y motivo se **sanean** (sin controles, saltos de línea ni caracteres invisibles/bidi; longitud acotada). La IP se valida como IP. |
| Sin secretos | No expone contenido de archivos, secretos ni la base de datos. |

## Consultas (herramientas del sistema 2)

| Herramienta | Ruta | Parámetros | Respuesta |
|---|---|---|---|
| `get_status` | `GET /api/v1/status` | — | `StatusDto`: versión, hora, latido (`heartbeat_at`, `heartbeat_age_seconds`), modo efectivo de cada regla, `log_shipping`, `integrity` y `problems` (fuentes que el agente **no puede leer**: canal de eventos sin permiso o inexistente, carpeta vigilada que falta...; vacío si todo se lee) |
| `list_alerts` | `GET /api/v1/alerts` | `rule`, `severity` (mínima: info\|baja\|media\|alta\|critica), `ip`, `since` (ISO 8601), `limit` (1–200, def. 50) | `ListDto<AlertDto>` |
| `list_blocks` | `GET /api/v1/blocks` | — | `ListDto<BlockDto>` (activos, con expiración y motivo) |
| `get_rule` | `GET /api/v1/rules/{id}` | — | `RuleDetailDto` con umbral, ventana, modo y últimas 10 alertas; 404 si no existe |
| `get_audit_summary` | `GET /api/v1/audit` | — | `AuditSummaryDto` (hardening, certificados, respaldos). Sin datos: `status = "sin_datos"` y "No hay información…" |
| `get_event` | `GET /api/v1/events/{id}` | — | `EventDetailDto`: `kind = "event"` o `"alert"` (IDs `ALR-…`); 404 si no existe |

JSON en `snake_case`. Errores: `{"error": "..."}` con 400 (parámetro inválido), 401, 403 o 404.

## Modo efectivo de una regla

`mode` = `enforce` solo si el archivo de la regla dice `enforce` **y** la aprobación persistida en `agent.db` también
(doble llave, principio 1). En cualquier otro caso es `observe`. `file_mode` muestra lo que declara el archivo.
