# Revisión de seguridad independiente del sistema 1 (2026-10-09)

Un revisor sin contexto previo leyó el código del monitor (`SecurityAgent`) buscando fallos explotables, con entradas hostiles
(todo texto de logs es del atacante, principio 12). Cada hallazgo se comprobó leyendo el código antes de corregirlo y tiene una
prueba que lo reproduce en `tests/CScph26.Tests/SecurityReviewTests.cs`. El sistema 2 (asesor) se revisó aparte (ver el final).

| # | Severidad | Hallazgo | Estado |
|---|---|---|---|
| 1 | Alta | La IP de un login fallido de SQL se podía falsificar con el nombre de usuario (`x [CLIENT: 8.8.8.8]`): se bloqueaba una IP ajena o el atacante evadía la regla SEC-002 | **Corregido**: la IP se toma del último campo, anclada y de derecha a izquierda |
| 2 | Media-alta | `CF-Connecting-IP` se aceptaba de cualquier par de la red privada: un equipo de la LAN podía acusar a otra IP | **Corregido**: solo se confía cuando el par es el propio servidor (loopback o una dirección propia) |
| 3 | Media | Eran bloqueables `0.0.0.0`, difusión, multidifusión, enlace local, las IP propias del servidor, su puerta de enlace y sus DNS/DHCP | **Corregido**: nunca se bloquean (`Allowlist` + `HostAddresses`) |
| 4 | Media | El cursor de los logs se desfasaba con bytes UTF-8 inválidos: se saltaban o repetían líneas (un atacante podía ocultar peticiones) | **Corregido**: el cursor avanza por bytes; una línea gigante sin salto de línea ya no deja ciego al lector |
| 5 | Media (enforce) | Cada acierto lanzaba otro `netsh` (reglas duplicadas, saturación); un bloqueo vencido cuya baja fallaba se purgaba a las 24 h y dejaba una regla huérfana; `netsh`/`auditpol` por nombre relativo | **Corregido**: no se duplica un bloqueo, hay tope por minuto (20) y activos (500); los bloqueos vencidos no se purgan hasta confirmar la baja y el fallo se informa en `problems`; rutas completas de System32 |
| 6 | Media-baja | `AllowedClients` no se podía restringir (el binder añadía a los valores por defecto); una entrada mal escrita tumbaba todo el monitor; se aceptaban tokens de ejemplo; `FixedTimeEquals` filtraba la longitud; el registro de accesos admitía CR/LF e inundación | **Corregido**: lista sin prellenar, API deshabilitada (no el monitor) ante configuración inválida, token ≥ 32 y sin `CAMBIAR…`, comparación de resúmenes, ruta saneada y rechazos limitados |
| 7 | Media-baja | Consultas de URL y líneas de comandos (Sysmon, servicios) con contraseñas llegaban a `agent.db`, a la API y al envío de logs | **Corregido**: `SecretScrubber` en el camino de persistencia (las reglas ven el original, así que no se esconde un ataque) |
| 8 | Media-baja | `RuleEngine.Compact` costaba O(n) por evento con ≥ 20 000 claves vivas (alcanzable con IP falsas) | **Corregido**: tope duro con descarte amortizado |
| 9 | Media-baja | Una ráfaga de IIS expulsaba eventos de Security/Sysmon por el tope global | **Corregido**: cuota por fuente (`MaxEventsPerSource`) y el tope de tamaño recorta primero la fuente más grande |
| 10 | Media-baja | El servicio recibía lectura de todos los archivos de `D:\Apps` (secretos de las otras apps); la configuración existía unos instantes con permisos heredados | **Corregido**: solo listar carpetas (`(CI)RX`); las ACL se aplican antes de copiar (la prueba de CI lo verifica) |
| 11 | Baja-media | SEC-006 ignoraba `data`, `logs`, `temp`, `App_Data`: un `web.config` plantado ahí no alertaba; los webshells `.aspx/.ashx/...` no estaban vigilados | **Corregido**: esos nombres se vigilan en cualquier carpeta (salvo `.git`, `obj`, `node_modules`) |
| 12 | Baja | Sin `HmacKey` la integridad pasaba por válida sin aviso | **Corregido**: se informa en `problems` (también con la clave de ejemplo) |
| 13 | Baja | El texto de atacante en alertas de Teams se interpretaba como Markdown/HTML (enlaces de phishing) | **Corregido**: escape de Markdown y HTML |
| — | Endurecimiento | `XDocument.Parse` admitía DTD en el XML de eventos | **Corregido**: `DtdProcessing.Prohibit` |

## Pendiente (requiere decisión o datos reales)

- **TLS en la API de estado**: el token viaja por HTTP dentro de la red interna. Mitigado con `AllowedClients` y la regla de firewall
  del puerto solo para la IP del asesor; falta decidir el certificado (CA interna o autofirmado con fijación).
- **Bloqueo y túnel**: el firewall local no frena el tráfico que entra por Cloudflare Tunnel; valorar reglas en Cloudflare WAF (ver §10 de `CLAUDE.md`).
- **Rangos de Cloudflare e IP de administración** en `rules/allowlist.yaml` (siguen vacíos).
- **Rendimiento de la escritura (corregido tras medirlo en Windows real):** la corrida sostenida del servicio instalado en Windows Server
  (`Test-InstallFlow.ps1 -SoakSeconds`, ~1 700 líneas IIS/s hostiles al 10 % más eventos de seguridad y cambios de archivos) mostró que con una
  transacción SQLite por evento el agente solo ingería ~200 eventos/s (en Linux, con disco rápido, parecía 4 000): tras 40 s de carga había leído
  743 KB de 5,1 MB y el latido llegó a 32 s de retraso. Se corrigió agrupando las escrituras de cada lote de un collector (eventos, alertas y
  cursor) en una transacción, `synchronous=NORMAL` en WAL y dando el latido mientras se procesa. Resultado en el mismo runner: 71 000 eventos
  ingeridos durante la carga, al día en cuanto termina, latido máximo 1,6 s, RAM máxima 117 MB (tope 512), CPU máxima 2,4 % (tope 25 %),
  `agent.db` + WAL de 20 MB, API sin fallos, SEC-007 detecta el tráfico hostil y sin reinicios. En Linux (`LoadTests`): ~49 000 eventos/s.
  Riesgo aceptado: un corte de energía puede perder las últimas confirmaciones de SQLite (la base no se corrompe y los collectors releen desde
  su cursor, que se confirma en la misma transacción). El workflow manual `Soak` repite la corrida durante minutos (úsese con 600 s o más antes
  de desplegar cambios del núcleo; solo aparece para ejecutar cuando el archivo esté en la rama principal).
- **Reconciliación del firewall tras un corte:** si un corte de energía pierde un registro de bloqueo recién confirmado, la regla de
  Windows Firewall quedaría sin entrada en `agent.db`. Pendiente (antes de `enforce`): al arrancar, listar las reglas `CScph26-block-*` y
  retirar las que no tengan bloqueo vigente.

## Revisión del sistema 2 (asesor)

Hallazgos propios, corregidos con pruebas en `AdvisorRedactionTests.cs`: la redacción (`MaskIps`/`PseudonymizeUsers`) no cubría el
texto libre (mensaje, motivo, detalle, objeto, acción) ni `get_rule` ni `get_event` de una alerta; el texto que ve el usuario podía
llevar secuencias de control o marcas bidireccionales que el modelo repitiera de un log hostil; el cliente de la API seguía redirecciones.

## Revisado y sin defecto

Sin inyección en `netsh` (lista de argumentos y IP re-validada y canonizada); SQLite siempre parametrizado; los filtros de las reglas
usan siempre `NonBacktracking`; la API solo mapea `GET` y el middleware cubre también las rutas inexistentes; ninguna ruta ni mensaje
de excepción expone secretos; con las ACL del instalador un usuario sin privilegios no puede aprobar `enforce` (`--set-mode`).
