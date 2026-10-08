# CScph26 — Agente local de seguridad para srv-copahue2

> Documento base del proyecto. Describe qué es, qué hace, cómo se diseña y en qué orden se
> construye. Estado: **Fases 2–7 y 9 completadas en código** (las compuertas 1, 8 y 10 y el destino de logs siguen pendientes de personas; ver §10). Siguiente autónoma: Fases 11–12 (sistema 2). Creado 2026-10-08.
> Revisado 2026-10-08: el proyecto pasa a ser un **sistema doble** (monitor autónomo + agente IA de consulta).

---

## 1. Qué es

Un **sistema doble** para proteger srv-copahue2:

- **Sistema 1 — Monitor autónomo (`SecurityAgent`):** servicio de Windows que **detecta amenazas y protege el servidor** aplicando reglas y protocolos definidos por nosotros. Funciona solo, sin depender del sistema 2.
- **Sistema 2 — Agente IA de consulta (`SecurityAdvisor`):** agente local con un modelo de lenguaje que **observa al sistema 1 en modo solo lectura** y permite **consultarle su estado** en lenguaje natural ("¿cómo está el servidor?", "¿qué se bloqueó hoy?", "¿por qué saltó SEC-001?"). No decide ni ejecuta acciones de protección.

| | Sistema 1 — Monitor | Sistema 2 — Agente IA |
|---|---|---|
| Rol | Detecta, alerta, bloquea | Consulta, explica, resume |
| Decide | Reglas auditables | Nada; solo lee |
| Acceso | Lee y escribe `agent.db`, firewall | Solo lectura vía API de estado |
| Si falla | Se pierde la consulta, no la protección | Nada se degrada: el sistema 1 sigue protegiendo |
| Dónde corre | srv-copahue2 (servicio) | Equipo propio dedicado, físico o VM, con recursos abundantes (hardware por especificar, ver §10) |

- No es un SIEM ni un panel: el dashboard es **opcional y secundario** (solo lectura, local).
- No usa licencias de pago ni servicios en la nube obligatorios.
- No sigue el modelo IIS/puerto-propio del resto del ecosistema (ver `Estructura y organizacion proyectos/2.PREPARAR-DEPLOY-SRVCOPAHUE2.md`): es un **Worker Service**, no un sitio web.
- Complementa (no reemplaza) a `Supervisor Salud Apps`, que vigila la **salud** de las apps; este vigila su **seguridad**.

### Alcance

| Dentro | Fuera (por ahora) |
|---|---|
| Detección en el host: Windows, IIS, SQL Server, archivos de `D:\Apps\*` | Pentesting / auditoría formal externa |
| Respuesta acotada y reversible (bloqueo de IPs, alertas) | Seguridad de red perimetral (router, VLAN) |
| Auditoría periódica de hardening (CIS) | Gestión de endpoints de usuarios |
| Runbooks / planes de respuesta documentados | SIEM multi-servidor (posible fase futura con Wazuh) |
| Consulta de estado en lenguaje natural (sistema 2, solo lectura) | IA que ejecuta acciones o modifica el servidor |

---

## 2. Principios no negociables

1. **Observe antes de enforce.** Toda regla nace en modo `observe` (solo alerta). Pasa a `enforce` solo tras revisar falsos positivos.
2. **Lista blanca obligatoria.** Red interna, rangos de Cloudflare y IPs de administración jamás se bloquean.
3. **Acciones acotadas y reversibles.** Todo bloqueo tiene expiración y se puede deshacer con un comando.
4. **Privilegios mínimos.** Cuenta de servicio dedicada; solo los permisos que cada módulo necesita.
5. **Decisiones deterministas.** Las acciones de protección las toman reglas auditables, nunca un modelo de IA.
6. **Coexistencia.** Misma regla que el resto del servidor: nada de `iisreset`, no tocar puertos, App Pools, bases ni el túnel `cloudflared` de otras apps; carpeta propia (`D:\Apps\SecurityAgent`); vigilar el espacio de `D:` (compartido).
7. **Los logs salen del servidor.** Un atacante con acceso no debe poder borrar su rastro.
8. **El agente se protege a sí mismo:** integridad verificable, permisos estrictos en su carpeta y config.
9. **Cero secretos en git.** Mismo criterio que las otras apps (`appsettings.Production.json` gitignored).
10. **La IA solo lee.** El sistema 2 no tiene herramientas de escritura ni de ejecución: solo consultas de lectura a la API de estado. Si en el futuro propone acciones (p. ej. desbloquear una IP), un humano las confirma y las ejecuta por el canal normal del sistema 1.
11. **Independencia de sistemas.** El sistema 1 nunca depende del sistema 2. Si la IA cae, se equivoca o es manipulada, la protección no cambia.
12. **Los logs son datos, no instrucciones.** Todo texto originado en el exterior (URLs, usuarios, nombres de archivo, User-Agent) puede intentar manipular al modelo (inyección de prompts). Se entrega al modelo como datos delimitados y saneados, nunca como instrucciones.
13. **Respuestas con evidencia.** Toda afirmación del sistema 2 cita el ID de evento, alerta o regla de `agent.db`. Si no hay dato, responde "no hay información", no estima.

---

## 3. Arquitectura

### Vista general de los dos sistemas

```
 SISTEMA 1 (srv-copahue2)                          SISTEMA 2 (equipo/VM aparte)
┌───────────────────────────────┐   API de estado  ┌──────────────────────────────┐
│ SecurityAgent (monitor)       │   solo lectura   │ SecurityAdvisor              │
│ detecta · alerta · bloquea    │ ───────────────► │ Modelo local + herramientas  │
│ agent.db (SQLite)             │  (token, red     │ de lectura (get_status, ...) │
└───────────────────────────────┘   interna)       │ Interfaz: consola / web local│
        ▲ independiente                            └──────────────────────────────┘
        └── sigue protegiendo aunque el sistema 2 falle              ▲ usuario consulta
```

### Sistema 1 — Monitor autónomo

```
 Fuentes                         Núcleo (Worker Service .NET 8)               Salidas
┌──────────────────────┐      ┌──────────────────────────────────┐      ┌─────────────────┐
│ Event Log (Security, │      │ Collectors  → eventos normalizados│      │ Alertas         │
│  System, Sysmon)     │ ───► │ Rule Engine (reglas YAML/JSON)    │ ───► │ (correo/Teams)  │
│ Logs IIS             │      │ State Store (SQLite local)        │      ├─────────────────┤
│ ERRORLOG / Audit SQL │      │ Responders (acciones acotadas)    │ ───► │ Firewall local  │
│ FileSystemWatcher    │      │ Scheduler (auditorías periódicas) │      ├─────────────────┤
│  D:\Apps\*           │      └──────────────────────────────────┘      │ Log externo     │
│ /api/health de apps  │                                                │ (fuera del srv) │
└──────────────────────┘                                                └─────────────────┘
```

### Componentes

- **Collectors:** un módulo por fuente. Leen eventos y los convierten a un modelo común (`SecurityEvent`: tiempo, fuente, tipo, actor, IP, objeto, severidad).
- **Rule Engine:** evalúa eventos contra reglas declarativas (umbral, ventana de tiempo, agrupación por IP/usuario). Las reglas viven en archivos versionados, no en el código.
- **State Store:** SQLite propio (`agent.db`) con eventos recientes, estado de reglas, bloqueos activos y su expiración. No toca ninguna base de las apps.
- **Responders:** acciones concretas y limitadas — notificar, crear/eliminar regla de Windows Firewall, marcar un incidente. Cada una con modo `observe`/`enforce`, expiración y rollback.
- **Scheduler:** auditorías periódicas (hardening, certificados, backups).
- **API de estado (solo lectura):** endpoint local del sistema 1 (escucha solo en la red interna, autenticado con token, sin operaciones de escritura). Es la **única puerta** del sistema 2 y también alimenta el dashboard. Consultas mínimas:
  - `get_status` — salud general, latido del agente, versión, modo de cada regla (`observe`/`enforce`).
  - `list_alerts` — alertas recientes filtrables por regla, severidad, IP y rango de tiempo.
  - `list_blocks` — bloqueos activos con expiración y motivo.
  - `get_rule` — estado, umbral y disparos recientes de una regla.
  - `get_audit_summary` — última auditoría de hardening, certificados y backups.
  - `get_event` — detalle de un evento/alerta por ID (con campos externos saneados).
- **Dashboard (opcional):** página local de solo lectura sobre la API de estado. Fase tardía.

### Sistema 2 — Agente IA de consulta

- **Modelo de lenguaje local** (p. ej. vía Ollama u otro runtime) con *tool calling*. Corre en un **equipo propio dedicado (físico o VM) con recursos abundantes**, fuera de srv-copahue2, para no competir por CPU/RAM con las 6 apps (principio 6). El hardware exacto está por especificar (§10); el tamaño del modelo se elegirá con él. Si se usara una API de pago, los datos se filtran antes de salir (IPs y usuarios) y se requiere decisión explícita.
- **Herramientas = las consultas de la API de estado.** Nada más. Sin shell, sin escritura, sin acceso directo a archivos ni a `agent.db`.
- **Flujo:** el usuario pregunta → el modelo elige una o varias consultas → recibe datos estructurados y saneados → redacta la respuesta citando IDs (principio 13).
- **Interfaz:** consola y/o página local de chat (supuesto inicial; Teams queda como opción).
- **Verificación cruzada:** puede comprobar el latido del sistema 1 y avisar si dejó de reportar, pero ese aviso crítico también lo emite el propio sistema 1 por su canal de alertas; la IA no es el único vigilante.
- **Capacidades posteriores (opcionales):** resumen diario/semanal proactivo, explicación de un runbook aplicado a una alerta concreta, priorización de alertas. Siempre solo lectura.

### Stack

| Capa | Tecnología |
|---|---|
| Runtime | .NET 8 Worker Service, instalado como servicio de Windows |
| Telemetría | Event Log de Windows + **Sysmon** (Sysinternals, gratuito) |
| Antimalware | Microsoft Defender (ya incluido), leído vía eventos/PowerShell |
| Persistencia | SQLite local |
| Reglas | YAML/JSON versionado en git |
| Alertas | Correo (SMTP/Graph) o Teams webhook |
| Bloqueo | Windows Firewall (reglas locales vía `netsh`/NetSecurity) |
| Auditoría | CIS-CAT Lite y baselines de Microsoft Security Compliance Toolkit |
| API de estado | Endpoint HTTP local de solo lectura (Kestrel dentro del Worker), token, solo red interna |
| Agente IA (sistema 2) | Modelo local (Ollama u otro runtime) + capa de herramientas de solo lectura; equipo propio dedicado (físico o VM, hardware por especificar) |

Todo gratuito con modelo local. Una API de pago por uso es una alternativa para el sistema 2 (con filtrado previo de datos); en ningún caso el modelo decide acciones de protección.

---

## 4. Catálogo inicial de reglas

Todas inician en `observe`.

| ID | Detección | Fuente | Respuesta (cuando pase a enforce) |
|---|---|---|---|
| SEC-001 | Fuerza bruta RDP (N logins fallidos 4625 por IP en X min) | Event Log Security | Bloqueo temporal de la IP |
| SEC-002 | Fuerza bruta SQL (≥4 logins fallidos en 5 min por IP) | ERRORLOG SQL | Alerta; bloqueo de IP si es externa |
| SEC-003 | Cuenta local/administrador creada o agregada a grupo privilegiado (4720, 4732) | Event Log Security | Alerta crítica |
| SEC-004 | Servicio o tarea programada nueva (7045, 4698) | System / Security | Alerta |
| SEC-005 | App Pool detenido o en bucle de reinicios | Event Log / IIS | Alerta |
| SEC-006 | Cambio en `web.config`, `appsettings.*` o binarios de `D:\Apps\*` fuera de ventana de deploy | FileSystemWatcher | Alerta crítica |
| SEC-007 | Patrones de ataque en logs IIS (escaneo, `../`, inyección; variante SEC-007-404 para ráfagas de 404) | Logs IIS | Bloqueo temporal de la IP |
| SEC-008 | Defender detecta malware o se desactiva | Eventos de Defender | Alerta crítica |
| SEC-009 | Certificado por vencer / backup sin ejecutar | Scheduler | Alerta |
| SEC-010 | Proceso sospechoso (Sysmon: PowerShell codificado; variante SEC-010-TEMP para procesos desde `Temp`) | Sysmon | Alerta |

El catálogo crecerá; cada regla debe tener su runbook (§6).

---

## 5. Modelo de regla (borrador)

```yaml
id: SEC-001
nombre: Fuerza bruta RDP
modo: observe            # observe | enforce
fuente: eventlog.security
condicion:
  event_id: 4625
  agrupar_por: ip_origen
  umbral: 8
  ventana: 5m
severidad: alta
excluir: [lista_blanca]   # referencia a allowlist.yaml
respuesta:
  accion: firewall.block_ip
  duracion: 1h
  notificar: [correo, teams]
runbook: runbooks/SEC-001-fuerza-bruta-rdp.md
```

---

## 6. Protocolos y planes de seguridad

Carpeta `runbooks/` — un documento por regla/escenario. Cada runbook incluye: qué significa la alerta, cómo verificar si es real, contención, erradicación, recuperación y a quién avisar.

Planes transversales a redactar:
- Respuesta a incidentes (clasificación, escalamiento, evidencia).
- Compromiso de cuenta / credenciales.
- Sospecha de ransomware (aislamiento, backups, restauración).
- Procedimiento para desbloquear una IP / desactivar una regla (rollback).
- Línea base de hardening del servidor (CIS) y calendario de revisiones.

---

## 7. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Falso positivo bloquea a un usuario/servicio legítimo | `observe` por defecto, lista blanca, bloqueos con expiración, rollback documentado |
| Carga extra en un servidor compartido con 6 apps | Collectors livianos, límites de CPU/RAM del servicio, retención acotada de `agent.db` |
| El agente es un objetivo de alto valor | Cuenta de servicio mínima, ACL estrictas, integridad de binarios/reglas, logs externos |
| Mantenimiento de una solución propia | Apoyarse en Sysmon/Defender/Firewall nativos; el agente solo orquesta; reglas fuera del código |
| Falsa sensación de seguridad | Documentar alcance; no sustituye una auditoría o pentest profesional |
| Inyección de prompts vía logs (texto controlado por un atacante llega al modelo) | Principios 10 y 12: IA sin herramientas de escritura, datos delimitados y saneados, pruebas de inyección en fase 12 |
| El modelo alucina o afirma un estado falso | Respuestas basadas en consultas estructuradas, con cita de IDs; "no hay información" ante la duda (principio 13) |
| Modelo local consume demasiados recursos | Ejecutarlo en equipo propio dedicado, fuera de srv-copahue2; el sistema 1 no depende de él |
| La API de estado amplía la superficie de ataque del sistema 1 | Solo lectura, token, escucha solo en red interna, sin datos sensibles (sin secretos ni contenido de archivos), registro de accesos |
| Dependencia excesiva de la IA para enterarse de problemas | Las alertas críticas salen siempre por el canal del sistema 1 (correo/Teams); la IA es consulta, no vigilancia primaria |

---

## 8. Estructura prevista del repositorio

```
CScph26/
├── CScph26.sln
├── CLAUDE.md                 (este documento)
├── src/
│   ├── SecurityAgent.Worker/ Servicio .NET 8 (host del sistema 1)
│   ├── SecurityAgent.Core/   Modelo de eventos, motor de reglas, estado
│   ├── SecurityAgent.Collectors/
│   ├── SecurityAgent.Responders/
│   ├── SecurityAgent.StatusApi/      Servidor de la API de estado de solo lectura
│   ├── SecurityAgent.StatusContract/ Contrato compartido (DTOs, sin dependencias); es lo único que ve el advisor
│   └── SecurityAdvisor/      Sistema 2: agente IA, herramientas de lectura, interfaz de consulta
├── rules/                    Reglas YAML + allowlist.yaml
├── runbooks/                 Un runbook por regla/escenario
├── deploy/                   Instalación del servicio, permisos, firewall, Sysmon config, despliegue del advisor
├── docs/                     Contrato de la API de estado (api-estado.md) y planes transversales (planes/)
├── .github/workflows/ci.yml  CI: compilar y probar
└── tests/                    Banco de eventos simulados (tests/fixtures/events); motor de reglas con eventos simulados; pruebas de inyección y de respuestas del advisor
```

---

## 9. Roadmap

Cada fase tiene un **tipo**, un **criterio de salida** verificable y sus **dependencias**:

- **Autónoma:** se puede construir y verificar sin intervención humana (código + pruebas con eventos simulados). Se encadena con la siguiente apenas cumple su criterio de salida.
- **Compuerta:** requiere una persona (acceso al servidor, decisión, credenciales, revisión con datos reales o tiempo de calendario). El trabajo se detiene ahí hasta que se cumpla la condición. Las compuertas son deliberadas, no fallos del plan.

| Fase | Contenido | Tipo | Criterio de salida | Depende de |
|---|---|---|---|---|
| 0 | Este documento; decisiones mínimas de §10 (lista blanca inicial, canal de alertas, nombre/carpeta del servicio) | Compuerta | Diseño aprobado y decisiones de "Fase 0" de §10 cerradas | — |
| 1 | Línea base: inventario del servidor, CIS-CAT, revisión de Defender/firewall/auditoría SQL e IIS/backups | Compuerta (acceso administrador a srv-copahue2) | Informe de brechas entregado y revisado | 0 |
| 2 | Repositorio, solución .NET 8 (estructura de §8), CI (compilar y probar), **banco de eventos simulados** (4625, 4720, 4732, 7045, 4698, líneas IIS/SQL de ataque) | Autónoma | La solución compila, las pruebas corren en CI y el banco de eventos simulados está versionado | 0 |
| 3 | Modelo `SecurityEvent`, State Store SQLite (`agent.db`), retención y límites de tamaño | Autónoma | Pruebas de persistencia, expiración y purga pasan; el tamaño queda acotado por configuración | 2 |
| 4 | Motor de reglas (YAML, umbral/ventana/agrupación), `allowlist.yaml`, modos `observe`/`enforce`, rollback de bloqueos | Autónoma | Reglas SEC-001/003/005 de ejemplo disparan sobre eventos simulados; la lista blanca nunca se bloquea; el modo `observe` nunca ejecuta acciones (probado) | 3 |
| 5 | Notificaciones (correo/Teams) y **API de estado de solo lectura** (contrato en `docs/`, token, solo red interna, sin escritura) | Autónoma (envío real: ver fase 8) | Las seis consultas de §3 responden con datos simulados; pruebas confirman que la API no admite escritura; notificaciones probadas contra un receptor simulado | 4 |
| 6 | Collectors (Event Log, IIS, SQL, FileSystemWatcher, Defender) y reglas SEC-001, SEC-003, SEC-005 | Autónoma | Cada collector convierte muestras reales/simuladas al modelo común; las tres reglas pasan sus pruebas extremo a extremo | 4, 5 |
| 7 | Instalador del servicio, cuenta de servicio mínima y ACL, integridad de binarios/reglas (principio 8), envío de logs al exterior (principio 7), límites de CPU/RAM | Autónoma (código) + Compuerta (destino de logs externos, §10) | Scripts de `deploy/` probados en una VM de prueba; verificación de integridad detecta una modificación simulada; el envío de logs funciona hacia un destino de prueba | 6; decisión del destino de logs |
| 8 | Despliegue en srv-copahue2 en modo `observe`, Sysmon instalado, credenciales SMTP/Teams reales, primeras detecciones reales | Compuerta (acceso al servidor y credenciales) | Servicio estable ≥ 72 h sin superar límites de recursos; al menos una alerta real o de prueba llega al canal definido | 1, 7; decisiones de canal y lista blanca |
| 9 | Resto del catálogo (SEC-002, 004, 006, 007, 008, 009, 010), runbooks por regla, planes transversales (§6), auditorías programadas | Autónoma (SEC-006 requiere las ventanas de deploy de §10) | Cada regla tiene pruebas, runbook y entrada en el catálogo; las auditorías corren en el Scheduler | 6 (código); 8 para validar en real |
| 10 | Periodo de observación y paso a `enforce` **regla por regla** | Compuerta (humana y de tiempo; principio 1) | Para cada regla: informe de falsos positivos revisado, aprobación explícita, prueba de bloqueo y de rollback ejecutadas | 8, 9 |
| 11 | **Sistema 2:** SecurityAdvisor, herramientas de lectura sobre la API de estado, interfaz de consulta (consola/web local), respuestas con citas | Autónoma (código y pruebas contra la API simulada) + Compuerta (equipo del modelo, §10) | Las preguntas de un conjunto de prueba se responden con las consultas correctas y citan IDs; ante falta de datos responde "no hay información"; no existe ninguna herramienta de escritura | 5 (API); equipo/hardware del modelo |
| 12 | Endurecimiento del sistema 2: pruebas de inyección de prompts con logs hostiles simulados, evaluación de calidad, verificación de latido | Autónoma | Un conjunto de logs hostiles no consigue que el modelo ignore sus reglas ni invoque algo fuera de la lista de consultas; evaluación de respuestas por encima del umbral acordado | 11 |
| 13 (opcional) | Resúmenes proactivos diarios/semanales; dashboard local de solo lectura; evaluar Wazuh si crece la infraestructura | Opcional | A definir si se decide hacerlo | 8, 11 |

### Lectura del plan

- **Cadena autónoma 2 → 3 → 4 → 5 → 6:** todo el núcleo del sistema 1 se construye y prueba sin tocar el servidor.
- **Cadena autónoma 11 → 12:** el sistema 2 puede desarrollarse contra la API simulada de la fase 5, sin esperar al despliegue ni a datos reales; solo necesita el equipo del modelo para ejecutarse de verdad.
- **Compuertas en orden:** 0 (decisiones) → 1 (servidor) → 7 (destino de logs) → 8 (despliegue y credenciales) → 10 (aprobación humana de `enforce`) → 11 (equipo del modelo).
- Las fases 1 y 2 son independientes y pueden avanzar en paralelo.
- La fase 10 nunca se automatiza: el principio 1 exige que una persona apruebe cada paso a `enforce` con datos reales.

### Qué desbloquea cada compuerta (de §10)

| Compuerta | Decisiones o recursos necesarios |
|---|---|
| Fase 0 | Nombre del servicio y carpeta de despliegue; lista blanca inicial; canal de alertas y destinatarios; si el agente es solo para srv-copahue2 |
| Fase 1 | Acceso administrador a srv-copahue2; edición de Windows Server y de SQL Server |
| Fase 7 | VM/equipo para enviar los logs fuera del servidor |
| Fase 8 | Credenciales SMTP/Graph o webhook de Teams; ventana de mantenimiento para instalar |
| Fase 9 (SEC-006) | Ventanas de deploy conocidas |
| Fase 10 | Tiempo de observación y aprobación por regla |
| Fase 11 | Equipo del modelo (físico o VM), hardware, interfaz de consulta y datos que nunca deben llegar al modelo |

---

## 10. Decisiones abiertas

- [ ] ¿Hay una VM/equipo aparte para enviar los logs fuera del servidor? (define el destino de los logs externos y si Wazuh es viable más adelante)
- [ ] Edición de Windows Server y de SQL Server (afecta qué auditorías nativas están disponibles).
- [x] **Canal de alertas (decidido 2026-10-08):** correo y Teams; si ambos no son posibles o dan problemas, solo correo como canal principal. Destinatarios: pendiente (antes de Fase 8).
- [x] **Lista blanca inicial (decidido 2026-10-08, provisional):** red interna `192.168.0.0/16` (rango general, se ajustará). Pendiente: IPs de administración y rangos de Cloudflare (`rules/allowlist.yaml`).
- [x] **Alcance (decidido 2026-10-08):** por ahora solo srv-copahue2.
- [x] **Servicio y carpeta (decidido 2026-10-08):** servicio `SecurityAgent`, carpeta `D:\Apps\SecurityAgent`. Repositorio y solución: `CScph26`.
- [ ] Ventanas de deploy conocidas, para no alertar SEC-006 durante despliegues legítimos.
- [x] **Sistema 2 — ubicación (decidido 2026-10-08):** el modelo corre en un **equipo propio dedicado** (físico o VM), separado de srv-copahue2, con **recursos abundantes** asignados. No compite con las apps del servidor.
- [ ] **Sistema 2 — hardware (pendiente de especificar):** el detalle (RAM, GPU/VRAM, CPU, disco) no está definido aún, pero se asume holgado. Al fijarlo se elige el tamaño del modelo; con recursos amplios ya no se está limitado a modelos de 7–8B. Decidir también si el equipo es físico o VM (una VM con GPU en passthrough exige verificar soporte del hipervisor).
- [ ] **Sistema 2 — modelo local vs. API de pago:** con hardware propio y abundante, se prioriza modelo local (los datos no salen); la API de pago queda solo como alternativa con filtrado previo.
- [ ] **Sistema 2:** interfaz de consulta preferida (consola, página local de chat o Teams) y quién puede consultar.
- [ ] **Sistema 2:** ¿qué datos nunca deben llegar al modelo (usuarios, IPs internas, rutas)? Define el saneado de la API de estado.
- [ ] **Respaldos a vigilar (SEC-009):** ¿cómo y dónde se respaldan SQL Server y `D:\Apps`? Hace falta carpeta, patrón de archivo y antigüedad máxima de cada respaldo (`Audits:Backups:Targets`). Mientras no se configure, la auditoría informa `sin_configurar`.
- [ ] **Registro de la IP real tras Cloudflare Tunnel (SEC-007):** configurar en IIS el campo personalizado `CF-Connecting-IP`; sin él las reglas de IIS ven la IP local del túnel y no pueden atribuir ni bloquear al atacante. Además, el bloqueo en Windows Firewall no frena tráfico que entra por el túnel: valorar reglas en Cloudflare WAF.
- [ ] **Privilegios para bloquear (antes de cualquier `enforce`):** la cuenta virtual de mínimos privilegios no puede crear reglas de firewall. Decidir entre un ayudante privilegiado mínimo o una cuenta con permisos de firewall (ver `deploy/README.md`).
- [ ] **Datos de contacto de escalamiento** para `docs/planes/respuesta-a-incidentes.md` (nombres y teléfonos).
- [ ] **Confirmar con datos reales (Fase 8):** IDs de eventos de Defender de SEC-008 (1116, 1119, 5001, 5010, 5012), configuración de Sysmon (depende de su versión) y que `auditpol` reporta correctamente la auditoría de 4625.
