# Fase 1 — Línea base de srv-copahue2

**Objetivo:** conocer el estado real del servidor antes de desplegar nada, cerrar las decisiones abiertas de §10 que dependen de él y entregar un **informe de brechas revisado** (criterio de salida de la fase).
**Regla:** todo es de **solo lectura**. No se cambia ninguna configuración en esta fase; las brechas se anotan y se corrigen después, con un cambio planificado.

## Pasos

### 1. Preparación (10 min)
- Conéctate al servidor con tu usuario administrador y abre **PowerShell como administrador**.
- Elige una hora de poca carga: leer el registro de seguridad y las reglas de firewall consume algo de CPU/disco unos minutos.
- Copia al servidor `deploy/baseline/Collect-Baseline.ps1` (portapapeles de la sesión remota o carpeta compartida). No hace falta instalar nada.

### 2. Inventario automático (5–15 min)
```powershell
powershell -ExecutionPolicy Bypass -File .\Collect-Baseline.ps1
# SQL con instancia con nombre:   -SqlInstance 'localhost\NOMBRE'      Sin consultas SQL:   -SkipSql
```
Al terminar deja una carpeta `baseline-<servidor>-<fecha>` (y un `.zip`) en `%TEMP%`. Abre **`00-resumen.txt`**: cada área debe decir `OK`. Si alguna dice `ERROR`, anota cuál y sigue (el resto es válido).
> El script se validó solo en sintaxis; es la primera vez que corre en Windows. Si algo falla, copia el mensaje y lo corregimos.

### 3. Evaluación CIS / Microsoft (1–2 h, también solo lectura)
Elige según la edición de Windows Server que muestre `01-sistema.txt`:
- **CIS-CAT Lite** (gratis, requiere registro en CIS): descarga la versión actual, ejecuta una evaluación del benchmark **CIS Level 1** de tu edición y guarda el informe HTML. *Compruebe en la descarga que la edición de su Windows Server está soportada por la versión Lite; si no lo está, use la opción siguiente.*
- **Microsoft Security Compliance Toolkit** (gratis, sin registro): descarga la *baseline* de tu edición y compárala con la directiva local usando **Policy Analyzer**. Exporta el resultado a Excel.

### 4. Revisión manual de lo que el script no ve (30 min)
- **Cloudflare:** ¿qué expone el túnel? (`cloudflared tunnel list` / `config.yml`: que RDP o SQL no estén publicados sin Cloudflare Access). Confirma si IIS recibe tráfico solo por el túnel.
- **Perímetro:** ¿están 3389 (RDP) y 1433 (SQL) abiertos hacia Internet en el router/firewall? (esto no se ve desde el servidor).
- **Respaldos:** ¿dónde y cómo se respaldan SQL Server y `D:\Apps`? ¿Hay copia fuera del servidor? ¿Se ha probado una restauración?
- **Parches:** fecha del último parche y política de actualización (`01-sistema.txt`).

### 5. Informe de brechas
Copia `docs/linea-base/informe-de-brechas.md` fuera del repositorio (o rellénalo sin datos sensibles), anota cada hallazgo con su evidencia (nombre del archivo del paso 2) y un riesgo (alto/medio/bajo).

### 6. Qué me tienes que pasar para cerrar la fase
Pégame (puedes tachar nombres de usuario si prefieres) estas secciones, **no el zip entero y nunca a git**:
`01-sistema` (edición/versión), `08-sql-server` (edición/versión/AuditLevel), `04-red-y-firewall` (puertos en escucha y reglas), `07-iis` (formato/campos del log y `CF-Connecting-IP`), `09-defender` (IDs de evento y exclusiones), `10-auditoria-y-registros`, `11-actividad-de-logon` y `13-respaldos`, más tu informe de brechas.

Con eso yo: cierro las decisiones de §10 (edición de Windows/SQL, IP de administración para la lista blanca, respaldos a vigilar, `CF-Connecting-IP`), ajusto umbrales con el volumen real de intentos fallidos, confirmo los IDs de Defender de SEC-008 y actualizo el estado de la Fase 1.

## Qué mirar en cada archivo

| Archivo | Qué buscar | Decisión que alimenta |
|---|---|---|
| `01-sistema` | Edición y versión de Windows; fecha del último parche; zona horaria; runtime .NET | Edición de Windows (§10); si falta el runtime de .NET 8 para el agente |
| `02-discos` | Espacio libre en `D:` (compartido con las apps) | Límites de `agent.db` y logs |
| `03-cuentas` | `Administrator`/`Guest` habilitadas; quién está en Administradores y Escritorio remoto; cuentas sin caducidad | Brechas; SEC-003 |
| `04-red-y-firewall` | Puertos en escucha (¿3389, 1433, 80?); perfiles de firewall activos; reglas que permiten 3389/1433 desde cualquier IP; NLA (`UserAuthentication = 1`); SMBv1 | Brechas de exposición; SEC-001/002 |
| `05-servicios`, `06-tareas-programadas` | Servicios/tareas con rutas raras (`Users\Public`, `Temp`); cuentas con las que corren | Línea base de SEC-004 |
| `07-iis` | Formato W3C y campos del log; **si existe el campo `CF-Connecting-IP`**; carpeta y tamaño de los logs; identidad de los App Pools; `cloudflared` | Decisión CF-Connecting-IP (§10); ruta del collector de IIS |
| `08-sql-server` | Edición, versión, `AuditLevel` (¿registra logins fallidos?), modo mixto, puerto, ruta del `ERRORLOG`, último respaldo por base | Edición de SQL (§10); SEC-002; respaldos a vigilar |
| `09-defender` | Protección en tiempo real y firmas al día; **exclusiones**; IDs de evento vistos | Confirmar IDs de SEC-008 |
| `10-auditoria-y-registros` | Auditoría de «Logon» con **Failure** (si no, SEC-001 queda ciego); tamaño de los registros; Sysmon instalado; 4688 con línea de comandos | Brechas; instalación de Sysmon (Fase 8) |
| `11-actividad-de-logon` | Volumen de 4625 por IP/cuenta (¿ataques ya en curso?); **IP que entran por RDP con éxito** | Lista blanca (IP de administración); umbrales de SEC-001 |
| `12-apps` | Apps, tamaño, última modificación, `web.config`/`appsettings.Production.json` | Ventanas de deploy; alcance de SEC-006 |
| `13-respaldos` | Tareas/servicios/Windows Server Backup/VSS | Respaldos a vigilar (SEC-009) |
| `14-certificados` | Certificados con clave privada y su vencimiento | SEC-009 |

## Criterio de salida
Informe de brechas entregado y revisado, y las decisiones de Fase 1 de §10 cerradas o con responsable y fecha.
