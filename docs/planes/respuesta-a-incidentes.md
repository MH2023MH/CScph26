# Plan de respuesta a incidentes

Aplica a cualquier alerta crítica de SecurityAgent o a una sospecha razonable de compromiso de srv-copahue2.

## 1. Clasificación
| Nivel | Criterio | Ejemplos | Plazo de respuesta |
|---|---|---|---|
| **P1 — Crítico** | Indicios de compromiso confirmado o en curso | SEC-003 sin explicación, SEC-008 con ejecución, SEC-006 con web shell, inicio de sesión exitoso tras SEC-001 | Inmediato |
| **P2 — Alto** | Ataque activo sin evidencia de éxito | SEC-001/002/007 con ráfagas sostenidas, SEC-004 sospechosa | Mismo día |
| **P3 — Medio** | Anomalía a investigar | SEC-005, SEC-010-TEMP, SEC-009 | Esta semana |
| **P4 — Bajo** | Informativo / falso positivo probable | Ráfagas internas, alertas de observación | Revisión periódica |

## 2. Pasos
1. **Detectar y registrar.** Anotar hora (UTC), alerta (ID `ALR-…`), reglas relacionadas y quién la recibió. No modificar el servidor todavía si P1.
2. **Contener** (ver el runbook de la regla). Prioridad: cortar el acceso del atacante sin destruir evidencia. Aislar red antes que apagar.
3. **Preservar evidencia.** Exportar logs (`wevtutil epl Security C:\evidencia\Security.evtx`), copiar `agent.db`, los logs externos ya enviados (el atacante no puede borrarlos) y hashes de archivos sospechosos. Registrar cadena de custodia (quién, cuándo, dónde).
4. **Erradicar.** Eliminar persistencia, cuentas, tareas y binarios del atacante; cerrar la vía de entrada.
5. **Recuperar.** Restaurar desde respaldo limpio si no se puede garantizar la integridad (ver plan *ransomware* para el procedimiento de restauración); volver a `observe`/`enforce` según corresponda.
6. **Cerrar y aprender.** Informe: línea de tiempo, causa raíz, impacto, acciones, mejoras a reglas/runbooks.

## 3. Escalamiento
| Quién | Cuándo |
|---|---|
| Administrador de sistemas | Todo P1–P3 |
| Responsable de seguridad | P1–P2 |
| Dirección / responsables de datos | P1 con posible fuga o indisponibilidad prolongada |
| Proveedores (hosting, banco, Cloudflare) | Cuando la contención dependa de ellos |

> Completar con nombres y teléfonos reales (decisión pendiente de §10: destinatarios de alertas).

## 4. Qué NO hacer
- No usar `iisreset` ni reiniciar el servidor antes de recoger evidencia volátil si es P1.
- No borrar archivos del atacante: moverlos a cuarentena o copiarlos antes.
- No comunicar el incidente por canales alojados en el propio servidor comprometido.
