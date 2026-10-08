# SEC-006 — Cambio en archivos de D:\Apps fuera de ventana de deploy

## Qué significa
Se creó, modificó, renombró o eliminó un `web.config`, `appsettings*.json`, `.dll`, `.exe` o `.config` bajo `D:\Apps` fuera de las ventanas de deploy declaradas en `rules/deploy-windows.yaml`. Severidad crítica: puede ser una web shell, un binario troyanizado o un cambio de configuración malicioso. También se emite con `fs.overflow` (se perdió visibilidad: el búfer del vigilante se desbordó o hubo cambios masivos).

## Cómo verificar
1. En la alerta: ruta (`target`). ¿Qué app es? ¿Hubo un deploy o un cambio manual autorizado que no está en las ventanas?
2. Comparar con el repositorio/versión desplegada (hash del archivo vs. build); `Get-Item <ruta> | Select LastWriteTime`.
3. Revisar quién tenía sesión en ese momento (4624/4672) y SEC-003/004/010 cercanas.
4. Si fue un cambio legítimo no previsto: agregar la ventana (o una puntual) a `deploy-windows.yaml` para el futuro.

## Contención
Si no está justificado: aislar el servidor o al menos la app (detener su App Pool, no `iisreset`), preservar el archivo modificado y su hash como evidencia y restaurar la versión conocida.

## Erradicación
Buscar otros archivos alterados (`Get-ChildItem D:\Apps -Recurse | Where LastWriteTime -gt ...`), web shells (archivos `.aspx/.ashx` nuevos), cuentas y tareas nuevas. Rotar secretos de los `appsettings` afectados.

## Recuperación
Desplegar desde el repositorio limpio, verificar hashes y regenerar la línea base. Registrar la causa raíz.

## A quién avisar
Responsable de la aplicación y de seguridad de inmediato; administrador de sistemas.
