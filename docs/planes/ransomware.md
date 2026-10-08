# Plan: sospecha de ransomware

Señales: archivos renombrados o con extensiones nuevas masivamente, notas de rescate, Defender detectando cifradores (SEC-008), cambios masivos en `D:\Apps` (SEC-006, `fs.overflow`), procesos extraños (SEC-010), apps que fallan por archivos ilegibles.

## 1. Aislar (inmediato)
1. **Desconectar el servidor de la red** (deshabilitar el adaptador o cortar el cable/puerto del switch). No apagarlo todavía: la memoria puede contener las claves.
2. Desconectar o proteger los **respaldos**: unidades externas, recursos compartidos y credenciales de respaldo accesibles desde el servidor. El ransomware ataca los respaldos primero.
3. Avisar al responsable de seguridad y a dirección (P1). Seguir `respuesta-a-incidentes.md`.

## 2. Evaluar
- Identificar el proceso y la cuenta (Sysmon evento 1, 4688, Defender 1116). Hora de inicio (primer archivo cifrado).
- Alcance: unidades `D:`/`C:`, recursos compartidos, bases de datos (archivos `.mdf/.ldf`), otros servidores alcanzables con la misma cuenta.
- ¿Hubo exfiltración antes (tráfico saliente, herramientas de compresión/sincronización)? Puede implicar obligaciones legales de notificación.

## 3. Restaurar
1. Reconstruir el servidor desde una imagen/instalación limpia (no limpiar en caliente un sistema comprometido).
2. Restaurar datos desde el **último respaldo anterior al compromiso**, verificado con antivirus actualizado y sin contacto con el sistema infectado.
3. Reinstalar apps desde el repositorio; recrear secretos nuevos (nunca reutilizar los anteriores).
4. Reinstalar SecurityAgent con `deploy/Install-SecurityAgent.ps1`, en modo `observe`, y confirmar logs externos y estado (`/api/v1/status`).
5. Reabrir servicios gradualmente con monitoreo reforzado.

## 4. Prevención (revisar tras el incidente)
- Respaldos con copia desconectada/inmutable y **prueba de restauración trimestral** (SEC-009 vigila que se ejecuten, no que se puedan restaurar).
- Mínimo privilegio en cuentas de servicio y de respaldo; segmentación; parches al día.
- No pagar sin consultar a dirección y asesoría legal.
