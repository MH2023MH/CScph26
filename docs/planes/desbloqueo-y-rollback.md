# Procedimiento: desbloquear una IP y desactivar una regla (rollback)

Principio 3: todo bloqueo tiene expiración y se deshace con un comando.

## A. Ver y desbloquear una IP
En el servidor, como administrador:
```powershell
D:\Apps\SecurityAgent\SecurityAgent.Worker.exe --list-blocks
D:\Apps\SecurityAgent\SecurityAgent.Worker.exe --unblock-ip 203.0.113.50
```
El comando retira la regla de Windows Firewall (`CScph26-block-<ip>`) y el registro en `agent.db`. Es idempotente.
Los bloqueos expiran solos (1 h por defecto); el mantenimiento (cada 10 min) retira del firewall los vencidos.

Si el comando no pudiera ejecutarse, manualmente:
```powershell
Get-NetFirewallRule -DisplayName 'CScph26-block-203.0.113.50' | Remove-NetFirewallRule
```

## B. Evitar que se repita para una IP legítima
Agregarla a `rules/allowlist.yaml` (red interna, IPs de administración), **regenerar el manifiesto** de integridad
(`SecurityAgent.Worker.exe --make-manifest`) y reiniciar el servicio. Las IP de la lista blanca jamás se bloquean.

## C. Volver una regla a `observe` (rollback de `enforce`)
Una regla bloquea solo si su archivo YAML dice `modo: enforce` **y** la aprobación guardada en `agent.db` también. Para volver a `observe`:
1. Cambiar `modo: observe` en `rules/SEC-xxx.yaml`.
2. Regenerar el manifiesto y reiniciar el servicio.
3. Retirar los bloqueos activos de esa regla (`--list-blocks` y `--unblock-ip`).

## D. Parada de emergencia del agente
`Stop-Service SecurityAgent`. Los bloqueos ya creados permanecen hasta su retiro manual (sección A) o hasta reiniciar el servicio y que el mantenimiento los barra al vencer. Desinstalar con `deploy/Uninstall-SecurityAgent.ps1` retira también todas las reglas `CScph26-block-*`.

## E. Registrar
Anotar: IP/regla, motivo del desbloqueo (falso positivo, error, caso aprobado), quién y cuándo. Los falsos positivos alimentan el ajuste de reglas en la Fase 10.
