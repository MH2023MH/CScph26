# SEC-001 — Fuerza bruta RDP

## Qué significa
Una misma IP produjo 8 o más inicios de sesión fallidos (evento 4625) en 5 minutos. Alguien está probando contraseñas contra RDP u otro servicio de Windows que autentica contra el servidor.

## Cómo verificar
1. Revisar la alerta (`/api/v1/alerts?rule=SEC-001`) y los eventos citados: IP de origen, cuentas probadas, tipo de inicio de sesión (`logon_type=3` red, `10` RDP).
2. ¿La IP es interna o conocida (administración, un compañero con la contraseña vencida)? Si es interna ya está en la lista blanca y no debería alertar: revisar `rules/allowlist.yaml`.
3. ¿Hubo **algún inicio de sesión exitoso (4624) de esa IP** poco después? En PowerShell: `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | Where-Object { $_.Message -match '203.0.113.50' }`. Un éxito tras la ráfaga = posible compromiso: pasar al plan *compromiso de cuenta*.
4. Confirmar que RDP no debería estar expuesto a Internet (Cloudflare Tunnel/Access o VPN en su lugar).

## Contención
- En modo `enforce`: el agente bloquea la IP 1 h (reversible: `SecurityAgent.Worker.exe --unblock-ip <ip>`).
- En modo `observe` o si el bloqueo falla: bloquear manualmente en Windows Firewall y, si el puerto 3389 está abierto al exterior, cerrarlo en el router/firewall perimetral.

## Erradicación
- Forzar cambio de contraseña de las cuentas atacadas si alguna es válida; deshabilitar cuentas por defecto (`Administrator`, `Guest`) o renombrarlas.
- Activar NLA y bloqueo de cuenta tras N intentos (directiva "Account lockout threshold").

## Recuperación
Quitar el bloqueo cuando expire o tras confirmar que era un falso positivo (ver `docs/planes/desbloqueo-y-rollback.md`). Anotar la IP en el informe del incidente.

## A quién avisar
Administrador de sistemas. Si hubo inicio de sesión exitoso desde la IP atacante: responsable de seguridad y dueño de los datos del servidor (plan de respuesta a incidentes).
