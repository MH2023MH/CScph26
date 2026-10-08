# SEC-009 — Certificado por vencer / respaldo sin ejecutar

## Qué significa
La auditoría programada detectó un certificado que vence en menos de 30 días (o ya vencido), o un respaldo configurado cuyo archivo más reciente es más antiguo que el máximo permitido. No es un ataque, pero deja al servidor expuesto (caída por certificado vencido; sin posibilidad de recuperación ante ransomware).

## Cómo verificar
1. `/api/v1/audit`: estado de `certificates` y `backups` y el resumen con los elementos afectados.
2. Certificados: `Get-ChildItem Cert:\LocalMachine\My | Select Subject,NotAfter,Thumbprint`. Backups: revisar la carpeta y el trabajo/tarea que los genera.

## Contención
Renovar el certificado (o reemplazar el enlace en IIS) antes de la fecha límite; lanzar un respaldo manual si el último falló.

## Erradicación
Corregir la causa (tarea deshabilitada, disco lleno, credenciales caducadas, renovación automática rota).

## Recuperación
Ejecutar la auditoría de nuevo (o esperar al siguiente ciclo) y confirmar estado `ok`. Probar una restauración de ejemplo trimestralmente.

## A quién avisar
Administrador de sistemas; responsable de la aplicación que usa el certificado.
