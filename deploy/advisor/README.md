# Despliegue del SecurityAdvisor (sistema 2)

Corre en un **equipo propio** (físico o VM), nunca en srv-copahue2. Solo necesita alcanzar la API de estado (TCP 8750) y su propio runtime del modelo.

## Requisitos
- .NET 8 Runtime.
- Un runtime de modelo local con llamadas a herramientas (por defecto **Ollama**) y un modelo descargado. El tamaño del modelo se elige cuando se defina el hardware (decisión abierta de §10).
- En srv-copahue2, el instalador debe haberse ejecutado con `-AdvisorAddress <IP de este equipo>` para abrir el puerto solo a esa IP.

## Instalación
```powershell
dotnet publish src/SecurityAdvisor -c Release -o advisor-publish
# copiar advisor-publish\ al equipo del sistema 2 y crear advisor.Production.json a partir de advisor.Production.example.json
ollama pull <modelo>
```

## Uso
```powershell
.\SecurityAdvisor.exe                     # conversación interactiva
.\SecurityAdvisor.exe --ask "¿Cómo está el servidor?"
.\SecurityAdvisor.exe --eval eval-cases.json --min-score 0.9    # evaluación de calidad con el modelo real (Fase 12)
```

## Garantías (probadas)
- Solo existen las seis consultas de la API de estado; ninguna escritura, ejecución ni acceso a archivos o a `agent.db`.
- El proyecto SecurityAdvisor solo referencia `SecurityAgent.StatusContract` (prueba de arquitectura).
- Las órdenes de acción ("bloquea…", "desactiva…") se rechazan sin consultar al modelo.
- Los datos de las herramientas llegan al modelo como datos delimitados; las respuestas se verifican contra los IDs realmente devueltos y siempre terminan con `Fuentes:`. Sin datos, responde "No hay información".
- Si el modelo cita un ID que no existe, se le pide corregir una vez; si persiste, el usuario no ve el texto del modelo.

## Pendiente de la compuerta del modelo (§10)
Hardware y modelo definitivos, interfaz preferida (consola ya disponible; chat web opcional) y qué datos no deben llegar al modelo (`Redaction`).
