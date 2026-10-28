# NadieScan v2.3 - Auditoría Web, Multi-Target & Smart Endpoint Hunter

Herramienta de auditoría de seguridad, fingerprinting y reconocimiento de APIs con soporte opcional para enrutar tráfico a través de **Cloudflare WARP** (SOCKS5 local) o en conexión directa.

---

## Características Principales

1. **Escaneo Masivo / Multi-Target (.txt o comas)**:
   - Permite ingresar un archivo `.txt` (ej: `dominios.txt`) con múltiples dominios o URLs separados por comas, saltos de línea o punto y coma.
   - También permite escribir directamente varios dominios separados por comas en la consola (`dom1.com, dom2.com, https://dom3.com`).
   - Escaneo por lotes ordenado con reportes individuales y resumen consolidado.

2. **Rastreo Autónomo & Spidering (Búsqueda "por su cuenta")**:
   - Descubre endpoints dinámicamente analizando la aplicación web por su cuenta:
     - Extrae rutas ocultas de `robots.txt` y `sitemap.xml`.
     - Rastrea el código HTML (enlaces internos `href` y formularios `action`).
     - **Spider de JavaScript**: localiza y analiza bundles JS de la app (`app.js`, `main.js`, `chunk-*.js`) y extrae endpoints REST, GraphQL y llamadas de `fetch` / `axios` / `ajax`.
   - Combina las rutas descubiertas por spidering con el diccionario agresivo de NadieScan.

3. **API & Endpoint Hunter Multihilo**:
   - Motor concurrente ultra-rápido basado en `ThreadPoolExecutor`.
   - Diccionario de rutas REST, OpenAPI/Swagger, Serverless y GraphQL.
   - **Fuzzing de parámetros dinámicos**: prueba parámetros habituales (`id`, `user`, `email`, `token`, `key`, `q`, `doc`, `ref`, etc.) sobre rutas de API.
   - Detección inteligente de respuestas JSON y descarte de falsos positivos (soft 404).

4. **Reconocimiento & Fingerprinting (Whoami)**:
   - Detección de servidor web (`Server`), frameworks y tecnologías backend (`X-Powered-By`, ASP.NET, PHP, etc.).
   - Detección de CDN / WAF (Cloudflare Ray ID, Akamai, AWS, etc.).
   - Auditoría de cabeceras de seguridad y cookies (`Secure`, `HttpOnly`).

5. **Búsqueda de Leaks, DBs / Información Expuesta (Nuevo Módulo)**:
   - Inteligencia pasiva OSINT (Certificate Transparency via crt.sh, índices de búsqueda y Google dorks, referencias en repositorios públicos GitHub, APIs de brechas históricas).
   - Comprobaciones directas de bajo impacto a alta velocidad (ThreadPool multihilo) de volcados SQL (`.sql`, `.dump`, `.db`), archivos `.env`, copias de respaldo `.bak`, `.git/HEAD`, interfaces de diagnóstico (`phpinfo`, `actuator/env`) y directorios abiertos.
   - Si la búsqueda pasiva no arroja hallazgos, escala de forma proactiva a comprobaciones directas exhaustivas sobre todos los activos autorizados.
   - Enrutamiento seguro y verificado a través del túnel SOCKS5 de **Cloudflare WARP**.
   - Detección y **redacción centralizada inmediata de secretos** (AWS keys, tokens GitHub/Slack, claves privadas, credenciales BD, JWT).
   - Organización estructurada en expedientes independientes (`results/exposure_audits/{id}/`) con reporte ejecutivo/técnico en español (`report.txt`) y formatos JSON.

6. **Reportes Automáticos**:
   - Generación de reportes estructurados en formato `JSON` y texto legible `TXT` en la carpeta `reports/` y `results/`.

---

## Requisitos e Instalación

### 1. Python 3.10 o superior
Instala las dependencias:
```bash
pip install -r requirements.txt
```

---

## Ejecución

### Desde Windows:
Haz doble clic sobre **`iniciar.bat`** o ejecuta en tu consola:
```powershell
python nadie_scan.py
```

### Opciones de línea de comandos:

| Flag | Descripción |
|---|---|
| `--no-warp` | Inicia directamente sin consultar Cloudflare WARP. |
| `--allow-unlisted` | Permite escanear cualquier dominio sin verificar `whitelist.txt`. |

---

## Menú de la Herramienta

```text
========================================================================
 [1] Whoami / Fingerprint (URL, .txt o lista de dominios)
 [2] API / Endpoint Finder (Multihilo + Fuzzing de parámetros)
 [3] Auditoría Completa (Whoami + Finder + Reporte)
 [4] Búsqueda de Leaks, DBs / Información Expuesta
 [5] Diagnóstico de Red y Cloudflare WARP
 [0] Salir
========================================================================
```

