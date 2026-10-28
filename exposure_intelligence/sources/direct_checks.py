# -*- coding: utf-8 -*-
"""
Proveedor de comprobaciones directas de bajo impacto y alta velocidad.
Verifica archivos de configuración, respaldos, volcados de BD, .git y directorios expuestos
con concurrencia multihilo, streaming limitado (sin descarga masiva) y descarte de soft-404.
"""

import concurrent.futures
import hashlib
import threading
import time
from datetime import datetime
from typing import Callable, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import requests

from .base import BaseSourceProvider
from ..models import AuditScope, Finding, SourceStatus, ExternalReference, VerificationStatus, ExposureType, SeverityLevel
from ..redactor import SecretRedactor
from ..scope import ScopeValidator

# Diccionario exhaustivo de rutas clave de exposición sensible
DIRECT_CHECK_PATHS = [
    # Archivos de entorno y configuración sensible
    ("/.env", ExposureType.EXPOSED_CONFIG, "Archivo de entorno con posibles secretos de aplicación", SeverityLevel.CRITICO),
    ("/.env.local", ExposureType.EXPOSED_CONFIG, "Archivo de entorno local", SeverityLevel.CRITICO),
    ("/.env.production", ExposureType.EXPOSED_CONFIG, "Archivo de entorno de producción", SeverityLevel.CRITICO),
    ("/.env.stage", ExposureType.EXPOSED_CONFIG, "Archivo de entorno de staging", SeverityLevel.CRITICO),
    ("/.env.bak", ExposureType.EXPOSED_CONFIG, "Copia de respaldo de archivo .env", SeverityLevel.CRITICO),
    ("/.env.old", ExposureType.EXPOSED_CONFIG, "Archivo de entorno anterior", SeverityLevel.CRITICO),
    ("/.env.save", ExposureType.EXPOSED_CONFIG, "Archivo de entorno guardado por editor", SeverityLevel.CRITICO),
    ("/config.php.bak", ExposureType.EXPOSED_CONFIG, "Copia de respaldo de configuración PHP", SeverityLevel.ALTO),
    ("/web.config.bak", ExposureType.EXPOSED_CONFIG, "Copia de respaldo de configuración IIS", SeverityLevel.ALTO),
    ("/settings.json", ExposureType.EXPOSED_CONFIG, "Archivo de configuración JSON accesible", SeverityLevel.MEDIO),
    ("/config.json", ExposureType.EXPOSED_CONFIG, "Archivo de configuración general", SeverityLevel.MEDIO),
    ("/secrets.json", ExposureType.EXPOSED_CONFIG, "Archivo de secretos JSON", SeverityLevel.CRITICO),
    ("/parameters.yml", ExposureType.EXPOSED_CONFIG, "Archivo de parámetros de configuración", SeverityLevel.ALTO),
    ("/docker-compose.yml", ExposureType.EXPOSED_CONFIG, "Archivo de orquestación Docker con definiciones de servicios", SeverityLevel.ALTO),
    
    # Volcados de Bases de Datos y respaldos
    ("/backup.sql", ExposureType.BACKUP_DATABASE_EXPOSURE, "Volcado de base de datos SQL", SeverityLevel.ALTO),
    ("/database.sql", ExposureType.BACKUP_DATABASE_EXPOSURE, "Volcado de base de datos SQL", SeverityLevel.ALTO),
    ("/dump.sql", ExposureType.BACKUP_DATABASE_EXPOSURE, "Volcado de datos SQL", SeverityLevel.ALTO),
    ("/db.sql", ExposureType.BACKUP_DATABASE_EXPOSURE, "Respaldo de base de datos SQL", SeverityLevel.ALTO),
    ("/export.sql", ExposureType.BACKUP_DATABASE_EXPOSURE, "Exportación SQL de base de datos", SeverityLevel.ALTO),
    ("/users.sql", ExposureType.BACKUP_DATABASE_EXPOSURE, "Posible exportación de tabla de usuarios", SeverityLevel.CRITICO),
    ("/schema.sql", ExposureType.BACKUP_DATABASE_EXPOSURE, "Esquema de base de datos SQL expuesto", SeverityLevel.ALTO),
    ("/backup.zip", ExposureType.BACKUP_DATABASE_EXPOSURE, "Archivo comprimido de respaldo", SeverityLevel.ALTO),
    ("/backup.tar.gz", ExposureType.BACKUP_DATABASE_EXPOSURE, "Archivo tarball de respaldo", SeverityLevel.ALTO),
    ("/dump.tar.gz", ExposureType.BACKUP_DATABASE_EXPOSURE, "Archivo comprimido de volcado", SeverityLevel.ALTO),
    ("/db.sqlite", ExposureType.BACKUP_DATABASE_EXPOSURE, "Base de datos SQLite embebida", SeverityLevel.CRITICO),
    ("/database.sqlite3", ExposureType.BACKUP_DATABASE_EXPOSURE, "Base de datos SQLite3 expuesta", SeverityLevel.CRITICO),
    ("/data.sql.bak", ExposureType.BACKUP_DATABASE_EXPOSURE, "Copia de respaldo de base de datos", SeverityLevel.ALTO),

    # Control de versiones (VCS)
    ("/.git/HEAD", ExposureType.VERSION_CONTROL_EXPOSURE, "Repositorio Git expuesto públicamente", SeverityLevel.CRITICO),
    ("/.git/config", ExposureType.VERSION_CONTROL_EXPOSURE, "Configuración interna de Git expuesta", SeverityLevel.ALTO),
    ("/.svn/entries", ExposureType.VERSION_CONTROL_EXPOSURE, "Metadatos SVN expuestos", SeverityLevel.ALTO),

    # Interfaces de diagnóstico y administración
    ("/phpinfo.php", ExposureType.DIAGNOSTIC_INTERFACE, "Página de diagnóstico phpinfo con detalles del entorno", SeverityLevel.MEDIO),
    ("/server-status", ExposureType.DIAGNOSTIC_INTERFACE, "Módulo de estado de Apache accesible", SeverityLevel.MEDIO),
    ("/server-info", ExposureType.DIAGNOSTIC_INTERFACE, "Módulo de información de servidor Apache", SeverityLevel.MEDIO),
    ("/actuator/env", ExposureType.DIAGNOSTIC_INTERFACE, "Endpoint de Spring Boot Actuator con variables de entorno", SeverityLevel.CRITICO),
    ("/actuator/heapdump", ExposureType.DIAGNOSTIC_INTERFACE, "Endpoint de volcado de memoria Spring Boot", SeverityLevel.CRITICO),
    ("/actuator/health", ExposureType.DIAGNOSTIC_INTERFACE, "Endpoint de salud Spring Boot Actuator", SeverityLevel.BAJO),
    ("/elmah.axd", ExposureType.DIAGNOSTIC_INTERFACE, "Registro de errores ELMAH en .NET", SeverityLevel.ALTO),
    ("/trace.axd", ExposureType.DIAGNOSTIC_INTERFACE, "Trazador de depuración ASP.NET", SeverityLevel.MEDIO),

    # Directorios propensos a listado abierto
    ("/uploads/", ExposureType.DIRECTORY_LISTING, "Directorio de archivos subidos", SeverityLevel.MEDIO),
    ("/backup/", ExposureType.DIRECTORY_LISTING, "Directorio de respaldos", SeverityLevel.ALTO),
    ("/backups/", ExposureType.DIRECTORY_LISTING, "Directorio de respaldos", SeverityLevel.ALTO),
    ("/files/", ExposureType.DIRECTORY_LISTING, "Directorio público de archivos", SeverityLevel.BAJO),
    ("/data/", ExposureType.DIRECTORY_LISTING, "Directorio de datos", SeverityLevel.MEDIO),
    ("/db/", ExposureType.DIRECTORY_LISTING, "Directorio de base de datos", SeverityLevel.ALTO),
    ("/sql/", ExposureType.DIRECTORY_LISTING, "Directorio de scripts SQL", SeverityLevel.ALTO),
    ("/dump/", ExposureType.DIRECTORY_LISTING, "Directorio de volcados", SeverityLevel.ALTO),
    ("/logs/", ExposureType.DIRECTORY_LISTING, "Directorio de registros del sistema", SeverityLevel.ALTO),
]


class DirectHttpChecker(BaseSourceProvider):
    """Realiza comprobaciones directas concurrentes sobre los activos autorizados."""

    MAX_CHUNK_BYTES = 8192  # Leer como máximo 8 KB para inspección sin transferir volcados completos
    CONCURRENT_WORKERS = 20 # Hilos concurrentes para escaneo rápido

    def __init__(self):
        super().__init__(
            source_id="direct_http_verifier",
            name="Comprobaciones HTTP Directas de Bajo Impacto",
            category="DIRECT_CHECK"
        )

    def _read_decompressed_chunk(self, resp: requests.Response) -> bytes:
        """Lee hasta MAX_CHUNK_BYTES de forma segura manejando descompresión gzip/deflate."""
        chunks = []
        total = 0
        try:
            for c in resp.iter_content(chunk_size=4096):
                chunks.append(c)
                total += len(c)
                if total >= self.MAX_CHUNK_BYTES:
                    break
        except Exception:
            pass
        return b"".join(chunks)[:self.MAX_CHUNK_BYTES]

    def _get_404_baseline(self, base_url: str, session: requests.Session) -> Tuple[Set[str], Set[str]]:
        """Obtiene hashes y títulos de páginas de error 404 para evitar falsos positivos."""
        hashes = set()
        titles = set()
        test_url = base_url.rstrip("/") + "/atlas_leak_probe_nonexistent_xyz987"
        try:
            r = session.get(test_url, timeout=(3.0, 5.0), allow_redirects=True, stream=True)
            chunk = self._read_decompressed_chunk(r)
            r.close()
            h = hashlib.md5(chunk).hexdigest()
            hashes.add(h)
            text = chunk.decode("utf-8", errors="ignore")
            if "<title>" in text.lower():
                import re
                m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                if m:
                    titles.add(m.group(1).strip().lower())
        except Exception:
            pass
        return hashes, titles

    def _probe_single_path(
        self,
        target: str,
        base_url: str,
        item: Tuple[str, ExposureType, str, SeverityLevel],
        session: requests.Session,
        baseline_hashes: Set[str],
        baseline_titles: Set[str],
        scope_validator: ScopeValidator
    ) -> Tuple[Optional[Finding], Optional[ExternalReference]]:
        rel_path, exp_type, description, severity = item
        target_url = base_url.rstrip("/") + rel_path

        try:
            resp = session.get(target_url, timeout=(3.0, 5.0), allow_redirects=True, stream=True)
            p_final = urlparse(resp.url)
            in_scope_final, _ = scope_validator.is_in_scope(p_final.netloc)
            if not in_scope_final:
                ref = ExternalReference(
                    source=self.source_id,
                    reference_value=resp.url,
                    relation_type="REDIRECT_EXTERNAL",
                    details=f"Petición a {target_url} redirigió fuera de alcance a {p_final.netloc}"
                )
                resp.close()
                return None, ref

            raw_chunk = self._read_decompressed_chunk(resp)
            resp.close()

            status_code = resp.status_code
            content_type = resp.headers.get("content-type", "").lower()
            chunk_text = raw_chunk.decode("utf-8", errors="ignore")
            chunk_hash = hashlib.md5(raw_chunk).hexdigest()

            # Descartar respuestas típicas de no encontrado o servidor caído
            if status_code in (404, 410, 502, 503, 504):
                return None, None

            # Descartar soft-404 por hash idéntico al baseline
            if chunk_hash in baseline_hashes:
                return None, None

            # Descartar páginas de error HTML con títulos baseline
            if "html" in content_type and baseline_titles:
                for bt in baseline_titles:
                    if bt in chunk_text.lower():
                        return None, None

            is_html = ("html" in content_type or "<html" in chunk_text.lower() or "<!doctype html" in chunk_text.lower())

            is_hit = False
            verification_status = VerificationStatus.OBSERVATION.value
            demonstrated_impact = ""
            potential_risk = ""
            remediation = ""
            evidence_sample = ""

            # 1. Comprobación de .env (NUNCA debe ser una página HTML)
            if exp_type == ExposureType.EXPOSED_CONFIG and rel_path.startswith("/.env"):
                if status_code == 200 and not is_html:
                    env_indicators = ["app_key=", "db_password=", "database_url=", "aws_access_key", "secret_key=", "smtp_pass=", "db_host=", "redis_"]
                    if any(ind in chunk_text.lower() for ind in env_indicators) and ("=" in chunk_text):
                        is_hit = True
                        verification_status = VerificationStatus.CONFIRMED_VULNERABILITY.value
                        demonstrated_impact = f"Acceso público a variables de entorno de producción ({status_code} OK)."
                        potential_risk = "Compromiso de credenciales de base de datos, API keys y secretos criptográficos."
                        remediation = "Bloquear acceso a archivos .* en el servidor web y rotar inmediatamente las credenciales."
                        evidence_sample = chunk_text[:600]

            # 2. Comprobación de .git (NUNCA debe ser una página HTML)
            elif exp_type == ExposureType.VERSION_CONTROL_EXPOSURE:
                if status_code == 200 and not is_html:
                    if "ref: refs/heads/" in chunk_text or ("[core]" in chunk_text and "repositoryformatversion" in chunk_text):
                        is_hit = True
                        verification_status = VerificationStatus.CONFIRMED_VULNERABILITY.value
                        demonstrated_impact = f"Directorio .git expuesto con metadatos de ramas o configuración ({status_code} OK)."
                        potential_risk = "Descarga del código fuente completo del proyecto e historial de commits."
                        remediation = "Configurar el servidor web para denegar el acceso a la carpeta .git/."
                        evidence_sample = chunk_text[:400]

            # 3. Comprobación de Backups / SQL (NUNCA debe ser una página HTML)
            elif exp_type == ExposureType.BACKUP_DATABASE_EXPOSURE:
                if status_code == 200 and not is_html:
                    sql_indicators = ["-- mysql dump", "-- postgresql database dump", "create table ", "insert into ", "sqlite format 3"]
                    is_sql_dump = any(ind in chunk_text.lower() for ind in sql_indicators)
                    is_archive = ("application/zip" in content_type or "application/x-gzip" in content_type) and (raw_chunk.startswith(b"PK\x03\x04") or raw_chunk.startswith(b"\x1f\x8b"))
                    
                    if is_sql_dump or is_archive:
                        is_hit = True
                        verification_status = VerificationStatus.CONFIRMED_VULNERABILITY.value
                        demonstrated_impact = f"Archivo de respaldo o volcado de base de datos accesible públicamente ({content_type})."
                        potential_risk = "Extracción masiva de bases de datos, registros de usuarios y datos corporativos."
                        remediation = "Mover los respaldos fuera del document root público y restringir permisos de lectura."
                        evidence_sample = chunk_text[:400] if is_sql_dump else f"[Archivo binario comprimido verificado: {len(raw_chunk)} bytes inspeccionados]"

            # 4. Listado de directorios abierto
            elif exp_type == ExposureType.DIRECTORY_LISTING:
                if status_code == 200 and is_html:
                    dir_indicators = ["index of /", "directory listing for", "<title>index of", "parent directory"]
                    if any(ind in chunk_text.lower() for ind in dir_indicators):
                        is_hit = True
                        verification_status = VerificationStatus.CONFIRMED_VULNERABILITY.value
                        demonstrated_impact = f"Listado de directorios activo en {rel_path} mostrando estructura de archivos."
                        potential_risk = "Navegación e indexación no autorizada de archivos internos y subidas."
                        remediation = "Desactivar la directiva 'autoindex' (Nginx) o 'Options -Indexes' (Apache)."
                        evidence_sample = chunk_text[:500]

            # 5. Interfaces de diagnóstico (phpinfo, actuator)
            elif exp_type == ExposureType.DIAGNOSTIC_INTERFACE:
                if status_code == 200:
                    if "phpinfo()" in chunk_text.lower() and ("configuration file (php.ini)" in chunk_text.lower() or "zend extension build" in chunk_text.lower()):
                        is_hit = True
                        verification_status = VerificationStatus.CONFIRMED_VULNERABILITY.value
                        demonstrated_impact = "Página phpinfo accesible con detalles de compilación y variables de servidor."
                        potential_risk = "Reconocimiento detallado de versiones de software, rutas locales y módulos cargados."
                        remediation = "Eliminar el archivo phpinfo de entornos públicos o protegerlo tras autenticación."
                        evidence_sample = chunk_text[:400]
                    elif "/actuator" in rel_path and not is_html:
                        if rel_path == "/actuator/heapdump":
                            if raw_chunk.startswith(b"JAVA PROFILE"):
                                is_hit = True
                                verification_status = VerificationStatus.CONFIRMED_VULNERABILITY.value
                                demonstrated_impact = "Descarga de volcado de memoria Java (HPROF heapdump) accesible."
                                potential_risk = "Extracción de secretos en memoria, tokens de sesión y contraseñas en claro."
                                remediation = "Deshabilitar el endpoint management.endpoint.heapdump.enabled=false."
                                evidence_sample = "[Encabezado binario HPROF 'JAVA PROFILE' verificado]"
                        else:
                            is_actuator_json = False
                            try:
                                import json
                                data = json.loads(chunk_text)
                                if isinstance(data, dict):
                                    if rel_path.startswith("/actuator/health") and ("status" in data or "components" in data):
                                        is_actuator_json = True
                                    elif rel_path.startswith("/actuator/env") and ("activeProfiles" in data or "propertySources" in data):
                                        is_actuator_json = True
                                    elif rel_path.startswith("/actuator") and ("_links" in data or "activeProfiles" in data or "status" in data):
                                        is_actuator_json = True
                            except Exception:
                                pass

                            if is_actuator_json:
                                is_hit = True
                                verification_status = VerificationStatus.CONFIRMED_VULNERABILITY.value
                                demonstrated_impact = f"Endpoint Spring Boot Actuator expuesto ({rel_path}) con estructura JSON verificada."
                                potential_risk = "Divulgación de variables de configuración, perfiles y estado interno de la aplicación."
                                remediation = "Configurar management.endpoints.web.exposure.exclude=* en application.properties."
                                evidence_sample = chunk_text[:400]

            if is_hit:
                safe_evidence = SecretRedactor.redact(evidence_sample)
                detected_secrets = SecretRedactor.scan_for_secrets(evidence_sample)
                limitations = "Inspección pasiva limitada a los primeros 8 KB de respuesta mediante conexión directa autorizada."

                finding = Finding(
                    id="EXP-TMP",
                    target_asset=target,
                    exposure_type=exp_type.value,
                    source=self.source_id,
                    reference_url=target_url,
                    timestamp=datetime.now().isoformat(),
                    verification_status=verification_status,
                    evidence=safe_evidence,
                    potential_risk=potential_risk,
                    demonstrated_impact=demonstrated_impact,
                    remediation=remediation,
                    limitations=limitations,
                    severity=severity.value,
                    reproduction_steps=f"curl -I -s -A 'AtlasScan-Audit/1.0' '{target_url}'",
                    extra_metadata={
                        "http_status": status_code,
                        "content_type": content_type,
                        "path": rel_path,
                        "detected_secret_patterns": [s["pattern_name"] for s in detected_secrets]
                    }
                )
                return finding, None

        except requests.RequestException:
            pass
        except Exception:
            pass

        return None, None

    def run(
        self,
        scope: AuditScope,
        session: requests.Session,
        scope_validator: ScopeValidator,
        is_cancelled: Callable[[], bool],
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[List[Finding], List[ExternalReference], SourceStatus]:
        t0 = time.time()
        findings: List[Finding] = []
        references: List[ExternalReference] = []

        # Recopilar todos los destinos a auditar
        targets = set()
        if scope.root_domain:
            targets.add(scope.root_domain)
        for s in scope.authorized_subdomains:
            if "*" not in s:
                targets.add(s)

        valid_targets = []
        for t in targets:
            in_scope, reason = scope_validator.is_in_scope(t)
            if in_scope:
                safe_ip, ip_msg = scope_validator.check_ssrf_safety(t)
                if safe_ip:
                    valid_targets.append(t)
                else:
                    if progress_callback:
                        progress_callback(f"[!] Destino '{t}' descartado por seguridad SSRF: {ip_msg}")
            else:
                if progress_callback:
                    progress_callback(f"[*] Destino '{t}' omitido: {reason}")

        if not valid_targets:
            return findings, references, SourceStatus(
                source_id=self.source_id,
                name=self.name,
                category=self.category,
                status="SUCCESS",
                findings_count=0,
                duration_seconds=round(time.time() - t0, 2),
                message="No se encontraron destinos válidos y seguros para comprobación directa."
            )

        # Preparar trabajos para ejecución paralela ultrarrápida
        probe_tasks = []
        for target in valid_targets:
            if is_cancelled():
                break
            base_url = f"https://{target}"
            if progress_callback:
                progress_callback(f"Evaluando baseline y comprobaciones directas en: {target}")

            baseline_hashes, baseline_titles = self._get_404_baseline(base_url, session)

            for item in DIRECT_CHECK_PATHS:
                probe_tasks.append((target, base_url, item, baseline_hashes, baseline_titles))

        total_probes = len(probe_tasks)
        if progress_callback:
            progress_callback(f"[*] Lanzando {total_probes} comprobaciones concurrentes ({self.CONCURRENT_WORKERS} workers)...")

        # Ejecución concurrente mediante ThreadPoolExecutor
        completed = 0
        finding_counter = 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.CONCURRENT_WORKERS) as pool:
            futures = {
                pool.submit(
                    self._probe_single_path,
                    target,
                    base_url,
                    item,
                    session,
                    b_hashes,
                    b_titles,
                    scope_validator
                ): (target, item[0])
                for target, base_url, item, b_hashes, b_titles in probe_tasks
            }

            for fut in concurrent.futures.as_completed(futures):
                if is_cancelled():
                    break
                completed += 1
                try:
                    res_finding, res_ref = fut.result()
                    if res_finding:
                        res_finding.id = f"EXP-DIR-{finding_counter:03d}"
                        finding_counter += 1
                        findings.append(res_finding)
                        if progress_callback:
                            progress_callback(f" [!] {res_finding.verification_status}: {res_finding.target_asset} ({res_finding.reference_url})")
                    if res_ref:
                        references.append(res_ref)
                except Exception:
                    pass

        elapsed = round(time.time() - t0, 2)
        status = SourceStatus(
            source_id=self.source_id,
            name=self.name,
            category=self.category,
            status="SUCCESS",
            findings_count=len(findings),
            duration_seconds=elapsed,
            message=f"{total_probes} comprobaciones directas completadas sobre {len(valid_targets)} destino(s) en {elapsed}s."
        )
        return findings, references, status
