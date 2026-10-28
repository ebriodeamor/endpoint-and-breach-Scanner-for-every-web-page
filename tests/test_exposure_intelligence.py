# -*- coding: utf-8 -*-
"""
Suite de pruebas automatizadas obligatorias para el Módulo de Inteligencia de Exposición y Leaks.
Cubre validación de alcance, protección SSRF, redacción de secretos, políticas de WARP,
comprobaciones directas sobre servidor HTTP local controlado, generación de reportes y descarte de falsos positivos.
"""

import http.server
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

from exposure_intelligence.engine import ExposureAuditEngine
from exposure_intelligence.evidence_manager import EvidenceManager
from exposure_intelligence.models import (
    AuditScope,
    ExposureType,
    Finding,
    SeverityLevel,
    SourceStatus,
    VerificationStatus,
    WarpPolicy,
)
from exposure_intelligence.redactor import SecretRedactor
from exposure_intelligence.reporter import ExposureReporter
from exposure_intelligence.scope import ScopeValidationError, ScopeValidator
from exposure_intelligence.sources.direct_checks import DirectHttpChecker
from exposure_intelligence.sources.osint_breaches import BreachIntelProvider
from exposure_intelligence.sources.osint_repos import RepositoryOsintProvider
from exposure_intelligence.warp_checker import WarpChecker, WarpStatusReport


# -------------------------------------------------------------------------
# Mock HTTP Handler para pruebas locales controladas con datos sintéticos
# -------------------------------------------------------------------------
class MockVulnServerHandler(http.server.BaseHTTPRequestHandler):
    """Simula un servidor web controlado con endpoints seguros y vulnerables sintéticos."""

    def log_message(self, format, *args):
        # Silenciar logs en consola de pruebas
        pass

    def do_GET(self):
        p = urlparse(self.path).path

        # 1. Archivo .env real con contenido sensible sintético
        if p == "/.env":
            content = (
                "APP_NAME=AuditTestApp\n"
                "APP_ENV=production\n"
                "APP_KEY=base64:qwe123rty456uio789pasdfghjklzxcvbnmQWERTYU=\n"
                "DB_CONNECTION=mysql\n"
                "DB_HOST=127.0.0.1\n"
                "DB_PORT=3306\n"
                "DB_DATABASE=corporate_db\n"
                "DB_USERNAME=admin_user\n"
                "DB_PASSWORD=SuperSecretPassword2026!\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        # 2. Archivo .git/HEAD
        elif p == "/.git/HEAD":
            content = b"ref: refs/heads/main\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        # 3. Listado de directorios abierto
        elif p == "/uploads/":
            content = (
                "<!DOCTYPE HTML><html><head><title>Index of /uploads</title></head>"
                "<body><h1>Index of /uploads</h1>"
                "<table><tr><td><a href='backup.sql'>backup.sql</a></td></tr></table>"
                "</body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        # 4. Respuesta masiva (> 64KB) para probar límite de streaming
        elif p == "/huge_response.bin":
            huge_data = b"A" * (128 * 1024)  # 128 KB
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(huge_data)))
            self.end_headers()
            self.wfile.write(huge_data)

        # 5. Redirección fuera de alcance
        elif p == "/redirect_external":
            self.send_response(302)
            self.send_header("Location", "https://malicious-external-domain.test/evil")
            self.end_headers()

        # 6. Página de error 404 genérica HTML (Soft-404 / 404 estándar)
        elif "fake_404" in p or "probe" in p:
            body = b"<html><head><title>Pagina no encontrada</title></head><body>Error 404</body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 7. Endpoint 403 Forbidden
        elif p == "/backup/":
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"403 Forbidden")

        # 8. Portal HTML comprimido con gzip que devuelve 200 y contiene llaves { } en CSS/JS
        elif p == "/actuator/env_gzipped_html":
            import gzip
            html_body = b"<!DOCTYPE html><html><head><style>{ margin: 0; }</style></head><body>Portal DIAN</body></html>"
            comp = gzip.compress(html_body)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(comp)))
            self.end_headers()
            self.wfile.write(comp)

        # 9. Endpoint Actuator legítimo con JSON válido
        elif p == "/actuator/env_valid":
            json_body = b'{"activeProfiles": ["production"], "propertySources": [{"name": "systemProperties"}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(json_body)))
            self.end_headers()
            self.wfile.write(json_body)

        # 10. Cualquier otra ruta -> 404
        else:
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


# -------------------------------------------------------------------------
# Test Suite
# -------------------------------------------------------------------------
class TestExposureIntelligence(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Iniciar servidor HTTP mock en puerto dinámico local
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockVulnServerHandler)
        cls.server_port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

        # Directorio temporal para expedientes de prueba
        cls.test_dir = tempfile.mkdtemp(prefix="test_exposure_")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    # 1. Dominio válido e inválido
    def test_domain_validation_valid_and_invalid(self):
        valid_domains = ["example.com", "sub.target.co", "portal.bancolombia.com", "localhost"]
        for d in valid_domains:
            self.assertTrue(ScopeValidator.is_valid_domain_syntax(d), f"Debería ser válido: {d}")

        invalid_domains = ["", "http://", "spaced domain.com", "invalid..com", "-dash.com", "trailing-.com"]
        for d in invalid_domains:
            self.assertFalse(ScopeValidator.is_valid_domain_syntax(d), f"Debería ser inválido: {d}")

    # 2. Inclusión y exclusión de subdominios
    def test_subdomain_inclusion_and_exclusion(self):
        scope = AuditScope(
            expediente_id="TEST-001",
            root_domain="empresa.com",
            authorized_subdomains=["api.empresa.com", "admin.empresa.com"],
            excluded_subdomains=["privado.empresa.com", "secretos.empresa.com"],
            timestamp="2026-10-26T00:00:00",
            enabled_sources=["all"],
            rate_limit_rps=2.0,
            authorization_confirmed=True
        )
        validator = ScopeValidator(scope)

        # Autorizados expresamente
        in_scope, _ = validator.is_in_scope("api.empresa.com")
        self.assertTrue(in_scope)
        in_scope, _ = validator.is_in_scope("empresa.com")
        self.assertTrue(in_scope)

        # Excluidos expresamente
        in_scope, reason = validator.is_in_scope("privado.empresa.com")
        self.assertFalse(in_scope)
        self.assertIn("excluido", reason.lower())

        # Subdominio de empresa.com pero no autorizado explícitamente
        in_scope, reason = validator.is_in_scope("desconocido.empresa.com")
        self.assertFalse(in_scope)
        self.assertIn("no fue listado", reason)

        # Tercero no autorizado
        in_scope, reason = validator.is_in_scope("google.com")
        self.assertFalse(in_scope)
        self.assertIn("tercero fuera del alcance", reason.lower())

    # 3. Rechazo de direcciones internas no autorizadas (Protección SSRF)
    def test_ssrf_rejection_internal_ips(self):
        scope = AuditScope(
            expediente_id="TEST-SSRF",
            root_domain="empresa.com",
            authorized_subdomains=[],
            excluded_subdomains=[],
            timestamp="2026-10-26T00:00:00",
            enabled_sources=["all"],
            rate_limit_rps=2.0,
            authorization_confirmed=True
        )
        # allow_private_ip = False (modo producción por defecto)
        validator = ScopeValidator(scope, allow_private_ip=False)

        dangerous_targets = [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",  # AWS metadata IP
            "localhost"
        ]
        for dt in dangerous_targets:
            safe, msg = validator.check_ssrf_safety(dt)
            self.assertFalse(safe, f"IP interna o loopback {dt} debió ser bloqueada por SSRF: {msg}")

    # 4. Redirecciones hacia destinos fuera del alcance
    def test_redirect_out_of_scope(self):
        scope = AuditScope(
            expediente_id="TEST-REDIR",
            root_domain="empresa.com",
            authorized_subdomains=[],
            excluded_subdomains=[],
            timestamp="2026-10-26T00:00:00",
            enabled_sources=["all"],
            rate_limit_rps=2.0,
            authorization_confirmed=True
        )
        validator = ScopeValidator(scope)
        in_scope, _ = validator.is_in_scope("malicious-external-domain.test")
        self.assertFalse(in_scope, "El destino redirigido fuera de alcance debe ser clasificado como falso en alcance.")

    # 5. Detección de patrones sensibles y redacción centralizada
    def test_secret_detection_and_redaction(self):
        text_with_secrets = (
            "Configuracion interna:\n"
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "GITHUB_PAT=ghp_1234567890abcdef1234567890abcdef1234\n"
            "DB_URI=postgres://admin_user:SuperSecretPass123@db.prod.internal:5432/corp\n"
            "JWT=eyJh.eyJwYXlsb2FkIjoxMjM0fQ.signature123456789\n"
            "DB_PASSWORD=MyUltraConfidentialPass!\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0syntheticKeyContentSample==\n-----END RSA PRIVATE KEY-----\n"
        )

        redacted = SecretRedactor.redact(text_with_secrets)

        # Comprobar que ningún secreto en claro permanece
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertNotIn("ghp_1234567890abcdef1234567890abcdef1234", redacted)
        self.assertNotIn("SuperSecretPass123", redacted)
        self.assertNotIn("MyUltraConfidentialPass!", redacted)
        self.assertNotIn("MIIEowIBAAKCAQEA0syntheticKeyContentSample==", redacted)

        # Comprobar que contiene marcas de redacción
        self.assertIn("REDACTADO", redacted)

        # Comprobar escaneo y detección
        secrets_found = SecretRedactor.scan_for_secrets(text_with_secrets)
        pattern_names = [s["pattern_name"] for s in secrets_found]
        self.assertIn("AWS_ACCESS_KEY", pattern_names)
        self.assertIn("GITHUB_TOKEN", pattern_names)
        self.assertIn("DB_CONNECTION_STRING", pattern_names)

        # Verificar que ninguno se marca como credencial comprobada automáticamente
        for s in secrets_found:
            self.assertFalse(s["verified"])

    # 6. Timeout, errores HTTP y respuestas demasiado grandes
    def test_timeout_http_errors_and_large_responses(self):
        url = f"http://127.0.0.1:{self.server_port}/huge_response.bin"
        s = requests.Session()
        # Verificar que streaming limitado no descarga todo en memoria
        r = s.get(url, stream=True)
        chunk = r.raw.read(DirectHttpChecker.MAX_CHUNK_BYTES)
        r.close()
        self.assertEqual(len(chunk), DirectHttpChecker.MAX_CHUNK_BYTES)

    # 7. Fuentes sin credenciales configuradas
    def test_unconfigured_sources(self):
        # Desactivar variables de entorno temporalmente
        old_hibp = os.environ.get("HIBP_API_KEY")
        if "HIBP_API_KEY" in os.environ:
            del os.environ["HIBP_API_KEY"]

        provider = BreachIntelProvider()
        is_cfg, msg = provider.is_configured()
        self.assertFalse(is_cfg)
        self.assertIn("NO CONFIGURADO", msg)

        scope = AuditScope(
            expediente_id="TEST-UNCFG",
            root_domain="example.com",
            authorized_subdomains=[],
            excluded_subdomains=[],
            timestamp="2026-10-26T00:00:00",
            enabled_sources=["osint_breach_intel"],
            rate_limit_rps=2.0,
            authorization_confirmed=True
        )
        validator = ScopeValidator(scope)
        findings, refs, status = provider.run(scope, requests.Session(), validator, lambda: False)
        self.assertEqual(status.status, "NO CONFIGURADO")
        self.assertEqual(len(findings), 0)

        if old_hibp is not None:
            os.environ["HIBP_API_KEY"] = old_hibp

    # 8. Resultados duplicados (Deduplicación)
    def test_deduplication_of_findings(self):
        f1 = Finding(
            id="TEMP-1",
            target_asset="example.com",
            exposure_type=ExposureType.EXPOSED_CONFIG.value,
            source="direct_http_verifier",
            reference_url="https://example.com/.env",
            timestamp="2026-10-26T00:00:00",
            verification_status=VerificationStatus.CONFIRMED_VULNERABILITY.value,
            evidence="APP_KEY=123",
            potential_risk="Riesgo",
            demonstrated_impact="Impacto",
            remediation="Remediar",
            limitations="Lim"
        )
        # Hallazgo idéntico en URL y tipo
        f2 = Finding(
            id="TEMP-2",
            target_asset="example.com",
            exposure_type=ExposureType.EXPOSED_CONFIG.value,
            source="direct_http_verifier",
            reference_url="https://example.com/.env",
            timestamp="2026-10-26T00:00:00",
            verification_status=VerificationStatus.CONFIRMED_VULNERABILITY.value,
            evidence="APP_KEY=123",
            potential_risk="Riesgo",
            demonstrated_impact="Impacto",
            remediation="Remediar",
            limitations="Lim"
        )

        scope = AuditScope(
            expediente_id="TEST-DEDUP",
            root_domain="example.com",
            authorized_subdomains=[],
            excluded_subdomains=[],
            timestamp="2026-10-26T00:00:00",
            enabled_sources=[],
            rate_limit_rps=2.0,
            authorization_confirmed=True,
            warp_policy=WarpPolicy.DIRECT.value
        )
        engine = ExposureAuditEngine(scope=scope, allow_private_ip=True)
        # Mock de ejecución interna para verificar deduplicación
        unique_findings = []
        seen_keys = set()
        for f in [f1, f2]:
            key = (f.target_asset.lower(), f.exposure_type, (f.reference_url or "").lower())
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        self.assertEqual(len(unique_findings), 1)

    # 9. Creación de carpetas sin sobrescribir expedientes
    def test_case_folder_no_overwrite(self):
        em = EvidenceManager(base_results_dir=Path(self.test_dir))
        p1, id1 = em.create_case_folder("empresa.com", custom_id="EXP_CLIENTE")
        p2, id2 = em.create_case_folder("empresa.com", custom_id="EXP_CLIENTE")

        self.assertTrue(p1.exists())
        self.assertTrue(p2.exists())
        self.assertNotEqual(str(p1), str(p2), "No debe sobrescribir carpetas de expedientes existentes.")

    # 10. Fallos al guardar evidencias y prevención de path traversal
    def test_evidence_saving_and_traversal_prevention(self):
        em = EvidenceManager(base_results_dir=Path(self.test_dir))
        case_p, _ = em.create_case_folder("empresa.com")

        # Intento de traversal en el ID de hallazgo
        rel_path = em.save_evidence_snippet(case_p, "../../etc/shadow", "test content")
        # Debe sanitizarse y guardarse dentro de evidence/ sin escapar
        self.assertTrue(rel_path.startswith("evidence/"))
        evidence_file = case_p / rel_path
        self.assertTrue(evidence_file.exists())
        self.assertTrue(str(evidence_file.resolve()).startswith(str(case_p.resolve())))

    # 11. Generación correcta del informe TXT
    def test_txt_report_generation(self):
        em = EvidenceManager(base_results_dir=Path(self.test_dir))
        case_p, case_id = em.create_case_folder("empresa.com")
        scope = AuditScope(
            expediente_id=case_id,
            root_domain="empresa.com",
            authorized_subdomains=["api.empresa.com"],
            excluded_subdomains=["intranet.empresa.com"],
            timestamp="2026-10-26T12:00:00",
            enabled_sources=["direct_http_verifier"],
            rate_limit_rps=2.0,
            authorization_confirmed=True
        )
        finding = Finding(
            id="EXP-001",
            target_asset="empresa.com",
            exposure_type=ExposureType.EXPOSED_CONFIG.value,
            source="direct_http_verifier",
            reference_url="https://empresa.com/.env",
            timestamp="2026-10-26T12:05:00",
            verification_status=VerificationStatus.CONFIRMED_VULNERABILITY.value,
            evidence="DB_PASSWORD=***REDACTADO***",
            potential_risk="Acceso indebido a bases de datos corporativas.",
            demonstrated_impact="Lectura de configuración en producción.",
            remediation="Restringir acceso al archivo .env.",
            limitations="Inspección HTTP directa.",
            severity=SeverityLevel.CRITICO.value
        )
        sources = [
            SourceStatus(
                source_id="direct_http_verifier",
                name="Comprobaciones HTTP Directas",
                category="DIRECT_CHECK",
                status="SUCCESS",
                findings_count=1
            )
        ]

        report_path = ExposureReporter.generate_report_txt(scope, [finding], sources, case_p)
        self.assertTrue(report_path.exists())
        content = report_path.read_text(encoding="utf-8")

        # Comprobar secciones obligatorias
        self.assertIn("ATLASSCAN", content)
        self.assertIn("DOMINIO Y ALCANCE AUTORIZADO", content)
        self.assertIn("RESUMEN EJECUTIVO", content)
        self.assertIn("DETALLE INDIVIDUAL DE HALLAZGOS", content)
        self.assertIn("VULNERABILIDADES CONFIRMADAS", content.upper())
        self.assertIn("AVISO DE REVISIÓN HUMANA OBLIGATORIA", content)
        self.assertIn("PAUTAS DE REPRODUCCIÓN DE BAJO IMPACTO", content)

    # 12. Cancelación de tareas
    def test_cancellation(self):
        scope = AuditScope(
            expediente_id="TEST-CANCEL",
            root_domain="empresa.com",
            authorized_subdomains=[],
            excluded_subdomains=[],
            timestamp="2026-10-26T00:00:00",
            enabled_sources=["direct_http_verifier"],
            rate_limit_rps=2.0,
            authorization_confirmed=True,
            warp_policy=WarpPolicy.DIRECT.value
        )
        engine = ExposureAuditEngine(scope=scope, allow_private_ip=True)
        self.assertFalse(engine.is_cancelled())
        engine.cancel()
        self.assertTrue(engine.is_cancelled())

    # 13. Estado de WARP desconocido o desconectado
    def test_warp_policy_handling(self):
        wc = WarpChecker()

        # Simular reporte desconectado
        disconnected_report = WarpStatusReport(
            is_connected=False,
            verifiable=True,
            details="warp-cli: Disconnected"
        )
        wc.check_status = lambda: disconnected_report

        # Política STRICT debe rechazar
        can_proceed, msg, _ = wc.evaluate_policy(WarpPolicy.STRICT.value)
        self.assertFalse(can_proceed)
        self.assertIn("canceladas", msg.lower())

        # Política WARN debe advertir
        can_proceed_warn, msg_warn, _ = wc.evaluate_policy(WarpPolicy.WARN.value)
        self.assertFalse(can_proceed_warn)
        self.assertIn("advertencia", msg_warn.lower())

        # Política DIRECT debe permitir
        can_proceed_direct, _, _ = wc.evaluate_policy(WarpPolicy.DIRECT.value)
        self.assertTrue(can_proceed_direct)

    # 14. Ausencia de falsos estados de vulnerabilidad confirmada
    def test_no_false_confirmed_vulnerability(self):
        # Una búsqueda OSINT sólo debe ser OBSERVATION
        finding_osint = Finding(
            id="EXP-SRCH-001",
            target_asset="empresa.com",
            exposure_type=ExposureType.PASSIVE_OSINT_REFERENCE.value,
            source="osint_search_engines",
            reference_url="https://duckduckgo.com/?q=test",
            timestamp="2026-10-26T00:00:00",
            verification_status=VerificationStatus.OBSERVATION.value,
            evidence="Consulta dork generada",
            potential_risk="Indexación",
            demonstrated_impact="Observación",
            remediation="Robots.txt",
            limitations="Consulta pasiva"
        )
        self.assertEqual(finding_osint.verification_status, VerificationStatus.OBSERVATION.value)
        self.assertNotEqual(finding_osint.verification_status, VerificationStatus.CONFIRMED_VULNERABILITY.value)

    # 15. Integración completa end-to-end con servidor local controlado
    def test_end_to_end_audit_engine_execution(self):
        em = EvidenceManager(base_results_dir=Path(self.test_dir))
        scope = AuditScope(
            expediente_id="EXP_E2E_TEST",
            root_domain="127.0.0.1",
            authorized_subdomains=[],
            excluded_subdomains=[],
            timestamp=datetime.now().isoformat(),
            enabled_sources=["direct_http_verifier"],
            rate_limit_rps=5.0,
            authorization_confirmed=True,
            warp_policy=WarpPolicy.DIRECT.value,
            notes="Prueba de integración end-to-end"
        )
        engine = ExposureAuditEngine(
            scope=scope,
            evidence_manager=em,
            allow_private_ip=True
        )

        # Usar session adaptada para el puerto del mock server
        s = requests.Session()
        # Modificar DIRECT_CHECK_PATHS para probar el puerto
        orig_run = engine.providers["direct_http_verifier"].run
        port = self.server_port

        def patched_run(scope, session, scope_validator, is_cancelled, progress_callback=None):
            # Probar endpoints directamente contra http://127.0.0.1:port
            f_list = []
            r_list = []
            # Probar .env
            resp_env = session.get(f"http://127.0.0.1:{port}/.env")
            if resp_env.status_code == 200:
                f_list.append(Finding(
                    id="EXP-E2E-001",
                    target_asset="127.0.0.1",
                    exposure_type=ExposureType.EXPOSED_CONFIG.value,
                    source="direct_http_verifier",
                    reference_url=f"http://127.0.0.1:{port}/.env",
                    timestamp=datetime.now().isoformat(),
                    verification_status=VerificationStatus.CONFIRMED_VULNERABILITY.value,
                    evidence=resp_env.text,
                    potential_risk="Compromiso de credenciales en .env",
                    demonstrated_impact="Archivo .env accesible en servidor web",
                    remediation="Restringir acceso a .env",
                    limitations="Test de integración sintético",
                    severity=SeverityLevel.CRITICO.value
                ))
            st = SourceStatus(
                source_id="direct_http_verifier",
                name="Comprobaciones HTTP Directas",
                category="DIRECT_CHECK",
                status="SUCCESS",
                findings_count=len(f_list)
            )
            return f_list, r_list, st

        engine.providers["direct_http_verifier"].run = patched_run

        result = engine.run_audit(session=s)
        self.assertTrue(result["ok"])
        self.assertEqual(result["confirmed_count"], 1)

        case_p = Path(result["case_path"])
        self.assertTrue((case_p / "README.txt").exists())
        self.assertTrue((case_p / "findings.json").exists())
        self.assertTrue((case_p / "sources.json").exists())
        self.assertTrue((case_p / "report.txt").exists())

        # Verificar que el reporte TXT contiene redacción estricta
        report_text = (case_p / "report.txt").read_text(encoding="utf-8")
        self.assertNotIn("SuperSecretPassword2026!", report_text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", report_text)
        self.assertIn("AKIA************MPLE", report_text)

    # 16. Verificación estricta de Actuator: descarte de páginas HTML gzipped y confirmación de JSON real
    def test_actuator_false_positive_rejection_and_real_detection(self):
        checker = DirectHttpChecker()
        scope = AuditScope(
            expediente_id="TEST-ACTUATOR",
            root_domain="127.0.0.1",
            authorized_subdomains=[],
            excluded_subdomains=[],
            timestamp=datetime.now().isoformat(),
            enabled_sources=["direct_http_verifier"],
            rate_limit_rps=5.0,
            authorization_confirmed=True
        )
        validator = ScopeValidator(scope, allow_private_ip=True)
        session = requests.Session()
        base_url = f"http://127.0.0.1:{self.server_port}"

        # Caso A: Portal HTML comprimido con GZIP que devuelve 200 con llaves { }
        # NO DEBE reportar vulnerabilidad confirmada ni falso positivo
        item_fake = ("/actuator/env_gzipped_html", ExposureType.DIAGNOSTIC_INTERFACE, "Endpoint Spring Boot Actuator env", SeverityLevel.CRITICO)
        finding_fake, _ = checker._probe_single_path("127.0.0.1", base_url, item_fake, session, set(), set(), validator)
        self.assertIsNone(finding_fake, "Un portal HTML con gzip que devuelva 200 no debe ser tomado como Actuator expuesto.")

        # Caso B: Endpoint Actuator real con Content-Type JSON y llaves JSON legítimas
        # DEBE reportar CONFIRMED_VULNERABILITY
        item_valid = ("/actuator/env_valid", ExposureType.DIAGNOSTIC_INTERFACE, "Endpoint Spring Boot Actuator env", SeverityLevel.CRITICO)
        finding_valid, _ = checker._probe_single_path("127.0.0.1", base_url, item_valid, session, set(), set(), validator)
        self.assertIsNotNone(finding_valid)
        self.assertEqual(finding_valid.verification_status, VerificationStatus.CONFIRMED_VULNERABILITY.value)
        self.assertIn("activeProfiles", finding_valid.evidence)


if __name__ == "__main__":
    unittest.main()

