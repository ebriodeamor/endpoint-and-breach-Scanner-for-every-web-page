# -*- coding: utf-8 -*-
"""
Motor central de orquestación de la auditoría de exposición y leaks.
Coordina proveedores, valida alcance, gestiona la cancelación segura,
persiste evidencias y genera reportes.
"""

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import requests

from .evidence_manager import EvidenceManager
from .models import (
    AuditScope,
    ExternalReference,
    Finding,
    SourceStatus,
    VerificationStatus,
    WarpPolicy,
)
from .redactor import SecretRedactor
from .reporter import ExposureReporter
from .scope import ScopeValidationError, ScopeValidator
from .sources.base import BaseSourceProvider
from .sources.direct_checks import DirectHttpChecker
from .sources.osint_breaches import BreachIntelProvider
from .sources.osint_crtsh import CertificateTransparencyProvider
from .sources.osint_repos import RepositoryOsintProvider
from .sources.osint_search import SearchOsintProvider
from .warp_checker import WarpChecker


class ExposureAuditEngine:
    """Orquestador principal de auditoría de exposición y leaks."""

    def __init__(
        self,
        scope: AuditScope,
        evidence_manager: Optional[EvidenceManager] = None,
        warp_checker: Optional[WarpChecker] = None,
        allow_private_ip: bool = False
    ):
        self.scope = scope
        self.evidence_manager = evidence_manager or EvidenceManager()
        self.warp_checker = warp_checker or WarpChecker()
        self.allow_private_ip = allow_private_ip
        self.scope_validator = ScopeValidator(scope, allow_private_ip=allow_private_ip)

        self._cancelled = False
        self._lock = threading.Lock()

        # Registro de proveedores disponibles
        self.providers: Dict[str, BaseSourceProvider] = {
            "direct_http_verifier": DirectHttpChecker(),
            "osint_crtsh": CertificateTransparencyProvider(),
            "osint_search_engines": SearchOsintProvider(),
            "osint_public_repos": RepositoryOsintProvider(),
            "osint_breach_intel": BreachIntelProvider(),
        }

    def cancel(self):
        """Cancela la ejecución de tareas pendientes de forma segura."""
        with self._lock:
            self._cancelled = True

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    def run_audit(
        self,
        session: requests.Session,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Dict:
        """
        Ejecuta la auditoría completa respetando la política de WARP y el alcance.
        Devuelve un diccionario resumen con resultados, expedientes y rutas de reporte.
        """
        t0 = time.time()
        self._cancelled = False

        if progress_callback:
            progress_callback(f"[*] Iniciando auditoría para dominio: {self.scope.root_domain}")

        # 1. Validación sintáctica del dominio raíz
        if not ScopeValidator.is_valid_domain_syntax(self.scope.root_domain):
            raise ScopeValidationError(f"El dominio raíz '{self.scope.root_domain}' no tiene una sintaxis válida.")

        # 2. Evaluación de política de Cloudflare WARP
        can_proceed, warp_msg, warp_report = self.warp_checker.evaluate_policy(self.scope.warp_policy)
        if not can_proceed:
            if progress_callback:
                progress_callback(f"[!] Política de red no superada: {warp_msg}")
            return {
                "ok": False,
                "error": warp_msg,
                "warp_report": warp_report.to_dict(),
                "findings": [],
                "sources": [],
                "case_path": None,
                "report_file": None
            }

        if progress_callback:
            progress_callback(f"[+] Estado de red validado: {warp_msg}")

        # 3. Creación segura de carpeta de expediente
        case_path, case_id = self.evidence_manager.create_case_folder(
            root_domain=self.scope.root_domain,
            custom_id=self.scope.expediente_id
        )
        self.scope.expediente_id = case_id
        self.evidence_manager.save_readme(case_path, self.scope)

        if progress_callback:
            progress_callback(f"[+] Expediente creado: {case_path}")

        all_findings: List[Finding] = []
        all_references: List[ExternalReference] = []
        source_statuses: List[SourceStatus] = []

        # 4. Ejecución modular con progresión inteligente:
        # Primero fuentes pasivas (OSINT) y luego comprobación directa sobre todos los activos (incluidos subdominios descubiertos)
        enabled_set = set(self.scope.enabled_sources)
        ordered_source_keys = [
            "osint_crtsh",
            "osint_search_engines",
            "osint_public_repos",
            "osint_breach_intel",
            "direct_http_verifier",
        ]

        passive_findings_count = 0

        for src_id in ordered_source_keys:
            if src_id not in self.providers:
                continue
            provider = self.providers[src_id]

            if self.is_cancelled():
                if progress_callback:
                    progress_callback("[!] Auditoría cancelada por el operador.")
                break

            # Si es el turno de comprobación directa, asegurar que todos los subdominios activos sean incluidos
            if src_id == "direct_http_verifier":
                if passive_findings_count == 0 and progress_callback:
                    progress_callback("\n[!] Búsqueda pasiva sin hallazgos suficientes en índices. Desplegando comprobación directa integral con máxima cobertura y protección WARP...")

                # Si no se ingresaron subdominios manualmente o son pocos, ejecutar descubrimiento híbrido automático
                if len(self.scope.authorized_subdomains) <= 1 or any("*" in s for s in self.scope.authorized_subdomains):
                    try:
                        from .subdomain_engine import SubdomainDiscoveryEngine
                        apex, discovered = SubdomainDiscoveryEngine.discover_all(
                            self.scope.root_domain,
                            session=session,
                            progress_callback=progress_callback
                        )
                        for d in discovered:
                            in_s, _ = self.scope_validator.is_in_scope(d)
                            if in_s and d not in self.scope.authorized_subdomains:
                                self.scope.authorized_subdomains.append(d)
                    except Exception as e:
                        if progress_callback:
                            progress_callback(f"[!] Aviso en descubrimiento de subdominios: {e}")

                if progress_callback:
                    valid_targets_count = len([s for s in self.scope.authorized_subdomains if "*" not in s])
                    progress_callback(f"\n[*] Objetivos activos listos para auditoría directa: {valid_targets_count} activo(s).")

            # Verificar si la fuente está habilitada por el usuario
            if enabled_set and src_id not in enabled_set and "all" not in enabled_set:
                source_statuses.append(SourceStatus(
                    source_id=src_id,
                    name=provider.name,
                    category=provider.category,
                    status="DESHABILITADA",
                    message="Fuente deshabilitada por configuración de alcance."
                ))
                continue

            if progress_callback:
                progress_callback(f"\n[*] Ejecutando fuente: {provider.name}...")

            try:
                findings, refs, status = provider.run(
                    scope=self.scope,
                    session=session,
                    scope_validator=self.scope_validator,
                    is_cancelled=self.is_cancelled,
                    progress_callback=progress_callback
                )
                all_findings.extend(findings)
                all_references.extend(refs)
                source_statuses.append(status)

                if provider.category == "OSINT":
                    passive_findings_count += len(findings)

                # Si crt.sh descubrió subdominios en alcance, alimentarlos a la lista autorizada para la fase directa
                if src_id == "osint_crtsh" and findings:
                    for f in findings:
                        all_subs = f.extra_metadata.get("all_subdomains") or f.extra_metadata.get("sample", [])
                        for sub in all_subs:
                            in_s, _ = self.scope_validator.is_in_scope(sub)
                            if in_s and sub not in self.scope.authorized_subdomains:
                                self.scope.authorized_subdomains.append(sub)

            except Exception as e:
                source_statuses.append(SourceStatus(
                    source_id=src_id,
                    name=provider.name,
                    category=provider.category,
                    status="ERROR",
                    message=f"Excepción no controlada en proveedor: {e}"
                ))

        # 5. Deduplicación de hallazgos
        unique_findings: List[Finding] = []
        seen_keys = set()
        finding_id_seq = 1

        for f in all_findings:
            # Clave de deduplicación: activo + tipo + url
            key = (f.target_asset.lower(), f.exposure_type, (f.reference_url or "").lower())
            if key not in seen_keys:
                seen_keys.add(key)
                f.id = f"EXP-{finding_id_seq:03d}"
                finding_id_seq += 1
                unique_findings.append(f)

        # 6. Almacenamiento de evidencias y referencias
        for f in unique_findings:
            if f.evidence:
                rel_file = self.evidence_manager.save_evidence_snippet(
                    case_path=case_path,
                    finding_id=f.id,
                    snippet=f.evidence
                )
                if rel_file:
                    f.extra_metadata["evidence_file"] = rel_file

        self.evidence_manager.save_references(case_path, all_references)
        self.evidence_manager.save_sources(case_path, source_statuses)
        self.evidence_manager.save_findings_json(case_path, unique_findings)

        # 7. Generación automática del informe TXT profesional
        report_file = ExposureReporter.generate_report_txt(
            scope=self.scope,
            findings=unique_findings,
            sources=source_statuses,
            case_path=case_path
        )

        elapsed = round(time.time() - t0, 2)
        if progress_callback:
            progress_callback(f"\n[+] Auditoría completada en {elapsed}s.")
            progress_callback(f"[+] Informe TXT generado: {report_file}")

        return {
            "ok": True,
            "case_id": case_id,
            "case_path": str(case_path),
            "report_file": str(report_file),
            "elapsed_seconds": elapsed,
            "findings_count": len(unique_findings),
            "confirmed_count": sum(1 for f in unique_findings if f.verification_status == VerificationStatus.CONFIRMED_VULNERABILITY.value),
            "validation_req_count": sum(1 for f in unique_findings if f.verification_status == VerificationStatus.VALIDATION_REQUIRED.value),
            "observation_count": sum(1 for f in unique_findings if f.verification_status == VerificationStatus.OBSERVATION.value),
            "sources": [s.to_dict() for s in source_statuses],
            "findings": [f.to_dict() for f in unique_findings],
        }
