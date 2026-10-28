# -*- coding: utf-8 -*-
"""
Proveedor OSINT: Índices de Buscadores y Búsquedas Estructuradas.
Genera y evalúa consultas pasivas dirigidas a índices públicos (dorks legítimos de auditoría)
para identificar posibles documentos expuestos, directorios y configuraciones indexadas.
"""

import time
import urllib.parse
from datetime import datetime
from typing import Callable, List, Optional, Tuple
import requests

from .base import BaseSourceProvider
from ..models import AuditScope, Finding, SourceStatus, ExternalReference, VerificationStatus, ExposureType, SeverityLevel
from ..scope import ScopeValidator

SEARCH_DORK_TEMPLATES = [
    (
        "Respaldos y Volcados de Bases de Datos",
        ExposureType.BACKUP_DATABASE_EXPOSURE,
        "site:{domain} (ext:sql | ext:dump | ext:bak | ext:backup | ext:db)",
        "Búsqueda de archivos SQL, respaldos o volcados de datos indexados públicamente."
    ),
    (
        "Archivos de Configuración y Entorno",
        ExposureType.EXPOSED_CONFIG,
        "site:{domain} (ext:env | ext:yml | ext:json | inurl:web.config | inurl:settings)",
        "Búsqueda de configuraciones y definiciones con posibles secretos expuestos."
    ),
    (
        "Listados de Directorios Abiertos",
        ExposureType.DIRECTORY_LISTING,
        'site:{domain} intitle:"index of" | intitle:"directory listing"',
        "Detección de índices web accesibles sin página por defecto."
    ),
    (
        "Documentos y Reportes Internos Accidentalmente Públicos",
        ExposureType.SENSITIVE_FILE_EXPOSURE,
        'site:{domain} (ext:pdf | ext:xlsx | ext:docx | ext:csv) ("confidencial" | "privado" | "interno")',
        "Búsqueda de documentos corporativos o datos personales indexados por motores de búsqueda."
    ),
    (
        "Interfaces de Diagnóstico o Administración",
        ExposureType.DIAGNOSTIC_INTERFACE,
        'site:{domain} inurl:phpinfo | inurl:server-status | inurl:actuator',
        "Identificación de interfaces diagnósticas indexadas públicamente."
    )
]


class SearchOsintProvider(BaseSourceProvider):
    """Genera y evalúa consultas estructuradas en índices de búsqueda públicos."""

    def __init__(self):
        super().__init__(
            source_id="osint_search_engines",
            name="Índices de Buscadores y Consultas Estructuradas",
            category="OSINT"
        )

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

        root = scope.root_domain
        if not root:
            return findings, references, SourceStatus(
                source_id=self.source_id,
                name=self.name,
                category=self.category,
                status="ERROR",
                message="Dominio raíz no configurado."
            )

        if progress_callback:
            progress_callback("Generando consultas estructuradas de auditoría para índices públicos...")

        counter = 1
        for title, exp_type, template, description in SEARCH_DORK_TEMPLATES:
            if is_cancelled():
                break

            query = template.format(domain=root)
            encoded_query = urllib.parse.quote(query)
            search_url_google = f"https://www.google.com/search?q={encoded_query}"
            search_url_ddg = f"https://duckduckgo.com/?q={encoded_query}"

            # Respetar normas anti-abuso: No automatizar scraping evasivo de Google/Bing
            # Construir el hallazgo como OBSERVATION / VALIDATION_REQUIRED con la consulta verificable
            evidence_text = (
                f"Consulta estructurada generada para indexadores públicos:\n"
                f"  Query:   {query}\n"
                f"  Enlace:  {search_url_ddg}\n"
                f"  Objetivo: {description}\n"
                f"Estado: Requiere validación manual por el auditor en el navegador para comprobar si existen registros activos."
            )

            potential_risk = "Presencia de recursos corporativos internos indexados por motores de búsqueda comerciales."
            demonstrated_impact = "Definición y registro de vectores de búsqueda pasiva sobre el dominio auditado."
            remediation = (
                "Verificar la directiva 'Disallow' en robots.txt e implementar encabezados 'X-Robots-Tag: noindex, nofollow' "
                "en áreas que no deban ser indexadas."
            )

            finding = Finding(
                id=f"EXP-SRCH-{counter:03d}",
                target_asset=root,
                exposure_type=exp_type.value,
                source=self.source_id,
                reference_url=search_url_ddg,
                timestamp=datetime.now().isoformat(),
                verification_status=VerificationStatus.OBSERVATION.value,
                evidence=evidence_text,
                potential_risk=potential_risk,
                demonstrated_impact=demonstrated_impact,
                remediation=remediation,
                limitations="La presencia de una consulta estructurada no confirma la existencia de vulnerabilidades sin validación humana interactiva.",
                severity=SeverityLevel.BAJO.value,
                reproduction_steps=f"Visitar {search_url_ddg} en un navegador autorizado y revisar los resultados devueltos.",
                extra_metadata={"query": query, "google_url": search_url_google, "ddg_url": search_url_ddg}
            )
            findings.append(finding)
            counter += 1

        elapsed = round(time.time() - t0, 2)
        status = SourceStatus(
            source_id=self.source_id,
            name=self.name,
            category=self.category,
            status="SUCCESS",
            findings_count=len(findings),
            duration_seconds=elapsed,
            message=f"{len(findings)} vectores de búsqueda pasiva documentados para revisión humana."
        )
        return findings, references, status
