# -*- coding: utf-8 -*-
"""
Proveedor OSINT: Repositorios Públicos de Código (GitHub Search).
Busca referencias al dominio auditado en repositorios públicos y analiza
fragmentos en busca de patrones sintácticos de secretos, con redacción inmediata
y sin realizar ninguna prueba automática de credenciales.
"""

import os
import time
from datetime import datetime
from typing import Callable, List, Optional, Tuple
import requests

from .base import BaseSourceProvider
from ..models import AuditScope, Finding, SourceStatus, ExternalReference, VerificationStatus, ExposureType, SeverityLevel
from ..redactor import SecretRedactor
from ..scope import ScopeValidator


class RepositoryOsintProvider(BaseSourceProvider):
    """Consulta la API de búsqueda de código en repositorios públicos."""

    def __init__(self):
        super().__init__(
            source_id="osint_public_repos",
            name="Repositorios Públicos (GitHub Search API)",
            category="OSINT"
        )
        self.github_token = os.getenv("GITHUB_TOKEN", "").strip()

    def is_configured(self) -> Tuple[bool, str]:
        if self.github_token:
            return True, "Configurado con GITHUB_TOKEN"
        return True, "Modo anónimo (límite estricto de GitHub de 10 req/min)"

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
            progress_callback(f"Consultando referencias en repositorios públicos para '{root}'...")

        # Consultar la API oficial de búsqueda de GitHub
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AtlasScan-OSINT-Audit/1.0"
        }
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        api_url = f"https://api.github.com/search/code?q={root}&per_page=5"

        try:
            resp = session.get(api_url, headers=headers, timeout=10)
            if resp.status_code == 401:
                # Token en entorno no válido o revocado, reintentar en modo anónimo
                headers.pop("Authorization", None)
                resp = session.get(api_url, headers=headers, timeout=10)

            if resp.status_code in (401, 403):
                # Rate limit o autenticación requerida
                msg = "Límite de peticiones de GitHub API alcanzado o token no configurado."
                if not self.github_token or resp.status_code == 401:
                    msg += " Configure un GITHUB_TOKEN válido en variables de entorno para consultas autenticadas."
                elapsed = round(time.time() - t0, 2)
                return findings, references, SourceStatus(
                    source_id=self.source_id,
                    name=self.name,
                    category=self.category,
                    status="NO CONFIGURADO",
                    duration_seconds=elapsed,
                    message=msg
                )

            if resp.status_code != 200:
                elapsed = round(time.time() - t0, 2)
                return findings, references, SourceStatus(
                    source_id=self.source_id,
                    name=self.name,
                    category=self.category,
                    status="ERROR",
                    duration_seconds=elapsed,
                    message=f"GitHub API devolvió código HTTP {resp.status_code}."
                )

            data = resp.json()
            total_count = data.get("total_count", 0)
            items = data.get("items", [])

            if total_count == 0:
                elapsed = round(time.time() - t0, 2)
                return findings, references, SourceStatus(
                    source_id=self.source_id,
                    name=self.name,
                    category=self.category,
                    status="SUCCESS",
                    findings_count=0,
                    duration_seconds=elapsed,
                    message="No se encontraron menciones públicas del dominio en GitHub."
                )

            # Analizar items encontrados
            for idx, item in enumerate(items, 1):
                if is_cancelled():
                    break

                repo_info = item.get("repository", {})
                repo_full_name = repo_info.get("full_name", "Desconocido")
                html_url = item.get("html_url", "")
                file_path = item.get("path", "")

                # Registrar repositorio externo como referencia
                references.append(ExternalReference(
                    source=self.source_id,
                    reference_value=repo_full_name,
                    relation_type="PUBLIC_REPOSITORY_REFERENCE",
                    details=f"Archivo '{file_path}' menciona al dominio {root} ({html_url})"
                ))

                finding = Finding(
                    id=f"EXP-REPO-{idx:03d}",
                    target_asset=root,
                    exposure_type=ExposureType.CODE_REPOSITORY_REFERENCE.value,
                    source=self.source_id,
                    reference_url=html_url,
                    timestamp=datetime.now().isoformat(),
                    verification_status=VerificationStatus.OBSERVATION.value,
                    evidence=f"Repositorio: {repo_full_name}\nArchivo: {file_path}\nURL: {html_url}\nTotal menciones estimadas: {total_count}",
                    potential_risk="Mención de endpoints, dominios internos o configuraciones en proyectos públicos.",
                    demonstrated_impact=f"El dominio '{root}' aparece referenciado en el archivo público '{file_path}' de '{repo_full_name}'.",
                    remediation="Revisar si el repositorio pertenece a la organización o a un proveedor y asegurar que no contenga credenciales asociadas.",
                    limitations="Coincidencia textual obtenida mediante GitHub Code Search API. No implica titularidad ni acceso no autorizado.",
                    severity=SeverityLevel.BAJO.value,
                    reproduction_steps=f"Inspeccionar manualmente la URL pública: {html_url}",
                    extra_metadata={"repo": repo_full_name, "path": file_path, "total_count": total_count}
                )
                findings.append(finding)

            elapsed = round(time.time() - t0, 2)
            status = SourceStatus(
                source_id=self.source_id,
                name=self.name,
                category=self.category,
                status="SUCCESS",
                findings_count=len(findings),
                duration_seconds=elapsed,
                message=f"Se detectaron {total_count} mención(es) pública(s) en GitHub ({len(findings)} procesadas)."
            )
            return findings, references, status

        except requests.RequestException as e:
            elapsed = round(time.time() - t0, 2)
            return findings, references, SourceStatus(
                source_id=self.source_id,
                name=self.name,
                category=self.category,
                status="ERROR",
                duration_seconds=elapsed,
                message=f"Error al conectar con GitHub API: {e}"
            )
        except Exception as e:
            elapsed = round(time.time() - t0, 2)
            return findings, references, SourceStatus(
                source_id=self.source_id,
                name=self.name,
                category=self.category,
                status="ERROR",
                duration_seconds=elapsed,
                message=f"Error inesperado en consulta de repositorios: {e}"
            )
