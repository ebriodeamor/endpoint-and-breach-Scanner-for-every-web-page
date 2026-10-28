# -*- coding: utf-8 -*-
"""
Proveedor OSINT: Servicios Legítimos de Notificación de Filtraciones.
Consulta APIs autorizadas de detección de brechas (como HaveIBeenPwned) cuando están configuradas.
Si no se suministran claves por variables de entorno, reporta de manera transparente 'NO CONFIGURADO'
sin inventar datos simulados ni realizar descargas masivas de PII.
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


class BreachIntelProvider(BaseSourceProvider):
    """Proveedor para servicios autorizados de notificación de brechas y filtraciones históricas."""

    def __init__(self):
        super().__init__(
            source_id="osint_breach_intel",
            name="Inteligencia de Filtraciones (HIBP / Breach API)",
            category="BREACH_INTEL"
        )
        # Buscar claves en variables de entorno oficiales
        self.hibp_api_key = os.getenv("HIBP_API_KEY", "").strip()

    def is_configured(self) -> Tuple[bool, str]:
        if self.hibp_api_key:
            return True, "API Key HIBP configurada vía variable de entorno HIBP_API_KEY"
        return False, "NO CONFIGURADO (Requiere HIBP_API_KEY en variables de entorno)"

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

        is_cfg, msg = self.is_configured()
        if not is_cfg:
            elapsed = round(time.time() - t0, 2)
            if progress_callback:
                progress_callback("Inteligencia de Filtraciones: NO CONFIGURADO (sin API Key). Omitiendo.")
            return findings, references, SourceStatus(
                source_id=self.source_id,
                name=self.name,
                category=self.category,
                status="NO CONFIGURADO",
                findings_count=0,
                duration_seconds=elapsed,
                message=msg
            )

        root = scope.root_domain
        if progress_callback:
            progress_callback(f"Consultando servicio de brechas para el dominio '{root}'...")

        # Consultar la API oficial de HIBP para el dominio si existe suscripción de dominio
        headers = {
            "hibp-api-key": self.hibp_api_key,
            "user-agent": "AtlasScan-Breach-Audit/1.0"
        }
        api_url = f"https://haveibeenpwned.com/api/v3/breaches?domain={root}"

        try:
            resp = session.get(api_url, headers=headers, timeout=10)
            if resp.status_code == 401 or resp.status_code == 403:
                elapsed = round(time.time() - t0, 2)
                return findings, references, SourceStatus(
                    source_id=self.source_id,
                    name=self.name,
                    category=self.category,
                    status="ERROR",
                    duration_seconds=elapsed,
                    message="Credencial de API HIBP rechazada o sin permisos para el dominio consultado."
                )

            if resp.status_code == 404:
                elapsed = round(time.time() - t0, 2)
                return findings, references, SourceStatus(
                    source_id=self.source_id,
                    name=self.name,
                    category=self.category,
                    status="SUCCESS",
                    findings_count=0,
                    duration_seconds=elapsed,
                    message="No se encontraron registros de filtraciones asociadas al dominio."
                )

            if resp.status_code == 200:
                breaches = resp.json()
                if isinstance(breaches, list):
                    for idx, b in enumerate(breaches, 1):
                        if is_cancelled():
                            break
                        b_name = b.get("Name", "Desconocido")
                        b_title = b.get("Title", b_name)
                        b_date = b.get("BreachDate", "N/A")
                        pwn_count = b.get("PwnCount", 0)
                        data_classes = b.get("DataClasses", [])

                        evidence_text = (
                            f"Filtración histórica registrada: {b_title}\n"
                            f"Fecha del incidente: {b_date}\n"
                            f"Cuentas afectadas estimadas: {pwn_count}\n"
                            f"Clases de datos comprometidas: {', '.join(data_classes)}"
                        )

                        finding = Finding(
                            id=f"EXP-BREACH-{idx:03d}",
                            target_asset=root,
                            exposure_type=ExposureType.HISTORICAL_LEAK_REFERENCE.value,
                            source=self.source_id,
                            reference_url=f"https://haveibeenpwned.com/PwnedWebsites#{b_name}",
                            timestamp=datetime.now().isoformat(),
                            verification_status=VerificationStatus.OBSERVATION.value,
                            evidence=evidence_text,
                            potential_risk="Compromiso histórico de credenciales corporativas utilizadas en servicios afectados.",
                            demonstrated_impact=f"El dominio estuvo involucrado en el incidente histórico '{b_title}' ({b_date}).",
                            remediation="Comprobar si los usuarios reutilizan contraseñas e imponer autenticación multifactor (MFA).",
                            limitations="Metadatos históricos provenientes de HIBP. No se almacenan ni descargan listas de correos ni contraseñas.",
                            severity=SeverityLevel.MEDIO.value,
                            reproduction_steps=f"Consultar ficha oficial en HIBP: https://haveibeenpwned.com/PwnedWebsites#{b_name}",
                            extra_metadata={"breach_name": b_name, "pwn_count": pwn_count, "data_classes": data_classes}
                        )
                        findings.append(finding)

                elapsed = round(time.time() - t0, 2)
                return findings, references, SourceStatus(
                    source_id=self.source_id,
                    name=self.name,
                    category=self.category,
                    status="SUCCESS",
                    findings_count=len(findings),
                    duration_seconds=elapsed,
                    message=f"Se identificaron {len(findings)} registro(s) de incidentes históricos."
                )

            elapsed = round(time.time() - t0, 2)
            return findings, references, SourceStatus(
                source_id=self.source_id,
                name=self.name,
                category=self.category,
                status="ERROR",
                duration_seconds=elapsed,
                message=f"Código de respuesta inesperado: {resp.status_code}"
            )

        except requests.RequestException as e:
            elapsed = round(time.time() - t0, 2)
            return findings, references, SourceStatus(
                source_id=self.source_id,
                name=self.name,
                category=self.category,
                status="ERROR",
                duration_seconds=elapsed,
                message=f"Error al conectar con la API de filtraciones: {e}"
            )
