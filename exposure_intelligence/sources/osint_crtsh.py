# -*- coding: utf-8 -*-
"""
Proveedor OSINT: Transparencia de Certificados y Descubrimiento Híbrido de Subdominios.
Consulta logs públicos mediante crt.sh con fallback automático a extracción activa de SANs TLS
y consultas DNS de HackerTarget si crt.sh no responde o devuelve error 502.
"""

import time
from datetime import datetime
from typing import Callable, List, Optional, Tuple
import requests

from .base import BaseSourceProvider
from ..models import AuditScope, Finding, SourceStatus, ExternalReference, VerificationStatus, ExposureType, SeverityLevel
from ..scope import ScopeValidator
from ..subdomain_engine import SubdomainDiscoveryEngine


class CertificateTransparencyProvider(BaseSourceProvider):
    """Consulta registros de Certificate Transparency públicos (crt.sh) con fallback multicanal."""

    def __init__(self):
        super().__init__(
            source_id="osint_crtsh",
            name="Transparencia de Certificados (crt.sh / TLS SANs)",
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
                message="No se configuró dominio raíz para consulta de certificados."
            )

        # Normalizar al dominio apex si el usuario ingresó un subdominio (ej: www.dian.gov.co -> dian.gov.co)
        apex = SubdomainDiscoveryEngine.extract_apex_domain(root)

        if progress_callback:
            progress_callback(f"Consultando fuentes de certificados para apex: %.{apex} (entrada: {root})...")

        discovered_names = set()
        fallback_used = []

        # 1. Intentar crt.sh con User-Agent de navegador
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        url = f"https://crt.sh/?q=%.{apex}&output=json"
        crt_ok = False

        try:
            resp = session.get(url, headers=headers, timeout=(4.0, 8.0))
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for raw_name in name_value.splitlines():
                            cleaned = raw_name.strip().lower()
                            if cleaned.startswith("*."):
                                cleaned = cleaned[2:]
                            if cleaned and "." in cleaned:
                                discovered_names.add(cleaned)
                    crt_ok = True
        except Exception as e:
            fallback_used.append(f"crt.sh no disponible ({e})")

        # 2. Si crt.sh falló o trajo poco, activar extracción directa de SANs del certificado TLS
        tls_sans = SubdomainDiscoveryEngine.get_tls_certificate_sans(root)
        if not tls_sans and root != apex:
            tls_sans = SubdomainDiscoveryEngine.get_tls_certificate_sans(f"www.{apex}")

        if tls_sans:
            discovered_names.update(tls_sans)
            fallback_used.append(f"Certificado TLS SANs ({len(tls_sans)} subdominios)")

        # 3. Consultar HackerTarget DNS
        ht_subs = SubdomainDiscoveryEngine.query_hackertarget(apex, session)
        if ht_subs:
            discovered_names.update(ht_subs)
            fallback_used.append(f"HackerTarget DNS ({len(ht_subs)} subdominios)")

        # Clasificar nombres descubiertos según el alcance
        in_scope_discovered = []
        out_of_scope_discovered = []

        for name in discovered_names:
            in_scope, reason = scope_validator.is_in_scope(name)
            if in_scope:
                in_scope_discovered.append(name)
            else:
                out_of_scope_discovered.append((name, reason))

        # Registrar referencias externas de dominios de terceros
        for o_name, reason in out_of_scope_discovered:
            references.append(ExternalReference(
                source=self.source_id,
                reference_value=o_name,
                relation_type="THIRD_PARTY_DOMAIN_IN_CERT",
                details=f"Dominio observado en certificados pero fuera del alcance: {reason}"
            ))

        # Generar hallazgo informativo si hay subdominios descubiertos
        if in_scope_discovered:
            sample = in_scope_discovered[:25]
            sample_str = ", ".join(sample)
            if len(in_scope_discovered) > 25:
                sample_str += f" ... (+{len(in_scope_discovered) - 25} adicionales)"

            finding = Finding(
                id="EXP-OSINT-CRT-001",
                target_asset=apex,
                exposure_type=ExposureType.PASSIVE_OSINT_REFERENCE.value,
                source=self.source_id,
                reference_url=f"https://crt.sh/?q=%.{apex}",
                timestamp=datetime.now().isoformat(),
                verification_status=VerificationStatus.OBSERVATION.value,
                evidence=f"Total subdominios en alcance identificados por certificados y DNS: {len(in_scope_discovered)}\nMuestra de activos:\n{sample_str}",
                potential_risk="Mapeo pasivo de la superficie de ataque externa e infraestructura del dominio.",
                demonstrated_impact=f"Descubrimiento de {len(in_scope_discovered)} subdominios asociados a '{apex}'.",
                remediation="Monitorear registros de certificados y restringir el acceso a entornos no productivos.",
                limitations="Identificación mediante logs públicos y metadatos de certificados SSL/TLS activos.",
                severity=SeverityLevel.INFORMATIVO.value,
                reproduction_steps=f"Inspeccionar SANs en certificado SSL de {root} o crt.sh",
                extra_metadata={
                    "total_subdomains": len(in_scope_discovered),
                    "sample": sample,
                    "all_subdomains": in_scope_discovered
                }
            )
            findings.append(finding)

        elapsed = round(time.time() - t0, 2)
        status_msg = f"{len(in_scope_discovered)} subdominios en alcance descubiertos ({'; '.join(fallback_used) or 'crt.sh'})."
        return findings, references, SourceStatus(
            source_id=self.source_id,
            name=self.name,
            category=self.category,
            status="SUCCESS",
            findings_count=len(findings),
            duration_seconds=elapsed,
            message=status_msg
        )
