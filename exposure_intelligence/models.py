# -*- coding: utf-8 -*-
"""
Modelos de datos para el módulo de Inteligencia de Exposición y Leaks.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime


class VerificationStatus(str, Enum):
    OBSERVATION = "OBSERVATION"
    VALIDATION_REQUIRED = "VALIDATION_REQUIRED"
    CONFIRMED_VULNERABILITY = "CONFIRMED_VULNERABILITY"


class ExposureType(str, Enum):
    EXPOSED_CONFIG = "EXPOSED_CONFIG"
    BACKUP_DATABASE_EXPOSURE = "BACKUP_DATABASE_EXPOSURE"
    DIRECTORY_LISTING = "DIRECTORY_LISTING"
    VERSION_CONTROL_EXPOSURE = "VERSION_CONTROL_EXPOSURE"
    SUSPECTED_SECRET_PATTERN = "SUSPECTED_SECRET_PATTERN"
    SENSITIVE_FILE_EXPOSURE = "SENSITIVE_FILE_EXPOSURE"
    DIAGNOSTIC_INTERFACE = "DIAGNOSTIC_INTERFACE"
    CODE_REPOSITORY_REFERENCE = "CODE_REPOSITORY_REFERENCE"
    PASSIVE_OSINT_REFERENCE = "PASSIVE_OSINT_REFERENCE"
    HISTORICAL_LEAK_REFERENCE = "HISTORICAL_LEAK_REFERENCE"


class SeverityLevel(str, Enum):
    CRITICO = "CRITICO"
    ALTO = "ALTO"
    MEDIO = "MEDIO"
    BAJO = "BAJO"
    INFORMATIVO = "INFORMATIVO"


class WarpPolicy(str, Enum):
    STRICT = "STRICT"    # No iniciar consultas externas si WARP no está conectado
    WARN = "WARN"        # Advertir y pedir confirmación interactiva
    DIRECT = "DIRECT"    # Permitir conexión directa explícitamente


@dataclass
class Finding:
    id: str
    target_asset: str
    exposure_type: str
    source: str
    reference_url: Optional[str]
    timestamp: str
    verification_status: str
    evidence: str
    potential_risk: str
    demonstrated_impact: str
    remediation: str
    limitations: str
    severity: str = SeverityLevel.MEDIO.value
    reproduction_steps: Optional[str] = None
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SourceStatus:
    source_id: str
    name: str
    category: str
    status: str  # "SUCCESS", "NO CONFIGURADO", "ERROR", "SKIPPED_POLICY", "RATE_LIMITED"
    findings_count: int = 0
    duration_seconds: float = 0.0
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExternalReference:
    source: str
    reference_value: str
    relation_type: str
    details: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditScope:
    expediente_id: str
    root_domain: str
    authorized_subdomains: List[str]
    excluded_subdomains: List[str]
    timestamp: str
    enabled_sources: List[str]
    rate_limit_rps: float
    authorization_confirmed: bool
    warp_policy: str = WarpPolicy.WARN.value
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
