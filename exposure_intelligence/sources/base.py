# -*- coding: utf-8 -*-
"""
Interfaz base para proveedores modulares de fuentes en AtlasScan.
Define la interfaz uniforme para adición, activación y desactivación de fuentes.
"""

from abc import ABC, abstractmethod
from typing import Callable, List, Optional, Tuple
import requests

from ..models import AuditScope, Finding, SourceStatus, ExternalReference
from ..scope import ScopeValidator


class BaseSourceProvider(ABC):
    """Clase abstracta para todos los proveedores de fuentes de información y comprobaciones."""

    def __init__(self, source_id: str, name: str, category: str):
        self.source_id = source_id
        self.name = name
        self.category = category  # "OSINT", "DIRECT_CHECK", "SECRET_SCAN", "BREACH_INTEL"
        self.enabled = True

    def is_configured(self) -> Tuple[bool, str]:
        """
        Indica si el proveedor cuenta con los requisitos/claves necesarios para operar.
        Por defecto True para fuentes públicas sin autenticación.
        """
        return True, "Disponible"

    @abstractmethod
    def run(
        self,
        scope: AuditScope,
        session: requests.Session,
        scope_validator: ScopeValidator,
        is_cancelled: Callable[[], bool],
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[List[Finding], List[ExternalReference], SourceStatus]:
        """
        Ejecuta la recolección de información o comprobación de bajo impacto.
        Devuelve (hallazgos, referencias_externas, estado_de_la_fuente).
        """
        pass
