# -*- coding: utf-8 -*-
"""
Validador estricto de alcance (Scope) y protección contra SSRF y desvíos fuera de alcance.
Asegura que solo los activos autorizados sean evaluados y bloquea accesos no autorizados a redes privadas.
"""

import ipaddress
import re
import socket
from typing import List, Optional, Tuple, Set
from urllib.parse import urlparse

from .models import AuditScope


class ScopeValidationError(Exception):
    """Excepción para violaciones de alcance o dominios inválidos."""
    pass


class ScopeValidator:
    """Validador y controlador de alcance de auditoría."""

    # Dominios de prueba / documentación reservados (RFC 2606)
    RESERVED_TLDS = {".example", ".invalid", ".localhost", ".test"}

    def __init__(self, scope: AuditScope, allow_private_ip: bool = False):
        self.scope = scope
        self.allow_private_ip = allow_private_ip
        self.root_domain = self.normalize_domain(scope.root_domain)
        self.apex_domain = self.extract_apex_domain(self.root_domain)
        self.authorized_subdomains = {self.normalize_domain(s) for s in scope.authorized_subdomains if s}
        self.excluded_subdomains = {self.normalize_domain(s) for s in scope.excluded_subdomains if s}

        # Asegurar que el dominio raíz y el apex estén autorizados
        if self.root_domain:
            self.authorized_subdomains.add(self.root_domain)
        if self.apex_domain:
            self.authorized_subdomains.add(self.apex_domain)

    @staticmethod
    def extract_apex_domain(domain: str) -> str:
        """Extrae el dominio apex registrado (ej: www.dian.gov.co -> dian.gov.co)."""
        if not domain or domain in ("localhost", "127.0.0.1"):
            return domain
        try:
            import tldextract
            ext = tldextract.extract(domain)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
        except Exception:
            pass
        return domain

    @staticmethod
    def normalize_domain(domain_or_url: str) -> str:
        """Normaliza un dominio o URL extrayendo el hostname en minúsculas."""
        if not domain_or_url:
            return ""
        raw = domain_or_url.strip()
        if "://" in raw:
            p = urlparse(raw)
            raw = p.netloc or p.path
        # Remover puerto si existe
        if ":" in raw:
            raw = raw.split(":", 1)[0]
        # Remover rutas residuales
        raw = raw.split("/")[0].strip().lower().rstrip(".")
        return raw

    @classmethod
    def is_valid_domain_syntax(cls, domain: str) -> bool:
        """Valida la sintaxis RFC de un nombre de dominio o hostname."""
        d = cls.normalize_domain(domain)
        if not d:
            return False
        # Aceptar localhost explícito
        if d == "localhost":
            return True
        # Aceptar direcciones IP válidas
        try:
            ipaddress.ip_address(d)
            return True
        except ValueError:
            pass

        # Validar dominio estándar (mínimo un punto, etiquetas <= 63 chars, longitud total <= 253)
        if len(d) > 253 or "." not in d:
            return False
        labels = d.split(".")
        # TLD al menos 2 letras
        if len(labels[-1]) < 2 or not labels[-1].isalpha():
            return False
        label_regex = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
        return all(label_regex.match(lbl) for lbl in labels)

    def is_in_scope(self, url_or_domain: str) -> Tuple[bool, str]:
        """
        Verifica si un dominio o URL está dentro del alcance autorizado.
        Devuelve (en_alcance: bool, motivo: str).
        """
        target = self.normalize_domain(url_or_domain)
        if not target:
            return False, "Destino vacío o no procesable."

        # 1. Comprobar exclusiones explícitas
        if target in self.excluded_subdomains:
            return False, f"El dominio '{target}' está explícitamente excluido del alcance."
        for excl in self.excluded_subdomains:
            if target.endswith("." + excl):
                return False, f"El subdominio '{target}' pertenece a la zona excluida '{excl}'."

        # 2. Comprobar coincidencia exacta con lista de autorizados
        if target in self.authorized_subdomains:
            return True, "Autorizado expresamente en alcance."

        # 3. Comprobar si es un subdominio válido del dominio raíz o del apex autorizado
        domains_to_check = [d for d in [self.root_domain, self.apex_domain] if d]
        for dom in domains_to_check:
            if target == dom or target.endswith("." + dom):
                # Si hay comodín (*.dominio o *) o si el comodín coincide con el apex
                has_wildcard = any(
                    s in (f"*.{dom}", "*", f"*.{self.apex_domain}", f"*.{self.root_domain}")
                    for s in self.scope.authorized_subdomains
                )
                if has_wildcard:
                    return True, f"Subdominio de '{dom}' autorizado por comodín."
                if target in (self.root_domain, self.apex_domain):
                    return True, "Coincide con el dominio raíz o apex autorizado."
                # Si no hay comodín explícito pero el target pertenece a la misma organización
                # y no está excluido, se permite si se autorizó el apex
                if f"*.{self.apex_domain}" in self.authorized_subdomains or "*" in self.authorized_subdomains:
                    return True, f"Subdominio de '{self.apex_domain}' autorizado."
                return False, f"El subdominio '{target}' pertenece a '{dom}' pero no fue listado como autorizado."

        # 4. Cualquier otro dominio es un tercero no autorizado
        return False, f"El dominio '{target}' es un tercero fuera del alcance de auditoría."

    def check_ssrf_safety(self, host_or_ip: str) -> Tuple[bool, str]:
        """
        Protección contra SSRF:
        Comprueba si la dirección IP o el host resuelto apunta a direcciones privadas,
        loopback, link-local, multicast o reservadas.
        """
        host = self.normalize_domain(host_or_ip)
        if not host:
            return False, "Host no válido para comprobación de red."

        # Si se permite explícitamente IP privada (por ejemplo, entorno de pruebas local)
        if self.allow_private_ip:
            return True, "IPs locales permitidas por configuración explícita de pruebas."

        # 1. Comprobar si host es directamente una IP literal
        try:
            ip_obj = ipaddress.ip_address(host)
            if self._is_dangerous_ip(ip_obj):
                return False, f"Acceso bloqueado por seguridad: IP no pública ({ip_obj})."
            return True, "IP pública válida."
        except ValueError:
            pass

        # 2. Si es nombre de dominio, resolver y verificar las IPs asociadas
        if host == "localhost":
            return False, "Acceso bloqueado: 'localhost' apunta a la interfaz local del sistema."

        try:
            addr_info = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            resolved_ips = set()
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                resolved_ips.add(ip_str)

            if not resolved_ips:
                return False, f"No se pudo resolver el host '{host}' a ninguna dirección IP."

            for ip_str in resolved_ips:
                ip_obj = ipaddress.ip_address(ip_str)
                if self._is_dangerous_ip(ip_obj):
                    return False, f"Acceso bloqueado por SSRF: '{host}' resuelve a IP no pública ({ip_obj})."

            return True, "Host público verificado correctamente."
        except socket.gaierror as e:
            return False, f"Fallo en la resolución DNS para '{host}': {e}"
        except Exception as e:
            return False, f"Error durante verificación de IP segura para '{host}': {e}"

    @staticmethod
    def _is_dangerous_ip(ip: ipaddress._BaseAddress) -> bool:
        """Determina si una dirección IP representa un riesgo de SSRF."""
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved or
            ip.is_unspecified
        )
