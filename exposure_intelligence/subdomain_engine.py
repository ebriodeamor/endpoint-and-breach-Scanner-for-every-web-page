# -*- coding: utf-8 -*-
"""
Motor híbrido de descubrimiento y enumeración exhaustiva de subdominios.
Combina extracción activa de certificados TLS (SANs), HackerTarget DNS,
Certificate Transparency (crt.sh), AlienVault OTX y fuerza bruta DNS multihilo.
"""

import concurrent.futures
import socket
import ssl
from typing import Callable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
import tldextract


COMMON_SUBDOMAIN_PREFIXES = [
    # APIs y microservicios
    "api", "api-docs", "apis", "apiazure", "apidesarrollo", "api-dev", "apigateway",
    "gateway", "services", "service", "rest", "graphql", "ws", "backend",
    
    # Portales y autenticación
    "portal", "app", "apps", "web", "auth", "login", "sso", "identity",
    "connect", "secure", "admin", "panel", "console", "dashboard",
    
    # Operaciones y agendamiento
    "agendamiento", "agendamientoadmin", "agendamientoapi", "agendamientodigiturno",
    "agendamientosw", "tramites", "consultas", "citas", "da", "alertmanager",
    "descargas", "facturacion", "pagos", "notificaciones",
    
    # Entornos y despliegues
    "dev", "test", "stage", "staging", "qa", "preprod", "prod", "beta",
    "demo", "lab", "internal", "corp", "mail", "vpn", "remote",
]


class SubdomainDiscoveryEngine:
    """Motor de enumeración rápida y exhaustiva de subdominios."""

    @staticmethod
    def extract_apex_domain(domain_or_url: str) -> str:
        """
        Extrae el dominio raíz o apex registrado (ej: 'www.dian.gov.co' -> 'dian.gov.co').
        """
        raw = (domain_or_url or "").strip().lower()
        if "://" in raw:
            p = urlparse(raw)
            raw = p.netloc or p.path
        raw = raw.split(":")[0].split("/")[0].strip().rstrip(".")
        if raw in ("localhost", "127.0.0.1"):
            return raw

        ext = tldextract.extract(raw)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return raw

    @staticmethod
    def get_tls_certificate_sans(host: str, timeout: int = 4) -> Set[str]:
        """
        Extrae los nombres alternativos del sujeto (SANs) directamente
        del certificado TLS activo en el puerto 443 del host.
        """
        sans = set()
        clean_host = host.split(":")[0].strip()
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((clean_host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cert = ssock.getpeercert()
                    for k, v in cert.get("subjectAltName", []):
                        if k == "DNS" and v:
                            d = v.strip().lower()
                            if d.startswith("*."):
                                d = d[2:]
                            if d and "." in d:
                                sans.add(d)
        except Exception:
            pass
        return sans

    @staticmethod
    def query_hackertarget(apex: str, session: requests.Session) -> Set[str]:
        """Consulta el servicio de búsqueda de hosts DNS de HackerTarget."""
        discovered = set()
        try:
            r = session.get(f"https://api.hackertarget.com/hostsearch/?q={apex}", timeout=(4.0, 6.0))
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(apex):
                            discovered.add(sub)
        except Exception:
            pass
        return discovered

    @staticmethod
    def query_alienvault(apex: str, session: requests.Session) -> Set[str]:
        """Consulta pasiva DNS de AlienVault OTX."""
        discovered = set()
        try:
            r = session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns", timeout=(4.0, 6.0))
            if r.status_code == 200:
                data = r.json().get("passive_dns", [])
                for entry in data:
                    hostname = entry.get("hostname", "").strip().lower()
                    if hostname and hostname.endswith(apex):
                        discovered.add(hostname)
        except Exception:
            pass
        return discovered

    @staticmethod
    def query_crtsh(apex: str, session: requests.Session) -> Set[str]:
        """Consulta registros de transparencia de certificados crt.sh con cabeceras de navegador."""
        discovered = set()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        try:
            r = session.get(f"https://crt.sh/?q=%.{apex}&output=json", headers=headers, timeout=(4.0, 8.0))
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    for entry in data:
                        name_val = entry.get("name_value", "")
                        for line in name_val.splitlines():
                            sub = line.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and sub.endswith(apex):
                                discovered.add(sub)
        except Exception:
            pass
        return discovered

    @staticmethod
    def resolve_subdomain_dns(subdomain: str) -> bool:
        """Comprueba rápidamente si un subdominio resuelve en DNS."""
        try:
            socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return True
        except Exception:
            return False

    @classmethod
    def bruteforce_common_subdomains(cls, apex: str, max_workers: int = 30) -> Set[str]:
        """Prueba una lista de prefijos habituales mediante resolución DNS multihilo ultrarrápida."""
        candidates = [f"{prefix}.{apex}" for prefix in COMMON_SUBDOMAIN_PREFIXES]
        resolved = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_sub = {pool.submit(cls.resolve_subdomain_dns, sub): sub for sub in candidates}
            for fut in concurrent.futures.as_completed(future_to_sub):
                sub = future_to_sub[fut]
                try:
                    if fut.result():
                        resolved.add(sub)
                except Exception:
                    pass

        return resolved

    @classmethod
    def check_http_alive(cls, sub: str, session: requests.Session, timeout: float = 1.5) -> bool:
        """Verifica a nivel de socket ultra-rápido si el subdominio tiene puerto 443 o 80 abierto."""
        for port in (443, 80):
            try:
                with socket.create_connection((sub, port), timeout=timeout):
                    return True
            except Exception:
                pass
        return False

    @classmethod
    def filter_active_web_hosts(
        cls,
        subdomains: Set[str],
        session: requests.Session,
        max_workers: int = 25,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> List[str]:
        """Filtra y devuelve únicamente los subdominios que responden como servidores web activos."""
        active = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_sub = {pool.submit(cls.check_http_alive, sub, session): sub for sub in subdomains}
            for fut in concurrent.futures.as_completed(future_to_sub):
                sub = future_to_sub[fut]
                try:
                    if fut.result():
                        active.append(sub)
                        if progress_callback:
                            progress_callback(f" [+] Subdominio activo: {sub}")
                except Exception:
                    pass

        return sorted(active)

    @classmethod
    def discover_all(
        cls,
        target_input: str,
        session: requests.Session,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[str, List[str]]:
        """
        Realiza el descubrimiento completo por capas:
        1. Determina el apex domain.
        2. Extrae SANs de certificados TLS directos.
        3. Consulta HackerTarget y crt.sh.
        4. Realiza resolución activa DNS sobre prefijos comunes.
        5. Filtra los hosts que están vivos en la web.
        Devuelve (apex_domain, lista_subdominios_activos_en_alcance).
        """
        apex = cls.extract_apex_domain(target_input)
        target_norm = target_input.split("://")[-1].split("/")[0].split(":")[0].strip().lower()

        if progress_callback:
            progress_callback(f"[*] Dominio raíz/apex determinado: {apex} (a partir de '{target_input}')")
            progress_callback("[*] Iniciando descubrimiento híbrido de subdominios...")

        all_discovered = set()
        all_discovered.add(apex)
        if target_norm:
            all_discovered.add(target_norm)

        # Capa 1: TLS SANs directos (súper rápido y 100% verificado)
        tls_hosts_to_try = [target_norm, f"www.{apex}", apex]
        for th in tls_hosts_to_try:
            sans = cls.get_tls_certificate_sans(th)
            if sans:
                for s in sans:
                    if s.endswith(apex):
                        all_discovered.add(s)
                if progress_callback:
                    progress_callback(f" [+] Certificado TLS ({th}): {len(sans)} subdominios obtenidos.")
                break

        # Capa 2: HackerTarget DNS
        ht_subs = cls.query_hackertarget(apex, session)
        if ht_subs:
            all_discovered.update(ht_subs)
            if progress_callback:
                progress_callback(f" [+] HackerTarget DNS: {len(ht_subs)} subdominios obtenidos.")

        # Capa 3: crt.sh
        crt_subs = cls.query_crtsh(apex, session)
        if crt_subs:
            all_discovered.update(crt_subs)
            if progress_callback:
                progress_callback(f" [+] Certificate Transparency (crt.sh): {len(crt_subs)} subdominios obtenidos.")

        # Capa 4: Fuerza bruta DNS de prefijos comunes
        bf_subs = cls.bruteforce_common_subdomains(apex)
        if bf_subs:
            all_discovered.update(bf_subs)
            if progress_callback:
                progress_callback(f" [+] Resolucion DNS activa: {len(bf_subs)} subdominios verificados.")

        if progress_callback:
            progress_callback(f"\n[*] Total subdominios únicos recopilados: {len(all_discovered)}")
            progress_callback("[*] Verificando disponibilidad web (HTTP/HTTPS) en paralelo...")

        # Filtrar solo los que responden web
        active_hosts = cls.filter_active_web_hosts(all_discovered, session, progress_callback=progress_callback)

        # Asegurar que al menos el target original y el apex estén si no hubo otros
        if not active_hosts:
            active_hosts = [target_norm or apex]

        return apex, active_hosts
