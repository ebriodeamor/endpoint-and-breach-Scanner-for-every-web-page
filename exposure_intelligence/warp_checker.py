# -*- coding: utf-8 -*-
"""
Verificación de estado de Cloudflare WARP y gestión de políticas de transporte.
Proporciona control de red sin realizar cambios silenciosos en el equipo ni promesas falsas de anonimato total.
"""

import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple
import requests

from .models import WarpPolicy

WARP_CLI_PATHS = [
    "warp-cli",
    r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
    r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe",
]
DEFAULT_WARP_SOCKS = "socks5h://127.0.0.1:40000"


class WarpStatusReport:
    def __init__(self, is_connected: bool, verifiable: bool, details: str, egress_info: Optional[Dict] = None):
        self.is_connected = is_connected
        self.verifiable = verifiable
        self.details = details
        self.egress_info = egress_info or {}
        self.check_timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            "is_connected": self.is_connected,
            "verifiable": self.verifiable,
            "details": self.details,
            "egress_info": self.egress_info,
            "check_timestamp": self.check_timestamp,
        }


class WarpChecker:
    """Comprueba el estado de WARP y hace cumplir la política seleccionada."""

    def __init__(self, socks_proxy: str = DEFAULT_WARP_SOCKS):
        self.socks_proxy = socks_proxy
        self._cached_cli_path: Optional[str] = None

    def find_cli(self) -> Optional[str]:
        if self._cached_cli_path:
            return self._cached_cli_path
        for p in WARP_CLI_PATHS:
            found = shutil.which(p)
            if found:
                self._cached_cli_path = found
                return found
            if Path(p).is_file():
                self._cached_cli_path = p
                return p
        return None

    def check_status(self, timeout: int = 5) -> WarpStatusReport:
        """
        Determina si el cliente WARP está disponible y conectado.
        No realiza cambios de configuración en el sistema operativo.
        """
        cli = self.find_cli()
        if not cli:
            return WarpStatusReport(
                is_connected=False,
                verifiable=False,
                details="warp-cli no está instalado o no se encuentra en el PATH."
            )

        try:
            proc = subprocess.run([cli, "status"], capture_output=True, text=True, timeout=timeout)
            out = ((proc.stdout or "") + (proc.stderr or "")).strip()
            low = out.lower()
            is_connected = "connected" in low and "not connected" not in low and "disconnected" not in low
            return WarpStatusReport(
                is_connected=is_connected,
                verifiable=True,
                details=out or f"Código de salida: {proc.returncode}"
            )
        except subprocess.TimeoutExpired:
            return WarpStatusReport(
                is_connected=False,
                verifiable=False,
                details="Tiempo de espera agotado al consultar warp-cli status."
            )
        except Exception as e:
            return WarpStatusReport(
                is_connected=False,
                verifiable=False,
                details=f"Error al ejecutar warp-cli: {e}"
            )

    def verify_egress_via_warp(self, timeout: int = 6) -> Dict:
        """Comprueba si el tráfico realmente fluye a través del proxy SOCKS de WARP."""
        s = requests.Session()
        s.proxies = {"http": self.socks_proxy, "https": self.socks_proxy}
        try:
            r = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=timeout)
            data = {}
            for line in r.text.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip()
            return {
                "ok": True,
                "ip": data.get("ip", "?"),
                "loc": data.get("loc", "?"),
                "warp_flag": data.get("warp", "off")
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def evaluate_policy(self, policy: str) -> Tuple[bool, str, WarpStatusReport]:
        """
        Evalúa si es seguro proceder según la política de WARP configurada.
        Devuelve: (puede_proceder: bool, explicacion: str, reporte: WarpStatusReport)
        """
        status = self.check_status()

        if policy == WarpPolicy.STRICT.value:
            if not status.verifiable:
                return False, "Política STRICT activa: No se puede verificar el estado de Cloudflare WARP. Consultas externas canceladas.", status
            if not status.is_connected:
                return False, "Política STRICT activa: Cloudflare WARP está DESCONECTADO. Consultas externas canceladas.", status
            return True, "Cloudflare WARP conectado y verificado según política STRICT.", status

        elif policy == WarpPolicy.WARN.value:
            if not status.is_connected:
                msg = f"Cloudflare WARP no está activo ({status.details}). Se requiere advertencia antes de continuar en conexión directa."
                return False, msg, status
            return True, "Cloudflare WARP conectado.", status

        elif policy == WarpPolicy.DIRECT.value:
            return True, "Política DIRECT: Conexión directa autorizada expresamente por el usuario.", status

        return True, "Política estándar evaluada.", status
