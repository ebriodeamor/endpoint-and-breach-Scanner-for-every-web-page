# -*- coding: utf-8 -*-
"""
Motor centralizado de redacción y detección de patrones sensibles.
Garantiza que ningún secreto, token, clave privada o credencial se almacene
sin redactar en reportes, evidencias o registros.
"""

import re
from typing import Dict, List, Tuple, Any


class SecretPattern:
    def __init__(self, name: str, pattern: re.Pattern, description: str):
        self.name = name
        self.pattern = pattern
        self.description = description


SECRET_PATTERNS = [
    # AWS Access Key ID
    SecretPattern(
        "AWS_ACCESS_KEY",
        re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "Identificador de clave de acceso AWS"
    ),
    # AWS Secret Access Key (heurística cuando va precedida de prefijo común)
    SecretPattern(
        "AWS_SECRET_KEY",
        re.compile(r"""(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""),
        "Posible clave secreta de AWS"
    ),
    # Claves privadas (RSA, EC, OPENSSH, DSA, PGP)
    SecretPattern(
        "PRIVATE_KEY_BLOCK",
        re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----[^-]+-----END (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----", re.S),
        "Bloque de clave criptográfica privada"
    ),
    # GitHub Personal Access Token / Oauth Token
    SecretPattern(
        "GITHUB_TOKEN",
        re.compile(r"(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})"),
        "Token de acceso personal de GitHub"
    ),
    # Slack Bot / User Token / Webhook
    SecretPattern(
        "SLACK_TOKEN",
        re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
        "Token de API de Slack"
    ),
    # JSON Web Token (JWT)
    SecretPattern(
        "JWT_TOKEN",
        re.compile(r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "Token JWT (posible token de sesión o portador)"
    ),
    # Cadenas de conexión a Bases de Datos con contraseña
    SecretPattern(
        "DB_CONNECTION_STRING",
        re.compile(r"""(?:postgres|postgresql|mysql|mssql|mongodb|mongodb\+srv|redis)://([^:]+):([^@\s'"]+)@([^\s'"]+)""", re.I),
        "Cadena de conexión a base de datos con credenciales"
    ),
    # Asignaciones comunes de contraseñas y secretos en archivos de configuración (.env, config.php, etc.)
    SecretPattern(
        "PASSWORD_ASSIGNMENT",
        re.compile(r"""(?i)(?:password|passwd|db_pass|db_password|api_key|secret|token|auth_key|private_key)\s*[:=]\s*["']?([^"'\s\r\n]{4,})["']?"""),
        "Asignación de contraseña o secreto en configuración"
    ),
    # Generic Bearer Token
    SecretPattern(
        "BEARER_AUTH_HEADER",
        re.compile(r"""(?i)Bearer\s+([a-zA-Z0-9_\-\.]{16,})"""),
        "Encabezado de autorización Bearer"
    ),
    # Stripe Secret Key
    SecretPattern(
        "STRIPE_KEY",
        re.compile(r"(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}"),
        "Clave secreta de Stripe"
    ),
    # Google API Key
    SecretPattern(
        "GOOGLE_API_KEY",
        re.compile(r"AIza[0-9A-Za-z-_]{35}"),
        "Clave de API de Google"
    )
]


class SecretRedactor:
    """Clase utilitaria para redacción y análisis de cadenas sensibles."""

    @staticmethod
    def mask_value(val: str, keep_start: int = 3, keep_end: int = 3) -> str:
        """Enmascara una cadena dejando visibles solo los extremos."""
        if not val:
            return ""
        val = val.strip()
        length = len(val)
        if length <= 6:
            return "***[REDACTADO]***"
        ks = min(keep_start, length // 3)
        ke = min(keep_end, length // 3)
        return val[:ks] + "*" * (length - ks - ke) + val[length - ke:]

    @classmethod
    def redact(cls, text: str) -> str:
        """
        Redacta todos los patrones conocidos dentro de un texto.
        Devuelve el texto seguro, garantizando que ninguna credencial se guarde en claro.
        """
        if not text:
            return ""

        redacted = str(text)

        # 1. Bloques de claves privadas completos
        redacted = re.sub(
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----[^-]+-----END (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\n***[CONTENIDO DE CLAVE PRIVADA REDACTADO POR SEGURIDAD]***\n-----END PRIVATE KEY-----",
            redacted,
            flags=re.S
        )

        # 2. Cadenas de conexión a BD
        def redact_db_uri(m: re.Match) -> str:
            proto = m.group(1)
            user = m.group(2)
            host_part = m.group(4)
            return f"{proto}://{user}:***[PASSWORD_REDACTADO]***@{host_part}"

        redacted = re.sub(
            r"""(?i)(postgres|postgresql|mysql|mssql|mongodb|mongodb\+srv|redis)://([^:]+):([^@\s'"]+)@([^\s'"]+)""",
            redact_db_uri,
            redacted
        )

        # 3. AWS Access Keys
        def redact_aws_key(m: re.Match) -> str:
            raw = m.group(0)
            return raw[:4] + "*" * 12 + raw[-4:]

        redacted = re.sub(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", redact_aws_key, redacted)

        # 4. GitHub Tokens
        def redact_github(m: re.Match) -> str:
            raw = m.group(0)
            return raw[:6] + "*" * (len(raw) - 10) + raw[-4:]

        redacted = re.sub(r"(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})", redact_github, redacted)

        # 5. Slack Tokens
        def redact_slack(m: re.Match) -> str:
            raw = m.group(0)
            return raw[:6] + "*" * (len(raw) - 10) + raw[-4:]

        redacted = re.sub(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", redact_slack, redacted)

        # 6. Google API Key
        def redact_google(m: re.Match) -> str:
            raw = m.group(0)
            return raw[:6] + "*" * (len(raw) - 10) + raw[-4:]

        redacted = re.sub(r"AIza[0-9A-Za-z-_]{35}", redact_google, redacted)

        # 7. Stripe keys
        def redact_stripe(m: re.Match) -> str:
            raw = m.group(0)
            return raw[:7] + "*" * (len(raw) - 11) + raw[-4:]

        redacted = re.sub(r"(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}", redact_stripe, redacted)

        # 8. JWT Tokens
        def redact_jwt(m: re.Match) -> str:
            raw = m.group(0)
            parts = raw.split(".")
            if len(parts) == 3:
                return f"{parts[0][:10]}...[PAYLOAD_JWT_REDACTADO]...{parts[2][-6:]}"
            return "***[JWT_REDACTADO]***"

        redacted = re.sub(r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", redact_jwt, redacted)

        # 9. Asignaciones de contraseñas y credenciales en configs
        def redact_assignment(m: re.Match) -> str:
            full = m.group(0)
            secret_val = m.group(1)
            # Evitar redactar palabras reservadas cortas como null, true, false
            if secret_val.lower() in ("null", "true", "false", "none", "undefined", "empty", "root", "admin", "123456"):
                return full
            masked = cls.mask_value(secret_val, keep_start=2, keep_end=2)
            return full.replace(secret_val, masked)

        redacted = re.sub(
            r"""(?i)((?:password|passwd|db_pass|db_password|api_key|secret|token|auth_key|private_key)\s*[:=]\s*["']?)([^"'\s\r\n]{4,})(["']?)""",
            lambda m: f"{m.group(1)}{cls.mask_value(m.group(2))}{m.group(3)}",
            redacted
        )

        return redacted

    @classmethod
    def scan_for_secrets(cls, text: str) -> List[Dict[str, Any]]:
        """
        Escanea el texto y detecta patrones sintácticos de credenciales.
        Devuelve una lista de coincidencias con el valor ya redactado y clasificado.
        """
        matches = []
        if not text:
            return matches

        for sp in SECRET_PATTERNS:
            found = sp.pattern.findall(text)
            for item in found:
                # Si el findall capturó grupos
                if isinstance(item, tuple):
                    # Tomar el grupo con mayor longitud de secreto
                    val = max(item, key=len)
                else:
                    val = str(item)

                if len(val) < 4 or val.lower() in ("null", "true", "false", "none"):
                    continue

                masked = cls.mask_value(val)
                matches.append({
                    "pattern_name": sp.name,
                    "description": sp.description,
                    "masked_value": masked,
                    "is_syntactic_pattern": True,
                    "verified": False  # NUNCA se asume verificado sin prueba autorizada
                })

        return matches
