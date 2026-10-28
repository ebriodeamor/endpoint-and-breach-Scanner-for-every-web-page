#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NadieScan v2.2 - Herramienta de auditoría web, fingerprinting y búsqueda de endpoints / APIs.

Motor de escaneo agresivo sin restricciones de whitelist.
Soporte opcional de Cloudflare WARP para anonimato.
"""

import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from exposure_intelligence.cli import run_exposure_intelligence_cli
except ImportError:
    run_exposure_intelligence_cli = None

# ------------------------------------------------------------------ Colores ANSI
class C:
    R = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    GRY = "\033[90m"

if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# ------------------------------------------------------------------ Banner
BANNER_ART = r"""
 _   _           _ _      ____                  
| \ | | __ _  __| (_) ___/ ___|  ___ __ _ _ __  
|  \| |/ _` |/ _` | |/ _ \___ \ / __/ _` | '_ \ 
| |\  | (_| | (_| | |  __/___) | (_| (_| | | | |
|_| \_|\__,_|\__,_|_|\___|____/ \___\__,_|_| |_|
"""

VERSION = "v2.3 (Multi-Target & Spider)"

# ------------------------------------------------------------------ Config
WARP_PATHS = [
    "warp-cli",
    r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
    r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe",
]
WARP_SOCKS = "socks5h://127.0.0.1:40000"
REPORTS_DIR = Path(__file__).resolve().parent / "reports"

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "Anti-Clickjacking"),
    ("x-content-type-options", "MIME Sniffing"),
    ("referrer-policy", "Referrer Policy"),
    ("permissions-policy", "Permissions Policy"),
    ("cross-origin-resource-policy", "CORP"),
    ("cross-origin-opener-policy", "COOP"),
]

# User-Agents rotativos para evadir WAFs básicos
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# ------------------------------------------------------------------ Endpoints Candidates (Diccionario gordo)
API_PATHS = [
    # Raíz y descubrimiento
    "/", "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/.well-known/openid-configuration", "/.well-known/jwks.json", "/.well-known/assetlinks.json",
    "/.env", "/config.json", "/manifest.json", "/package.json", "/composer.json",
    
    # Health, status, info
    "/health", "/healthz", "/healthcheck", "/health/check",
    "/status", "/server-status", "/server-info",
    "/info", "/version", "/ping", "/ready", "/live",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/configprops", "/actuator/metrics",

    # Docs & schemas
    "/docs", "/redoc", "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/openapi.yaml", "/openapi/v3/api-docs",
    "/graphql", "/graphiql", "/playground", "/altair",
    "/_explorer", "/__graphql",

    # API roots
    "/api", "/api/", "/v1", "/v2", "/v3",
    "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/service", "/services", "/srv",
    "/gateway", "/gateway/api",
    "/backend", "/core", "/internal",
    "/public", "/public/api",
    "/external", "/external/api",
    "/mobile", "/mobile/api",
    "/app", "/app/api",
    "/web", "/web/api",
    "/portal", "/portal/api",

    # Auth & Identity
    "/api/auth", "/api/auth/login", "/api/auth/logout", "/api/auth/register",
    "/api/auth/token", "/api/auth/refresh", "/api/auth/verify", "/api/auth/forgot",
    "/api/auth/reset", "/api/auth/callback", "/api/auth/me",
    "/api/login", "/api/logout", "/api/register", "/api/signup",
    "/api/signin", "/api/signout", "/api/sign-in", "/api/sign-up",
    "/api/session", "/api/sessions", "/api/token", "/api/tokens",
    "/api/oauth", "/api/oauth/token", "/api/oauth/authorize", "/api/oauth2/token",
    "/api/oidc", "/api/sso", "/api/saml",
    "/auth/login", "/auth/token", "/auth/callback",
    "/login", "/logout", "/signin", "/signup",
    "/oauth/token", "/oauth/authorize", "/oauth2/token",
    "/token", "/jwt", "/connect/token",

    # Usuarios & Perfil
    "/api/whoami", "/api/me", "/api/self",
    "/api/user", "/api/users", "/api/user/me", "/api/user/profile",
    "/api/profile", "/api/account", "/api/accounts",
    "/api/cliente", "/api/clientes",
    "/api/persona", "/api/personas",
    "/api/usuario", "/api/usuarios",
    "/api/customer", "/api/customers",
    "/api/member", "/api/members",
    "/whoami", "/me", "/user", "/users", "/profile",

    # Datos, consultas, búsqueda
    "/api/search", "/api/buscar", "/api/find", "/api/lookup",
    "/api/query", "/api/filter",
    "/api/consulta", "/api/consultar", "/api/consultas",
    "/api/data", "/api/datos", "/api/records",
    "/api/list", "/api/catalog", "/api/catalogo",
    "/api/productos", "/api/products",
    "/api/items", "/api/entries", "/api/resources",
    "/search", "/find", "/query", "/lookup",

    # Transacciones, financiero, saldos
    "/api/transactions", "/api/transacciones",
    "/api/transfers", "/api/transferencias",
    "/api/payments", "/api/pagos",
    "/api/balance", "/api/saldo", "/api/saldos",
    "/api/movements", "/api/movimientos",
    "/api/history", "/api/historial",
    "/api/statement", "/api/extracto",
    "/api/invoice", "/api/invoices", "/api/facturas",
    "/api/orders", "/api/ordenes", "/api/pedidos",
    "/api/receipt", "/api/recibo",
    "/api/billing", "/api/facturacion",

    # Verificaciones y validaciones
    "/api/verify", "/api/validate", "/api/check",
    "/api/estado", "/api/status",
    "/api/certificado", "/api/certificados",
    "/api/certified", "/api/certificate",
    "/api/solicitud", "/api/solicitudes",
    "/api/tramite", "/api/tramites",
    "/api/documento", "/api/documentos",

    # Notificaciones, mensajes
    "/api/notifications", "/api/notificaciones",
    "/api/messages", "/api/mensajes",
    "/api/inbox", "/api/alerts", "/api/alertas",
    "/api/push", "/api/email",

    # Admin & Config
    "/api/admin", "/api/dashboard",
    "/api/config", "/api/configuration", "/api/configuracion",
    "/api/settings", "/api/preferences",
    "/api/keys", "/api/apikeys",
    "/api/metrics", "/api/stats", "/api/statistics",
    "/api/logs", "/api/audit", "/api/events",
    "/api/roles", "/api/permissions",
    "/admin", "/dashboard", "/panel", "/backoffice",
    "/console", "/manage", "/management",
    "/cms", "/wp-admin", "/wp-json", "/wp-json/wp/v2",

    # Webhooks & integrations
    "/api/webhook", "/api/webhooks",
    "/api/callback", "/api/hook", "/api/hooks",
    "/api/integration", "/api/integrations",
    "/webhook", "/webhooks", "/callback",

    # CDN, assets, uploads
    "/api/upload", "/api/uploads", "/api/files", "/api/media",
    "/api/images", "/api/assets", "/api/attachments",
    "/api/storage", "/api/download",
    "/uploads", "/media", "/assets", "/static", "/files",
    "/cdn", "/content",

    # Misc / Common frameworks
    "/__debug__", "/_debug", "/debug",
    "/test", "/testing", "/dev", "/development",
    "/staging", "/sandbox",
    "/api/test", "/api/ping", "/api/echo",
    "/error", "/404", "/500",
    "/favicon.ico", "/crossdomain.xml",
    "/elmah.axd", "/trace.axd",
    "/.git/config", "/.git/HEAD",
    "/.svn/entries",
    "/wp-login.php", "/wp-content",
    "/administrator", "/admin.php",
    "/phpmyadmin", "/pma",
    "/cgi-bin/", "/cgi-bin/test",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/Global.asax",
]

# Parámetros para fuzzing
QUERY_PARAMS = [
    {"id": "1"},
    {"userId": "1"},
    {"uid": "1"},
    {"user": "admin"},
    {"username": "admin"},
    {"email": "test@example.com"},
    {"token": "test"},
    {"key": "test"},
    {"q": "test"},
    {"query": "test"},
    {"search": "test"},
    {"doc": "12345678"},
    {"documento": "12345678"},
    {"cedula": "12345678"},
    {"page": "1"},
    {"limit": "10"},
    {"offset": "0"},
    {"format": "json"},
    {"type": "all"},
    {"action": "list"},
    {"cmd": "info"},
    {"debug": "true"},
    {"test": "true"},
    {"callback": "test"},
    {"num": "1001"},
    {"code": "1001"},
    {"ref": "1001"},
    {"cuenta": "1001"},
    {"transaccion": "1001"},
    {"lang": "en"},
    {"locale": "es"},
    {"v": "1"},
    {"api_key": "test"},
    {"access_token": "test"},
]

# Rutas donde se aplica fuzzing de parámetros
PARAM_FUZZ_PATHS = [
    "/api", "/api/v1", "/api/v2",
    "/api/search", "/api/buscar", "/api/query",
    "/api/consulta", "/api/consultar",
    "/api/data", "/api/datos",
    "/api/user", "/api/users",
    "/api/check", "/api/verify", "/api/validate",
    "/api/status", "/api/lookup", "/api/find",
    "/search", "/query", "/find", "/lookup",
    "/api/whoami", "/api/me",
    "/graphql",
]

# Estado global
WARP_CONNECTED = False
WARP_BYPASS = False
WARP_EXE = None


# ------------------------------------------------------------------ WARP
def find_warp():
    global WARP_EXE
    if WARP_EXE:
        return WARP_EXE
    for p in WARP_PATHS:
        found = shutil.which(p)
        if found:
            WARP_EXE = found
            return found
        if Path(p).is_file():
            WARP_EXE = p
            return p
    return None


def get_warp_status():
    exe = find_warp()
    if not exe:
        return False, "warp-cli no encontrado."
    try:
        proc = subprocess.run([exe, "status"], capture_output=True, text=True, timeout=10)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        low = out.lower()
        ok = "connected" in low and "not connected" not in low and "disconnected" not in low
        return ok, out or f"exit {proc.returncode}"
    except Exception as e:
        return False, str(e)


def check_egress_ip(use_warp=False):
    s = requests.Session()
    if use_warp:
        s.proxies = {"http": WARP_SOCKS, "https": WARP_SOCKS}
    try:
        r = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=8)
        data = {}
        for line in r.text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
        return {"ok": True, "ip": data.get("ip", "?"), "loc": data.get("loc", "?"), "warp": data.get("warp", "off")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_session(ua_index=0):
    """Session con retry y User-Agent rotativo."""
    s = requests.Session()
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=60, pool_maxsize=60)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": USER_AGENTS[ua_index % len(USER_AGENTS)],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
        "Accept-Language": "es-CO,es;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
    })
    if WARP_CONNECTED and not WARP_BYPASS:
        s.proxies = {"http": WARP_SOCKS, "https": WARP_SOCKS}
    return s


# ------------------------------------------------------------------ URL helpers
def normalize_url(raw):
    url = (raw or "").strip()
    if not url:
        return None
    # No permitir espacios en el hostname / URL
    if " " in url or "\t" in url:
        return None
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    if not p.netloc or " " in p.netloc:
        return None
    # Un dominio válido tiene al menos un punto (ej: test.com) o es localhost/IP
    if "." not in p.netloc and p.netloc.lower() not in ("localhost", "127.0.0.1"):
        return None
    # Reconstruir solo scheme + netloc + path
    base = f"{p.scheme}://{p.netloc}"
    if p.path and p.path != "/":
        base += p.path.rstrip("/")
    return base


def resolve_targets(raw_input):
    """
    Parsea URLs o dominios a partir de:
    - Ruta a archivo .txt (con dominios separados por comas, saltos de línea o punto y coma)
    - Lista de dominios separados por comas introducida directamente (ej: 'dom1.com, dom2.com')
    - Una única URL o dominio
    """
    raw = (raw_input or "").strip().strip('"').strip("'")
    if not raw:
        return []

    tokens = []
    # 1. Verificar si es una ruta a archivo existente
    candidate_paths = [
        Path(raw),
        Path.cwd() / raw,
        Path(__file__).resolve().parent / raw,
    ]
    file_path = None
    for cp in candidate_paths:
        try:
            if cp.is_file():
                file_path = cp
                break
        except Exception:
            pass

    if file_path:
        print(f"{C.CYN}[*] Cargando objetivos desde archivo:{C.R} {file_path}")
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                # Separar por comas o punto y coma
                for item in re.split(r"[,;]+", line):
                    tokens.append(item)
        except Exception as e:
            print(f"{C.RED}[!] Error al leer el archivo {file_path}: {e}{C.R}")
            return []
    elif raw.lower().endswith(".txt"):
        print(f"{C.RED}[!] Archivo no encontrado: '{raw}'{C.R}")
        print(f"    {C.GRY}Verifica el nombre o coloca el archivo en esta misma carpeta.{C.R}")
        return []
    else:
        # Se asume entrada directa (uno o varios dominios separados por comas o punto y coma)
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            for item in re.split(r"[,;]+", line):
                tokens.append(item)

    targets = []
    seen = set()
    for tok in tokens:
        tok = tok.strip().strip('"').strip("'")
        if not tok or tok.startswith("#") or tok.startswith("//"):
            continue
        norm = normalize_url(tok)
        if norm and norm not in seen:
            seen.add(norm)
            targets.append(norm)

    return targets


def check_warp_or_ask():
    """Si WARP no está activo, pregunta si continuar en directo."""
    global WARP_BYPASS
    if WARP_CONNECTED or WARP_BYPASS:
        return True
    print(f"\n{C.YLW}[!]{C.R} WARP no está conectado. Tu IP real será visible.")
    try:
        ans = input(f"{C.B}¿Continuar con conexión directa? (S/n): {C.R}").strip().lower()
        if ans in ("", "s", "si", "y", "yes"):
            WARP_BYPASS = True
            return True
    except (EOFError, KeyboardInterrupt):
        pass
    return False


# ------------------------------------------------------------------ Whoami / Fingerprint
def audit_url(url, session):
    result = {"url": url, "ok": False, "error": None, "ts": datetime.now().isoformat()}
    t0 = time.time()
    try:
        resp = session.get(url, timeout=20, allow_redirects=True)
    except requests.RequestException as e:
        result["error"] = str(e)
        result["elapsed"] = round(time.time() - t0, 2)
        return result

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    server = hdrs.get("server", "No expuesto")
    tech = []
    if hdrs.get("x-powered-by"):
        tech.append(f"X-Powered-By: {hdrs['x-powered-by']}")
    if hdrs.get("cf-ray"):
        tech.append(f"Cloudflare (Ray: {hdrs['cf-ray']})")
    if hdrs.get("x-amz-cf-id") or hdrs.get("x-amz-request-id"):
        tech.append("AWS (CloudFront/S3/Lambda)")
    if hdrs.get("x-azure-ref"):
        tech.append("Azure")
    if hdrs.get("via"):
        tech.append(f"Via: {hdrs['via']}")
    if hdrs.get("x-aspnet-version"):
        tech.append(f"ASP.NET {hdrs['x-aspnet-version']}")
    if hdrs.get("x-drupal-cache") or hdrs.get("x-generator", "").lower().startswith("drupal"):
        tech.append("Drupal")
    if "x-wordpress" in " ".join(hdrs.keys()) or "wp-" in (hdrs.get("link") or ""):
        tech.append("WordPress")
    if "akamai" in " ".join(hdrs.keys()) or "akamai" in server.lower() or "type=ssa" in hdrs.get("content-type", "").lower():
        tech.append("Akamai CDN / WAF")
    if "!ut/p/" in resp.text[:3000] or "wps" in resp.url.lower():
        tech.append("IBM WebSphere Portal")

    sec = []
    for h, desc in SECURITY_HEADERS:
        sec.append({"header": h, "desc": desc, "ok": h in hdrs, "val": hdrs.get(h)})

    cookies = []
    for ck in resp.cookies:
        cookies.append({"name": ck.name, "secure": ck.secure,
                        "httponly": bool(getattr(ck, "_rest", {}).get("httponly") or ck.has_nonstandard_attr("httponly"))})

    result.update({
        "ok": True, "status": resp.status_code, "final_url": resp.url,
        "redirects": [r.url for r in resp.history],
        "elapsed": round(time.time() - t0, 2),
        "content_type": hdrs.get("content-type", "?"),
        "length": len(resp.content), "server": server,
        "tech": tech, "sec": sec, "cookies": cookies, "headers": hdrs,
    })
    return result


def print_audit(r):
    if not r.get("ok"):
        print(f"\n{C.RED}[!] Error:{C.R} {r.get('error')}")
        return
    sc = C.GRN if r["status"] < 400 else C.YLW
    print(f"\n{C.CYN}{'='*72}{C.R}")
    print(f"{C.GRN}{C.B} FINGERPRINT / WHOAMI{C.R}")
    print(f"{C.CYN}{'='*72}{C.R}")
    print(f" {C.B}URL:{C.R}            {r['url']}")
    print(f" {C.B}URL Final:{C.R}      {r['final_url']}")
    print(f" {C.B}HTTP:{C.R}           {sc}{r['status']}{C.R}")
    print(f" {C.B}Tiempo:{C.R}         {r['elapsed']}s")
    print(f" {C.B}Content-Type:{C.R}   {r['content_type']}")
    print(f" {C.B}Tamaño:{C.R}         {r['length']} bytes")
    print(f" {C.B}Servidor:{C.R}       {C.YLW}{r['server']}{C.R}")
    if r["redirects"]:
        print(f"\n {C.B}Redirecciones ({len(r['redirects'])}):{C.R}")
        for u in r["redirects"]:
            print(f"   -> {C.GRY}{u}{C.R}")
    if r["tech"]:
        print(f"\n {C.B}Tecnologías / WAF:{C.R}")
        for t in r["tech"]:
            print(f"   {C.CYN}•{C.R} {t}")
    print(f"\n {C.B}Cabeceras de Seguridad:{C.R}")
    for h in r["sec"]:
        if h["ok"]:
            v = f" {C.GRY}({h['val'][:55]}...){C.R}" if h["val"] and len(h["val"]) > 55 else f" {C.GRY}({h['val']}){C.R}" if h["val"] else ""
            print(f"   {C.GRN}[ OK ]{C.R} {h['header']:<30} {h['desc']}{v}")
        else:
            print(f"   {C.RED}[FALTA]{C.R} {h['header']:<30} {C.GRY}{h['desc']}{C.R}")
    if r["cookies"]:
        print(f"\n {C.B}Cookies ({len(r['cookies'])}):{C.R}")
        for ck in r["cookies"]:
            sf = f"{C.GRN}Secure{C.R}" if ck["secure"] else f"{C.RED}!Secure{C.R}"
            hf = f"{C.GRN}HttpOnly{C.R}" if ck["httponly"] else f"{C.RED}!HttpOnly{C.R}"
            print(f"   • {ck['name']} [{sf} | {hf}]")
    print(f"{C.CYN}{'='*72}{C.R}")


# ------------------------------------------------------------------ Endpoint Finder (Motor principal)
def extract_html_title(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    return m.group(1).strip() if m else ""


def harvest_robots_paths(base_url, session):
    """Extrae automáticamente rutas de robots.txt para añadirlas al escaneo."""
    discovered = []
    try:
        r = session.get(base_url + "/robots.txt", timeout=8, allow_redirects=False)
        if r.status_code == 200 and r.text:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        val = parts[1].strip()
                        if val and not val.startswith("#") and val.startswith("/"):
                            clean = val.split("?")[0].split("*")[0].strip()
                            if clean and clean not in ("/", "") and len(clean) > 1:
                                discovered.append(clean)
    except Exception:
        pass
    seen = set()
    return [p for p in discovered if not (p in seen or seen.add(p))]


def harvest_sitemap_paths(base_url, session):
    """Extrae rutas de /sitemap.xml para añadirlas al escaneo."""
    discovered = []
    try:
        r = session.get(base_url + "/sitemap.xml", timeout=8, allow_redirects=True)
        if r.status_code == 200 and r.text:
            locs = re.findall(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", r.text, re.I)
            p_base = urlparse(base_url)
            for loc in locs[:40]:
                p_loc = urlparse(loc)
                if p_loc.netloc == p_base.netloc and p_loc.path:
                    clean = p_loc.path.split("?")[0].rstrip("/")
                    if clean and clean not in ("/", "") and len(clean) > 1:
                        discovered.append(clean)
    except Exception:
        pass
    seen = set()
    return [p for p in discovered if not (p in seen or seen.add(p))]


# Dominios o CDN de scripts de terceros a descartar
THIRD_PARTY_JS_BLACKLIST = (
    "google", "googletagmanager", "google-analytics", "analytics",
    "facebook", "connect.facebook.net", "doubleclick", "hotjar",
    "sentry", "cloudflareinsights", "clarity.ms", "recaptcha",
    "fontawesome", "jsdelivr", "cdnjs", "unpkg", "polyfill",
    "newrelic", "datadog", "segment", "intercom"
)

# Extensiones estáticas no API
STATIC_EXTENSIONS_BLACKLIST = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4",
    ".pdf", ".zip", ".tar", ".gz"
)


def extract_endpoint_patterns_from_text(text):
    """Extrae candidatos a endpoints de texto/código (HTML o JS)."""
    endpoints = []
    if not text:
        return endpoints

    # Patrón 1: Rutas explícitas de API / auth / servicios entre comillas
    p1 = re.findall(
        r"""(?:['"`])(/(?:api|v[0-9]|rest|graphql|service|auth|gateway|backend|users?|account|datos?|query|tokens?|webhook)[a-zA-Z0-9_\-\./]*)['"`]""",
        text,
        re.I
    )
    endpoints.extend(p1)

    # Patrón 2: Llamadas de fetch / axios / xhr
    p2 = re.findall(
        r"""(?:fetch|axios(?:\.get|\.post|\.put|\.delete|\.patch)?|\$\.ajax|\$\.get|\$\.post)\s*\(\s*['"`](/[a-zA-Z0-9_\-\./]+)""",
        text,
        re.I
    )
    endpoints.extend(p2)

    # Patrón 3: Declaraciones de rutas
    p3 = re.findall(
        r"""(?:path|url|endpoint|route)\s*:\s*['"`](/[a-zA-Z0-9_\-\./]+)['"`]""",
        text,
        re.I
    )
    endpoints.extend(p3)

    return endpoints


def fetch_and_extract_js_endpoints(js_url, session):
    """Descarga un archivo JS y extrae candidatos a endpoints."""
    try:
        r = session.get(js_url, timeout=5, allow_redirects=True)
        if r.status_code == 200 and r.text:
            return extract_endpoint_patterns_from_text(r.text)
    except Exception:
        pass
    return []


def harvest_spider_endpoints(base_url, session, max_js_files=8):
    """
    Rastreo autónomo (spider/crawler de endpoints):
    1. Analiza el HTML principal para extraer rutas internas (enlaces, actions) y scripts inline.
    2. Identifica y descarga scripts JavaScript propios de la aplicación para extraer rutas de API ocultas.
    """
    discovered = []
    p_base = urlparse(base_url)
    js_urls = []

    try:
        r = session.get(base_url, timeout=10, allow_redirects=True)
        if r.status_code != 200 or not r.text:
            return []
        html = r.text

        # Buscar enlaces internos href y action
        href_action = re.findall(r"""(?:href|action)=["']([^"'#\s]+)["']""", html, re.I)
        for link in href_action:
            if link.startswith("/"):
                path_only = link.split("?")[0].rstrip("/")
                if path_only and len(path_only) > 1 and not path_only.lower().endswith(STATIC_EXTENSIONS_BLACKLIST):
                    if any(k in path_only.lower() for k in ("/api", "/v1", "/v2", "/v3", "/service", "/auth", "/rest", "/user", "/data", "/login", "/portal")):
                        discovered.append(path_only)
            elif link.startswith("http"):
                p_link = urlparse(link)
                if p_link.netloc == p_base.netloc and p_link.path:
                    path_only = p_link.path.rstrip("/")
                    if path_only and len(path_only) > 1 and not path_only.lower().endswith(STATIC_EXTENSIONS_BLACKLIST):
                        if any(k in path_only.lower() for k in ("/api", "/v1", "/v2", "/v3", "/service", "/auth", "/rest", "/user", "/data", "/login", "/portal")):
                            discovered.append(path_only)

        # Buscar scripts JS
        script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, re.I)
        preload_srcs = re.findall(r"""<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+)["']""", html, re.I)
        all_srcs = script_srcs + preload_srcs

        for src in all_srcs:
            src = src.strip()
            if any(tp in src.lower() for tp in THIRD_PARTY_JS_BLACKLIST):
                continue
            if src.startswith("//"):
                full_js = p_base.scheme + ":" + src
            elif src.startswith("/"):
                full_js = base_url.rstrip("/") + src
            elif src.startswith("http"):
                p_s = urlparse(src)
                if p_s.netloc != p_base.netloc:
                    continue
                full_js = src
            else:
                full_js = base_url.rstrip("/") + "/" + src

            if full_js not in js_urls and full_js.split("?")[0].endswith(".js"):
                js_urls.append(full_js)

        # Escanear el HTML inline
        inline_candidates = extract_endpoint_patterns_from_text(html)
        discovered.extend(inline_candidates)

        # Descargar scripts JS propios y extraer endpoints
        if js_urls:
            target_scripts = js_urls[:max_js_files]
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                future_to_url = {pool.submit(fetch_and_extract_js_endpoints, js_url, session): js_url for js_url in target_scripts}
                for fut in concurrent.futures.as_completed(future_to_url):
                    try:
                        eps = fut.result()
                        discovered.extend(eps)
                    except Exception:
                        pass
    except Exception:
        pass

    seen = set()
    clean_discovered = []
    for p in discovered:
        if not p.startswith("/"):
            p = "/" + p
        p = p.split("?")[0].rstrip("/")
        if p and p not in seen and len(p) > 1 and not p.lower().endswith(STATIC_EXTENSIONS_BLACKLIST):
            seen.add(p)
            clean_discovered.append(p)

    return clean_discovered


def build_jobs(extra_paths=None):
    """Genera todos los trabajos de escaneo: rutas base + rutas descubiertas + parámetros."""
    all_paths = list(API_PATHS)
    if extra_paths:
        for ep in extra_paths:
            if ep not in all_paths:
                all_paths.append(ep)

    jobs = []
    for p in all_paths:
        jobs.append((p, None))
    for p in PARAM_FUZZ_PATHS:
        for qs in QUERY_PARAMS:
            jobs.append((p, qs))

    seen = set()
    unique = []
    for path, params in jobs:
        key = (path, tuple(sorted(params.items())) if params else None)
        if key not in seen:
            seen.add(key)
            unique.append((path, params))
    return unique


def get_baseline_fingerprints(base_url, session):
    """
    Obtiene múltiples huellas de respuestas 404/catch-all para detectar soft-404 con precisión:
    - Hashes MD5 del body
    - Tamaños de body
    - Título HTML de la página de error / landing catch-all
    - Destinos de redirección catch-all (ej: /personas)
    """
    probes = [
        "/nadiescan_fake_404_a1b2c3",
        "/api/nadiescan_fake_z9y8x7",
        "/api/v1/nadiescan_bogus_p4q5r6",
    ]
    fp = {
        "hashes": set(),
        "sizes": [],
        "titles": set(),
        "final_urls": set(),
        "final_paths": set(),
    }
    for probe in probes:
        try:
            r = session.get(base_url + probe, timeout=10, allow_redirects=True)
            body_hash = hashlib.md5(r.content).hexdigest()
            fp["hashes"].add(body_hash)
            fp["sizes"].append(len(r.content))

            p_final = urlparse(r.url)
            fp["final_urls"].add(r.url.split("?")[0].rstrip("/"))
            fp["final_paths"].add(p_final.path.rstrip("/"))

            if "html" in r.headers.get("content-type", "").lower():
                title = extract_html_title(r.text)
                if title:
                    fp["titles"].add(title)
        except Exception:
            pass
    return fp


def probe_endpoint(base_url, path, params, session, baseline):
    """Prueba un endpoint y determina con precisión si es un hallazgo real o un soft-404."""
    url = base_url + path
    if params:
        url += "?" + urlencode(params)

    entry = {
        "path": path, "params": params, "url": url,
        "found": False, "status": None, "duration": None,
        "content_type": None, "length": 0, "json_keys": None,
        "body_preview": "", "notes": "", "interest": 0,
    }

    try:
        t0 = time.time()
        resp = session.get(url, timeout=(3.0, 5.0), allow_redirects=True)
        dur = round(time.time() - t0, 2)

        entry["status"] = resp.status_code
        entry["final_url"] = resp.url
        entry["duration"] = dur
        ctype = resp.headers.get("content-type", "")
        entry["content_type"] = ctype
        entry["length"] = len(resp.content)

        # 1. Filtrar códigos estándar de no encontrado / error servidor
        if resp.status_code in (404, 410, 501, 502, 503, 504):
            return entry

        # 2. Filtrar soft-404 exacto por hash MD5
        body_hash = hashlib.md5(resp.content).hexdigest()
        if body_hash in baseline.get("hashes", set()):
            return entry

        # 3. Filtrar redirección a catch-all landing page (ej: /personas o / en Bancolombia)
        p_final = urlparse(resp.url)
        final_path = p_final.path.rstrip("/")
        final_url = resp.url.split("?")[0].rstrip("/")
        is_html = "html" in ctype.lower()
        requested_path = path.rstrip("/")

        # Si el resultado final es una ruta de aterrizaje catch-all y no estábamos probando esa ruta
        if baseline.get("final_paths") and final_path in baseline["final_paths"] and requested_path not in baseline["final_paths"]:
            return entry
        if baseline.get("final_urls") and final_url in baseline["final_urls"] and requested_path not in baseline["final_paths"]:
            return entry

        # Si redirige a la raíz "/" o home y no estábamos probando "/"
        p_base = urlparse(base_url)
        if final_path in ("", "/") and requested_path not in ("", "/") and p_final.netloc == p_base.netloc:
            return entry

        # 4. Filtrar por título HTML idéntico al del catch-all 404
        if is_html and baseline.get("titles"):
            page_title = extract_html_title(resp.text)
            if page_title and page_title in baseline["titles"] and resp.status_code == 200:
                return entry

        # 5. Filtrar por similitud de tamaño con baseline 404 HTML si es 200 genérico
        if is_html and baseline.get("sizes") and resp.status_code == 200:
            avg_size = sum(baseline["sizes"]) / len(baseline["sizes"])
            diff = abs(len(resp.content) - avg_size)
            if avg_size > 0 and (diff < 400 or (diff / avg_size) < 0.03):
                return entry

        # ---- HALLAZGO REAL ----
        # JSON API
        is_json = False
        if "json" in ctype or resp.text.strip()[:1] in ("{", "["):
            try:
                data = resp.json()
                if isinstance(data, dict):
                    entry["json_keys"] = list(data.keys())[:25]
                    pairs = []
                    for k, v in list(data.items())[:8]:
                        val_str = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
                        pairs.append(f'"{k}": {val_str[:40]}')
                    data_sample = "{" + ", ".join(pairs) + "}"
                    is_json = True
                elif isinstance(data, list) and data:
                    if isinstance(data[0], dict):
                        entry["json_keys"] = list(data[0].keys())[:25]
                    data_sample = f"Lista ({len(data)} items): {json.dumps(data[0], ensure_ascii=False)[:160]}"
                    is_json = True
            except Exception:
                pass

        is_xml = "xml" in ctype.lower() and resp.text.strip().startswith("<")
        is_api_contract = resp.status_code in (405, 422)
        is_auth_contract = resp.status_code == 401 or ("www-authenticate" in resp.headers and resp.status_code in (401, 403))
        is_well_known = path in ("/robots.txt", "/sitemap.xml", "/.well-known/openid-configuration", "/.well-known/assetlinks.json") and resp.status_code == 200

        # CRITERIO DE ENDPOINT REAL:
        # Detecta datos estructurados (JSON/XML), endpoints protegidos (401/403 Auth) y contratos de método (405/422)
        if is_json:
            entry["found"] = True
            entry["notes"] = "API JSON"
            entry["interest"] = 4
        elif is_xml:
            entry["found"] = True
            entry["notes"] = "API XML"
            entry["interest"] = 3
            data_sample = resp.text[:200].replace("\r", " ").replace("\n", " ").strip()
        elif is_auth_contract:
            entry["found"] = True
            entry["notes"] = f"API Activa Protegida (HTTP {resp.status_code} - Requiere Auth/Token)"
            entry["interest"] = 3
            data_sample = resp.text[:200].replace("\r", " ").replace("\n", " ").strip() or f"Autenticación requerida ({resp.status_code})"
        elif is_api_contract:
            entry["found"] = True
            entry["notes"] = f"API Activa (HTTP {resp.status_code} - Requiere método o parámetros)"
            entry["interest"] = 3
            data_sample = resp.text[:200].replace("\r", " ").replace("\n", " ").strip()
        elif is_well_known:
            entry["found"] = True
            entry["notes"] = "Archivo de Descubrimiento"
            entry["interest"] = 2
            data_sample = resp.text[:200].replace("\r", " ").replace("\n", " ").strip()
        else:
            # Si devolvió 403 (bloqueo WAF sin datos), 302 (redirect), o 200 HTML genérico:
            # NO ES UN ENDPOINT DE API Y NO DEVUELVE DATOS -> SE DESCARTA
            entry["found"] = False
            return entry

        entry["data_sample"] = data_sample
        entry["body_preview"] = data_sample

    except requests.RequestException as e:
        entry["status"] = "ERR"
        entry["notes"] = type(e).__name__

    return entry


def find_endpoints(base_url, session, max_workers=32):
    """Motor principal de búsqueda de endpoints concurrente con auto-descubrimiento."""
    print(f"\n{C.CYN}{'='*72}{C.R}")
    print(f"{C.GRN}{C.B} API / ENDPOINT FINDER{C.R}")
    print(f" {C.B}Target:{C.R}          {base_url}")
    print(f" {C.B}Workers:{C.R}         {max_workers}")

    # 1. Auto-descubrimiento activo (Robots, Sitemap, HTML & Spider de JavaScript)
    print(f"{C.GRY}[*] Buscando rutas automáticamente por su cuenta (robots, sitemap, HTML y scripts JS)...{C.R}")
    discovered_robots = harvest_robots_paths(base_url, session)
    discovered_sitemap = harvest_sitemap_paths(base_url, session)
    discovered_spider = harvest_spider_endpoints(base_url, session)

    all_discovered = list(dict.fromkeys(discovered_robots + discovered_sitemap + discovered_spider))
    if all_discovered:
        print(f" {C.GRN}[+]{C.R} {len(all_discovered)} rutas descubiertas automáticamente (por su cuenta):")
        sample = all_discovered[:5]
        print(f"     {C.CYN}{', '.join(sample)}{'...' if len(all_discovered) > 5 else ''}{C.R}")

    jobs = build_jobs(extra_paths=all_discovered)
    total = len(jobs)
    print(f" {C.B}Total a probar:{C.R}  {total}")
    print(f"{C.CYN}{'='*72}{C.R}")

    # 2. Baseline inteligente de soft-404 / catch-all
    print(f"\n{C.GRY}[*] Tomando fingerprint de respuestas 404 y redirecciones catch-all...{C.R}")
    baseline = get_baseline_fingerprints(base_url, session)
    catchall_info = []
    if baseline.get("final_paths"):
        catchall_info.append(f"Landing catch-all: {', '.join(baseline['final_paths'])}")
    if baseline.get("titles"):
        catchall_info.append(f"Título: {', '.join(list(baseline['titles'])[:2])}")
    print(f"{C.GRY}[*] Filtros activos: {len(baseline['hashes'])} hashes, {len(baseline['sizes'])} baselines ({'; '.join(catchall_info)}){C.R}\n")

    results = []
    found_count = 0
    t_start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {
            pool.submit(probe_endpoint, base_url, path, params, session, baseline): (path, params)
            for path, params in jobs
        }

        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            res = fut.result()
            results.append(res)

            if res["found"]:
                found_count += 1
                sc = C.GRN if res["status"] in (200, 201, 204) else C.YLW
                jb = f" {C.MAG}[Campos: {', '.join(res['json_keys'][:6])}]{C.R}" if res["json_keys"] else ""
                nb = f" {C.CYN}({res['notes']}){C.R}" if res["notes"] else ""

                print(f"{C.GRN}[+]{C.R} {res['url']}")
                print(f"    {sc}HTTP {res['status']}{C.R} | {res['duration']}s | {res['length']}b{jb}{nb}")
                sample = res.get("data_sample") or res.get("body_preview")
                if sample:
                    print(f"    {C.CYN}Info devuelta:{C.R} {C.WHT}{sample[:140]}{C.R}")
                print()

            pct = int((done / total) * 100)
            sys.stdout.write(f"\r{C.GRY}[{done}/{total} ({pct}%)] Hallazgos: {found_count}{C.R}   ")
            sys.stdout.flush()

    elapsed = round(time.time() - t_start, 2)
    print(f"\r{' '*60}\r", end="")

    # Resumen ordenado por interés
    found_list = sorted([r for r in results if r["found"]], key=lambda x: x.get("interest", 0), reverse=True)

    print(f"\n{C.CYN}{'='*72}{C.R}")
    print(f"{C.GRN}{C.B} RESUMEN - {elapsed}s{C.R}")
    print(f" Probados: {total} | Hallazgos: {C.GRN if found_count else C.YLW}{found_count}{C.R}")

    if found_list:
        print(f"\n {C.B}Endpoints por relevancia:{C.R}")
        for r in found_list:
            star = "★" * min(r.get("interest", 0), 5)
            jb = f" [Campos: {', '.join(r['json_keys'][:6])}]" if r["json_keys"] else ""
            nb = f" ({r['notes']})" if r["notes"] else ""
            print(f"   {C.YLW}{star:<5}{C.R} {r['status']} {r['url']}{C.GRY}{jb}{nb}{C.R}")

    print(f"{C.CYN}{'='*72}{C.R}\n")
    return results


# ------------------------------------------------------------------ Reporte
def save_report(target, audit_data, endpoints):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", urlparse(target).netloc or "scan")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{safe}_{ts}"

    jp = REPORTS_DIR / f"{base}.json"
    tp = REPORTS_DIR / f"{base}.txt"

    found = [e for e in endpoints if e.get("found")]
    payload = {"target": target, "time": datetime.now().isoformat(),
               "audit": audit_data, "endpoints": found, "total_probed": len(endpoints)}

    jp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "=" * 72,
        f"REPORTE DETALLADO NADIESCAN - {target}",
        f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 72, "",
        "[FINGERPRINT DEL SERVIDOR]",
        f"URL Objetivo: {target}",
        f"Status:       {audit_data.get('status') if audit_data else 'N/A'}",
        f"Server:       {audit_data.get('server') if audit_data else 'No expuesto'}",
        f"Tecnologías:  {', '.join(audit_data.get('tech', [])) if audit_data and audit_data.get('tech') else 'Ninguna detectada'}",
        "",
        "=" * 72,
        f"[ENDPOINTS ENCONTRADOS Y DATOS DEVUELTOS ({len(found)})]",
        "=" * 72,
    ]

    if not found:
        lines.append("No se descubrieron endpoints públicos o con datos expuestos.")
    else:
        for idx, ep in enumerate(found, 1):
            lines.append(f"\n[#{idx}] {ep['url']}")
            lines.append(f"  • Estado HTTP:   [{ep['status']}] {ep.get('notes', '')}")
            lines.append(f"  • Content-Type:  {ep.get('content_type', 'N/A')} ({ep.get('length', 0)} bytes en {ep.get('duration', 0)}s)")
            if ep.get("params"):
                lines.append(f"  • Parámetros:    {json.dumps(ep['params'], ensure_ascii=False)}")
            if ep.get("json_keys"):
                lines.append(f"  • Campos JSON:   {', '.join(ep['json_keys'])}")
            
            sample = (ep.get("data_sample") or ep.get("body_preview") or "").strip()
            if sample:
                lines.append("  • Info / Datos devueltos:")
                for sline in sample.splitlines()[:5]:
                    lines.append(f"    | {sline[:150]}")
            lines.append("-" * 72)

    lines.append(f"\nTotal probados: {len(endpoints)} | Hallazgos válidos: {len(found)}")
    lines.append("=" * 72)
    tp.write_text("\n".join(lines), encoding="utf-8")

    print(f"{C.GRN}[+] Reporte guardado con detalle de datos:{C.R}")
    print(f"    JSON: {jp}")
    print(f"    TXT:  {tp}")


# ------------------------------------------------------------------ Menú
def banner():
    print(C.CYN + BANNER_ART + C.R)
    print(f"  {C.B}Auditoría Web & API/Endpoint Hunter{C.R} | {C.MAG}{VERSION}{C.R}")
    print(f"{C.CYN}{'='*72}{C.R}")
    if WARP_CONNECTED:
        wl = f"{C.GRN}[WARP ACTIVO]{C.R}"
    elif WARP_BYPASS:
        wl = f"{C.YLW}[CONEXIÓN DIRECTA]{C.R}"
    else:
        wl = f"{C.GRY}[SIN WARP - Conexión Directa]{C.R}"
    print(f"  • Red: {wl}")
    print(f"{C.CYN}{'='*72}{C.R}")


def main():
    global WARP_CONNECTED, WARP_BYPASS

    if "--no-warp" in sys.argv:
        WARP_BYPASS = True

    WARP_CONNECTED, _ = get_warp_status()

    while True:
        banner()
        print(" [1] Whoami / Fingerprint (URL, .txt o lista de dominios)")
        print(" [2] API / Endpoint Finder (URL, .txt o lista de dominios)")
        print(" [3] Auditoría Completa (Whoami + Finder + Reporte) (.txt o lista)")
        print(" [4] Búsqueda de Leaks, DBs / Información Expuesta")
        print(" [5] Diagnóstico de Red y Cloudflare WARP")
        print(" [0] Salir")
        print(f"{C.CYN}{'='*72}{C.R}")

        try:
            ch = input(f"{C.B}Opción [0-5]: {C.R}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.YLW}[*] Adiós.{C.R}")
            break

        if ch in ("1", "scan", "whoami"):
            try:
                t = input(f"\n{C.B}URL, dominios separados por coma o archivo .txt: {C.R}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            targets = resolve_targets(t)
            if not targets:
                print(f"{C.RED}[!] No se especificaron objetivos válidos.{C.R}")
                continue
            if not check_warp_or_ask():
                continue
            s = get_session()
            print(f"\n{C.GRN}[+]{C.R} Total de objetivos a auditar: {C.B}{len(targets)}{C.R}")
            for idx, url in enumerate(targets, 1):
                if len(targets) > 1:
                    print(f"\n{C.CYN}{'='*72}{C.R}")
                    print(f"{C.MAG}{C.B}>>> OBJETIVO [{idx}/{len(targets)}]: {url}{C.R}")
                    print(f"{C.CYN}{'='*72}{C.R}")
                print(f"\n{C.BLU}[*] Auditando {url}...{C.R}")
                r = audit_url(url, s)
                print_audit(r)

        elif ch in ("2", "find", "api"):
            try:
                t = input(f"\n{C.B}URL base, dominios separados por coma o archivo .txt: {C.R}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            targets = resolve_targets(t)
            if not targets:
                print(f"{C.RED}[!] No se especificaron objetivos válidos.{C.R}")
                continue
            if not check_warp_or_ask():
                continue
            s = get_session()
            print(f"\n{C.GRN}[+]{C.R} Total de objetivos a escanear: {C.B}{len(targets)}{C.R}")
            for idx, url in enumerate(targets, 1):
                if len(targets) > 1:
                    print(f"\n{C.CYN}{'='*72}{C.R}")
                    print(f"{C.MAG}{C.B}>>> OBJETIVO [{idx}/{len(targets)}]: {url}{C.R}")
                    print(f"{C.CYN}{'='*72}{C.R}")
                find_endpoints(url, s)

        elif ch in ("3", "full", "all"):
            try:
                t = input(f"\n{C.B}URL, dominios separados por coma o archivo .txt para auditoría completa: {C.R}").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            targets = resolve_targets(t)
            if not targets:
                print(f"{C.RED}[!] No se especificaron objetivos válidos.{C.R}")
                continue
            if not check_warp_or_ask():
                continue
            s = get_session()
            print(f"\n{C.GRN}[+]{C.R} Total de objetivos a auditar: {C.B}{len(targets)}{C.R}")

            multi_summary = []
            for idx, url in enumerate(targets, 1):
                if len(targets) > 1:
                    print(f"\n{C.CYN}{'='*72}{C.R}")
                    print(f"{C.MAG}{C.B}>>> AUDITANDO OBJETIVO [{idx}/{len(targets)}]: {url}{C.R}")
                    print(f"{C.CYN}{'='*72}{C.R}")
                print(f"\n{C.BLU}[*] Fase 1: Fingerprinting en {url}...{C.R}")
                a = audit_url(url, s)
                print_audit(a)
                print(f"\n{C.BLU}[*] Fase 2: Endpoint Finder & Spidering en {url}...{C.R}")
                ep = find_endpoints(url, s)
                print(f"\n{C.BLU}[*] Fase 3: Guardando reporte para {url}...{C.R}")
                save_report(url, a, ep)

                found_count = len([e for e in ep if e.get("found")])
                multi_summary.append({
                    "target": url,
                    "status": a.get("status", "N/A"),
                    "server": a.get("server", "N/A"),
                    "found_endpoints": found_count
                })

            if len(targets) > 1:
                print(f"\n{C.CYN}{'='*72}{C.R}")
                print(f"{C.GRN}{C.B} RESUMEN GENERAL DE ESCANEO POR LOTES ({len(targets)} dominios){C.R}")
                print(f"{C.CYN}{'='*72}{C.R}")
                for item in multi_summary:
                    sc = C.GRN if item["found_endpoints"] > 0 else C.YLW
                    print(f" • {item['target']:<38} | Server: {item['server']:<15} | Hallazgos: {sc}{item['found_endpoints']}{C.R}")
                print(f"{C.CYN}{'='*72}{C.R}\n")

        elif ch in ("4", "leaks", "dbs", "leak", "db", "exposicion"):
            if run_exposure_intelligence_cli:
                run_exposure_intelligence_cli(
                    session_factory=get_session,
                    default_warp_connected=WARP_CONNECTED,
                    default_warp_bypass=WARP_BYPASS
                )
            else:
                print(f"{C.RED}[!] Módulo de Inteligencia de Exposición no disponible.{C.R}")

        elif ch in ("5", "warp", "diag"):
            print(f"\n{C.CYN}{'='*60}{C.R}")
            print(f"{C.B} DIAGNÓSTICO DE RED{C.R}")
            print(f"{C.CYN}{'='*60}{C.R}")
            exe = find_warp()
            print(f" warp-cli:  {C.GRN + exe if exe else C.RED + 'No encontrado'}{C.R}")
            conn, det = get_warp_status()
            WARP_CONNECTED = conn
            print(f" Estado:    {C.GRN + 'CONECTADO' if conn else C.RED + 'NO CONECTADO'}{C.R}")
            print(f" Detalle:   {C.GRY}{det}{C.R}")

            print(f"\n {C.B}IP Pública (Directa):{C.R}")
            dc = check_egress_ip(False)
            if dc.get("ok"):
                print(f"   IP: {C.YLW}{dc['ip']}{C.R} | País: {dc['loc']} | WARP: {dc['warp']}")
            else:
                print(f"   Error: {dc.get('error')}")

            if conn:
                print(f"\n {C.B}IP vía WARP:{C.R}")
                wc = check_egress_ip(True)
                if wc.get("ok"):
                    print(f"   IP: {C.GRN}{wc['ip']}{C.R} | País: {wc['loc']} | WARP: {C.GRN}{wc['warp']}{C.R}")
                else:
                    print(f"   {C.RED}Proxy no respondió: {wc.get('error')}{C.R}")

            bypass_txt = f"{C.YLW}ACTIVO{C.R}" if WARP_BYPASS else f"{C.GRN}DESACTIVADO{C.R}"
            print(f"\n Bypass WARP: {bypass_txt}")
            try:
                tog = input(" ¿Alternar bypass? (s/n): ").strip().lower()
                if tog in ("s", "si", "y"):
                    WARP_BYPASS = not WARP_BYPASS
                    print(f"{C.GRN}[*] Bypass: {'ON' if WARP_BYPASS else 'OFF'}{C.R}")
            except (EOFError, KeyboardInterrupt):
                pass

        elif ch in ("0", "q", "exit", "salir"):
            print(f"\n{C.YLW}[*] Adiós.{C.R}")
            break
        else:
            print(f"{C.RED}[!] Opción inválida.{C.R}")


if __name__ == "__main__":
    main()
