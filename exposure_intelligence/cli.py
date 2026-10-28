# -*- coding: utf-8 -*-
"""
Interfaz de consola interactiva para el Módulo de Búsqueda de Leaks, DBs / Información Expuesta.
Integrada con la estética, colores ANSI y convenciones de AtlasScan / NadieScan.
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import requests

from .engine import ExposureAuditEngine
from .models import AuditScope, VerificationStatus, WarpPolicy
from .scope import ScopeValidator, ScopeValidationError
from .warp_checker import WarpChecker


# Colores ANSI idénticos a los de nadie_scan.py
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


def print_header(title: str):
    print(f"\n{C.CYN}{'='*72}{C.R}")
    print(f"{C.GRN}{C.B} {title}{C.R}")
    print(f"{C.CYN}{'='*72}{C.R}")


def run_exposure_intelligence_cli(session_factory, default_warp_connected: bool, default_warp_bypass: bool):
    """
    Controlador interactivo del módulo de exposición y leaks.
    session_factory: función que devuelve un requests.Session configurado según el entorno.
    """
    warp_checker = WarpChecker()
    status_report = warp_checker.check_status()

    while True:
        print_header("BÚSQUEDA DE LEAKS, DBS / INFORMACIÓN EXPUESTA")
        print(" Inteligencia pasiva de fuentes públicas, comprobaciones de bajo impacto,")
        print(" detección de secretos en código y gestión estructurada de evidencias.")
        print(f"{C.CYN}{'-'*72}{C.R}")

        # Mostrar estado de WARP actual
        if status_report.is_connected:
            warp_badge = f"{C.GRN}[CONECTADO]{C.R}"
        elif status_report.verifiable:
            warp_badge = f"{C.RED}[DESCONECTADO]{C.R}"
        else:
            warp_badge = f"{C.YLW}[NO DISPONIBLE / SIN WARP-CLI]{C.R}"

        print(f" • Estado Cloudflare WARP: {warp_badge} {C.GRY}({status_report.details}){C.R}")
        print(f"{C.CYN}{'-'*72}{C.R}")

        # 1. Solicitar Dominio Raíz
        try:
            raw_domain = input(f"{C.B}Dominio raíz para auditar (ej: empresa.com o '0' para volver): {C.R}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.YLW}[*] Operación cancelada.{C.R}")
            break

        if raw_domain in ("0", "salir", "exit", "q", ""):
            break

        root_domain = ScopeValidator.normalize_domain(raw_domain)
        apex_domain = ScopeValidator.extract_apex_domain(root_domain)
        if not ScopeValidator.is_valid_domain_syntax(root_domain):
            print(f"{C.RED}[!] Error: '{raw_domain}' no es un nombre de dominio válido.{C.R}")
            time.sleep(1)
            continue

        if apex_domain and apex_domain != root_domain:
            print(f" {C.GRN}[*]{C.R} Dominio Apex detectado: {C.B}{apex_domain}{C.R} (Auditoría ampliada a la organización)")

        # 2. Configurar Alcance y Subdominios Autorizados
        print(f"\n{C.CYN}[?] ALCANCE Y SUBDOMINIOS AUTORIZADOS{C.R}")
        print(f" [Enter] = Descubrimiento activo y auditoría de TODOS los subdominios (*.{apex_domain})")
        print(" O ingrese subdominios separados por comas, o la ruta a un archivo .txt con objetivos.")
        try:
            subs_input = input(f"{C.B}Subdominios autorizados [Enter para todos]: {C.R}").strip()
        except (EOFError, KeyboardInterrupt):
            break

        authorized_subdomains = []
        # Si se deja vacío, autorizar todos los subdominios del apex por defecto
        if not subs_input or subs_input == "*":
            authorized_subdomains.append(f"*.{apex_domain}")
            authorized_subdomains.append(apex_domain)
            if root_domain != apex_domain:
                authorized_subdomains.append(root_domain)
            print(f" {C.GRN}[+]{C.R} Alcance configurado: {C.B}*.{apex_domain}{C.R} (Todos los subdominios autorizados)")
        elif subs_input.lower().endswith(".txt") and Path(subs_input).is_file():
            print(f" {C.CYN}[*] Cargando objetivos desde archivo: {subs_input}{C.R}")
            try:
                for line in Path(subs_input).read_text(encoding="utf-8", errors="ignore").splitlines():
                    for item in line.replace(";", ",").split(","):
                        s_clean = ScopeValidator.normalize_domain(item)
                        if s_clean:
                            authorized_subdomains.append(s_clean)
                print(f" {C.GRN}[+]{C.R} {len(authorized_subdomains)} subdominios cargados desde archivo.")
            except Exception as e:
                print(f" {C.RED}[!] Error al leer archivo: {e}{C.R}")
        else:
            for s in subs_input.replace(";", ",").split(","):
                s_clean = ScopeValidator.normalize_domain(s)
                if s_clean:
                    authorized_subdomains.append(s_clean)

        # 3. Exclusiones expresas
        print(f"\n{C.CYN}[?] EXCLUSIONES EXPRESAS (Fuera de límites){C.R}")
        print(" Subdominios o áreas que NO deben ser consultadas bajo ninguna circunstancia.")
        try:
            excl_input = input(f"{C.B}Exclusiones separadas por comas (opcional): {C.R}").strip()
        except (EOFError, KeyboardInterrupt):
            break

        excluded_subdomains = []
        if excl_input:
            for e in excl_input.split(","):
                e_clean = ScopeValidator.normalize_domain(e)
                if e_clean:
                    excluded_subdomains.append(e_clean)

        # 4. Confirmación Explícita de Autorización
        print(f"\n{C.YLW}{'!'*72}{C.R}")
        print(f"{C.YLW}{C.B} AVISO DE AUTORIZACIÓN Y ÉTICA PROFESIONAL{C.R}")
        print(f" ¿Confirma que cuenta con autorización escrita para realizar esta auditoría")
        print(f" de seguridad defensiva sobre '{root_domain}'?")
        print(f"{C.YLW}{'!'*72}{C.R}")
        try:
            auth_confirm = input(f"{C.B}¿Autorización verificada? (s/N): {C.R}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if auth_confirm not in ("s", "si", "y", "yes"):
            print(f"{C.RED}[!] Auditoría abortada. No se ejecutan análisis sin autorización explícita.{C.R}")
            time.sleep(1.5)
            continue

        # 5. Política de Cloudflare WARP
        print(f"\n{C.CYN}[?] POLÍTICA DE TRANSPORTE Y RED (WARP){C.R}")
        print(" [1] STRICT  — Bloquear consultas externas si WARP no está conectado.")
        print(" [2] WARN    — Advertir si WARP no está activo y solicitar confirmación.")
        print(" [3] DIRECT  — Permitir conexión directa explícitamente.")
        try:
            policy_opt = input(f"{C.B}Seleccione política [1-3] (Por defecto 2): {C.R}").strip()
        except (EOFError, KeyboardInterrupt):
            break

        warp_policy = WarpPolicy.WARN.value
        if policy_opt == "1":
            warp_policy = WarpPolicy.STRICT.value
        elif policy_opt == "3":
            warp_policy = WarpPolicy.DIRECT.value

        # Si WARP no está activo y la política es WARN, pedir confirmación directa
        if not status_report.is_connected and warp_policy == WarpPolicy.WARN.value:
            print(f"\n{C.YLW}[!]{C.R} Cloudflare WARP no está conectado.")
            print(f"    {C.GRY}Detalle: {status_report.details}{C.R}")
            try:
                cont_direct = input(f"{C.B}¿Desea continuar utilizando su conexión directa a internet? (s/N): {C.R}").strip().lower()
                if cont_direct not in ("s", "si", "y", "yes"):
                    print(f"{C.RED}[*] Cancelado por política de transporte.{C.R}")
                    continue
                warp_policy = WarpPolicy.DIRECT.value
            except (EOFError, KeyboardInterrupt):
                break

        # 6. Selección de Fuentes
        print(f"\n{C.CYN}[?] SELECCIÓN DE FUENTES DISPONIBLES{C.R}")
        print(" [1] Todas las fuentes (Comprobaciones HTTP + OSINT Certs + Dorks + Repos + Breaches)")
        print(" [2] Solo Comprobaciones HTTP Directas de bajo impacto (.env, backups, .git, directorios)")
        print(" [3] Solo OSINT Pasivo (Certificados, Repositorios, Consultas de búsqueda)")
        try:
            src_choice = input(f"{C.B}Opción [1-3] (Por defecto 1): {C.R}").strip()
        except (EOFError, KeyboardInterrupt):
            break

        enabled_sources = ["all"]
        if src_choice == "2":
            enabled_sources = ["direct_http_verifier"]
        elif src_choice == "3":
            enabled_sources = ["osint_crtsh", "osint_search_engines", "osint_public_repos", "osint_breach_intel"]

        # Crear expediente
        ts_now = datetime.now().isoformat()
        scope = AuditScope(
            expediente_id="",
            root_domain=root_domain,
            authorized_subdomains=authorized_subdomains,
            excluded_subdomains=excluded_subdomains,
            timestamp=ts_now,
            enabled_sources=enabled_sources,
            rate_limit_rps=2.0,
            authorization_confirmed=True,
            warp_policy=warp_policy,
            notes="Iniciado desde interfaz interactiva AtlasScan."
        )

        engine = ExposureAuditEngine(scope=scope, warp_checker=warp_checker)

        # Iniciar análisis
        print_header(f"EJECUTANDO AUDITORÍA EN: {root_domain}")
        print(f"{C.GRY}[*] Presione Ctrl+C en cualquier momento para cancelar de forma segura.{C.R}\n")

        session = session_factory()

        def progress_printer(msg: str):
            print(f"{C.CYN}{msg}{C.R}")

        try:
            result = engine.run_audit(session=session, progress_callback=progress_printer)
        except KeyboardInterrupt:
            engine.cancel()
            print(f"\n{C.RED}[!] Cancelación solicitada por el usuario. Deteniendo procesos...{C.R}")
            time.sleep(1)
            continue
        except ScopeValidationError as e:
            print(f"\n{C.RED}[!] Error de validación de alcance: {e}{C.R}")
            input(f"{C.B}Presione Enter para continuar...{C.R}")
            continue
        except Exception as e:
            print(f"\n{C.RED}[!] Error inesperado durante la auditoría: {e}{C.R}")
            input(f"{C.B}Presione Enter para continuar...{C.R}")
            continue

        if not result.get("ok"):
            print(f"\n{C.RED}[!] La auditoría no pudo completarse:{C.R} {result.get('error')}")
            input(f"\n{C.B}Presione Enter para continuar...{C.R}")
            continue

        # Sub-menú de resultados del expediente
        findings = result.get("findings", [])
        case_path = Path(result["case_path"])
        report_file = Path(result["report_file"])

        while True:
            print_header(f"RESUMEN DEL EXPEDIENTE: {result['case_id']}")
            print(f" Dominio:        {root_domain}")
            print(f" Duración:       {result['elapsed_seconds']} segundos")
            print(f" Carpeta:        {case_path}")
            print(f" Reporte TXT:    {report_file}")
            print(f"{C.CYN}{'-'*72}{C.R}")

            sc_conf = C.RED if result['confirmed_count'] > 0 else C.GRN
            sc_val = C.YLW if result['validation_req_count'] > 0 else C.GRN
            print(f" • Vulnerabilidades Confirmadas:  {sc_conf}{result['confirmed_count']}{C.R}")
            print(f" • Pendientes de Validación:      {sc_val}{result['validation_req_count']}{C.R}")
            print(f" • Observaciones Pasivas:         {C.CYN}{result['observation_count']}{C.R}")
            print(f" • Total Hallazgos:               {C.B}{result['findings_count']}{C.R}")
            print(f"{C.CYN}{'-'*72}{C.R}")

            print(" [1] Ver lista de hallazgos")
            print(" [2] Filtrar hallazgos (por estado o severidad)")
            print(" [3] Inspeccionar evidencias redactadas")
            print(" [4] Ver estado de fuentes consultadas")
            print(" [5] Abrir o regenerar reporte TXT")
            print(" [0] Volver al menú principal")
            print(f"{C.CYN}{'='*72}{C.R}")

            try:
                sub_ch = input(f"{C.B}Opción [0-5]: {C.R}").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if sub_ch == "0":
                break

            elif sub_ch == "1":
                # Lista de hallazgos
                if not findings:
                    print(f"\n{C.GRN}[+] No se detectaron hallazgos para este dominio en las fuentes consultadas.{C.R}")
                else:
                    print_header(f"LISTA DE HALLAZGOS ({len(findings)})")
                    for f in findings:
                        sc = C.RED if f['verification_status'] == VerificationStatus.CONFIRMED_VULNERABILITY.value else C.YLW
                        print(f" • {C.B}[{f['id']}]{C.R} {sc}[{f['verification_status']}]{C.R} {C.MAG}[{f['severity']}]{C.R} {f['exposure_type']}")
                        print(f"    Activo: {f['target_asset']} | Fuente: {f['source']}")
                        if f.get('reference_url'):
                            print(f"    URL: {C.GRY}{f['reference_url']}{C.R}")
                        print(f"    Impacto: {f['demonstrated_impact'][:90]}")
                        print()
                input(f"{C.B}Presione Enter para continuar...{C.R}")

            elif sub_ch == "2":
                # Filtros
                print("\nFiltrar por estado:")
                print(" [1] Solo CONFIRMED_VULNERABILITY")
                print(" [2] Solo VALIDATION_REQUIRED")
                print(" [3] Solo OBSERVATION")
                f_opt = input("Opción: ").strip()
                target_status = None
                if f_opt == "1":
                    target_status = VerificationStatus.CONFIRMED_VULNERABILITY.value
                elif f_opt == "2":
                    target_status = VerificationStatus.VALIDATION_REQUIRED.value
                elif f_opt == "3":
                    target_status = VerificationStatus.OBSERVATION.value

                filtered = [f for f in findings if f['verification_status'] == target_status] if target_status else findings
                print_header(f"HALLAZGOS FILTRADOS ({len(filtered)})")
                for f in filtered:
                    print(f" • [{f['id']}] {f['exposure_type']} en {f['target_asset']}")
                    print(f"   Riesgo: {f['potential_risk'][:90]}")
                    print(f"   Remediación: {f['remediation'][:90]}")
                    print()
                input(f"{C.B}Presione Enter para continuar...{C.R}")

            elif sub_ch == "3":
                # Inspección de evidencias redactadas
                ev_dir = case_path / "evidence"
                if not ev_dir.exists() or not list(ev_dir.iterdir()):
                    print(f"\n{C.YLW}[!] No hay archivos de evidencia adicionales en el expediente.{C.R}")
                else:
                    print_header("ARCHIVOS DE EVIDENCIA REDACTADA")
                    files = list(ev_dir.iterdir())
                    for idx, ef in enumerate(files, 1):
                        print(f" [{idx}] {ef.name} ({ef.stat().st_size} bytes)")
                    try:
                        view_idx = input(f"\n{C.B}Seleccione número para ver contenido (o 0 para volver): {C.R}").strip()
                        if view_idx.isdigit() and 1 <= int(view_idx) <= len(files):
                            selected_file = files[int(view_idx) - 1]
                            print(f"\n{C.CYN}--- CONTENIDO SEGURO DE {selected_file.name} ---{C.R}")
                            content = selected_file.read_text(encoding="utf-8", errors="ignore")
                            print(content[:1500])
                            if len(content) > 1500:
                                print(f"{C.GRY}... [Resto del archivo en disco: {selected_file}] ...{C.R}")
                            print(f"{C.CYN}--- FIN DE CONTENIDO ---{C.R}")
                    except Exception as e:
                        print(f"{C.RED}[!] Error al leer evidencia: {e}{C.R}")
                input(f"\n{C.B}Presione Enter para continuar...{C.R}")

            elif sub_ch == "4":
                # Estado de fuentes
                print_header("ESTADO DE FUENTES CONSULTADAS")
                sources = result.get("sources", [])
                for s in sources:
                    st_color = C.GRN if s['status'] == "SUCCESS" else C.YLW if "NO CONFIGURADO" in s['status'] else C.RED
                    print(f" • {s['name']:<40} [{st_color}{s['status']}{C.R}] Hallazgos: {s['findings_count']}")
                    if s.get('message'):
                        print(f"    └─ {C.GRY}{s['message']}{C.R}")
                input(f"\n{C.B}Presione Enter para continuar...{C.R}")

            elif sub_ch == "5":
                # Visualizar informe TXT
                print_header(f"REPORTE TXT - {report_file.name}")
                if report_file.exists():
                    txt_content = report_file.read_text(encoding="utf-8", errors="ignore")
                    print(f"Ubicación: {report_file}")
                    print(f"Tamaño: {len(txt_content)} caracteres")
                    try:
                        show_all = input("¿Mostrar primeros 50 renglones en consola? (S/n): ").strip().lower()
                        if show_all in ("", "s", "si", "y"):
                            lines = txt_content.splitlines()
                            for l in lines[:50]:
                                print(l)
                            if len(lines) > 50:
                                print(f"\n{C.GRY}... ({len(lines) - 50} renglones adicionales en el archivo {report_file}) ...{C.R}")
                    except Exception:
                        pass
                else:
                    print(f"{C.RED}[!] El archivo de reporte no fue encontrado en {report_file}{C.R}")
                input(f"\n{C.B}Presione Enter para continuar...{C.R}")
