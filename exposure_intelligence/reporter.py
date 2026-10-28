# -*- coding: utf-8 -*-
"""
Generador del informe TXT profesional para la empresa / auditoría.
Elabora un reporte detallado en español conforme a los 16 puntos requeridos,
diferenciando hechos de hipótesis y garantizando redacción de datos sensibles.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import AuditScope, Finding, SourceStatus, VerificationStatus, SeverityLevel
from .redactor import SecretRedactor


class ExposureReporter:
    """Generador de informes técnicos y ejecutivos en formato TXT."""

    TOOL_NAME = "AtlasScan (NadieScan Engine)"
    MODULE_NAME = "Módulo de Inteligencia de Exposición y Leaks"

    @classmethod
    def generate_report_txt(
        cls,
        scope: AuditScope,
        findings: List[Finding],
        sources: List[SourceStatus],
        case_path: Path
    ) -> Path:
        """Genera el archivo report.txt en la carpeta del expediente."""

        # Conteo de hallazgos por estado
        obs_count = sum(1 for f in findings if f.verification_status == VerificationStatus.OBSERVATION.value)
        val_count = sum(1 for f in findings if f.verification_status == VerificationStatus.VALIDATION_REQUIRED.value)
        conf_count = sum(1 for f in findings if f.verification_status == VerificationStatus.CONFIRMED_VULNERABILITY.value)

        # Clasificación por severidad
        crit_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICO.value)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.ALTO.value)
        med_count = sum(1 for f in findings if f.severity == SeverityLevel.MEDIO.value)
        low_count = sum(1 for f in findings if f.severity == SeverityLevel.BAJO.value)
        info_count = sum(1 for f in findings if f.severity == SeverityLevel.INFORMATIVO.value)

        lines = []

        def add_banner(title: str):
            lines.append("=" * 80)
            lines.append(f" {title.upper()}")
            lines.append("=" * 80)

        # 1. Nombre de la herramienta y del módulo
        add_banner(f"{cls.TOOL_NAME} — {cls.MODULE_NAME}")
        lines.append(f"Versión de Auditoría:  1.0.0")
        lines.append(f"Normativa de Trabajo:  Auditoría Defensiva Autorizada / OSINT Pasivo / Verificación de Bajo Impacto")
        lines.append("")

        # 2. Identificador del expediente
        lines.append(f"Identificador de Expediente:  {scope.expediente_id}")
        lines.append(f"Ubicación de Archivos:        {case_path}")
        lines.append("")

        # 3. Dominio y alcance autorizado
        add_banner("1. DOMINIO Y ALCANCE AUTORIZADO")
        lines.append(f"Dominio Raíz:             {scope.root_domain}")
        lines.append(f"Estado de Autorización:   {'AUTORIZADO Y CONFIRMADO POR EL OPERADOR' if scope.authorization_confirmed else 'NO CONFIRMADO'}")
        lines.append(f"Política de Transporte:   WARP {scope.warp_policy}")
        lines.append(f"Límite de Solicitudes:    {scope.rate_limit_rps} req/s")
        lines.append("")
        lines.append("Subdominios Autorizados:")
        if scope.authorized_subdomains:
            for sub in scope.authorized_subdomains:
                lines.append(f"  [+] {sub}")
        else:
            lines.append("  [!] Únicamente el dominio raíz autorizado.")
        lines.append("")
        lines.append("Exclusiones Expresas:")
        if scope.excluded_subdomains:
            for exc in scope.excluded_subdomains:
                lines.append(f"  [-] {exc}")
        else:
            lines.append("  (Ninguna exclusión configurada)")
        lines.append("")

        # 4. Fecha y hora de ejecución
        add_banner("2. FECHA Y HORA DE EJECUCIÓN")
        lines.append(f"Fecha/Hora de Inicio:     {scope.timestamp}")
        lines.append(f"Fecha/Hora de Emisión:    {datetime.now().isoformat()}")
        lines.append("")

        # 5. Fuentes consultadas y fuentes no disponibles
        add_banner("3. FUENTES CONSULTADAS Y ESTADO DE DISPONIBILIDAD")
        lines.append(f"{'FUENTE':<32} {'CATEGORÍA':<16} {'ESTADO':<18} {'HALLAZGOS':<10}")
        lines.append("-" * 80)
        for s in sources:
            lines.append(f"{s.name:<32} {s.category:<16} {s.status:<18} {s.findings_count:<10}")
            if s.message:
                lines.append(f"   └─ Detalle: {s.message}")
        lines.append("")

        # 6. Resumen ejecutivo
        add_banner("4. RESUMEN EJECUTIVO")
        if conf_count > 0:
            lines.append(f"Se identificaron {conf_count} exposición(es) clasificada(s) como VULNERABILIDAD CONFIRMADA que")
            lines.append("requieren remediación prioritaria para evitar fugas de información sensible.")
        elif val_count > 0:
            lines.append("No se detectaron exposiciones confirmadas directas, pero se hallaron indicios que")
            lines.append("requieren validación adicional o revisión técnica por parte del equipo responsable.")
        elif obs_count > 0:
            lines.append("Se identificaron observaciones pasivas y referencias públicas que sirven como contexto")
            lines.append("de exposición externa, sin evidenciar acceso directo a datos confidenciales.")
        else:
            lines.append("No se detectaron indicios de archivos sensibles expuestos, bases de datos o configuraciones")
            lines.append("públicas en las fuentes y comprobaciones de bajo impacto efectivamente realizadas.")
            lines.append("Nota: Este resultado no implica ausencia total de vulnerabilidades en otros componentes.")
        lines.append("")

        # 7. Total de observaciones, hallazgos pendientes y vulnerabilidades confirmadas
        add_banner("5. CONTEO Y CLASIFICACIÓN DE HALLAZGOS")
        lines.append(f"Total de Hallazgos Registrados:                {len(findings)}")
        lines.append(f"  • Vulnerabilidades Confirmadas (CONFIRMED):   {conf_count}")
        lines.append(f"  • Pendientes de Validación (VALIDATION_REQ):  {val_count}")
        lines.append(f"  • Observaciones Pasivas (OBSERVATION):        {obs_count}")
        lines.append("")
        lines.append(f"Distribución por Severidad:")
        lines.append(f"  • Crítico:      {crit_count}")
        lines.append(f"  • Alto:         {high_count}")
        lines.append(f"  • Medio:        {med_count}")
        lines.append(f"  • Bajo:         {low_count}")
        lines.append(f"  • Informativo:  {info_count}")
        lines.append("")

        # 8. Sección individual para cada hallazgo
        add_banner("6. DETALLE INDIVIDUAL DE HALLAZGOS")
        if not findings:
            lines.append("No existen hallazgos reportables para el alcance evaluado.")
            lines.append("")
        else:
            for idx, f in enumerate(findings, 1):
                lines.append(f"[{f.id}] {f.exposure_type} — {f.target_asset}")
                lines.append("-" * 74)
                lines.append(f"  • Estado Verificación:  {f.verification_status}")
                lines.append(f"  • Nivel de Severidad:   {f.severity}")
                lines.append(f"  • Fuente:               {f.source}")
                lines.append(f"  • URL de Referencia:    {f.reference_url or 'N/A'}")
                lines.append(f"  • Fecha de Detección:   {f.timestamp}")
                lines.append("")
                lines.append(f"  • Riesgo Potencial:")
                lines.append(f"      {f.potential_risk}")
                lines.append("")
                lines.append(f"  • Impacto Demostrado:")
                lines.append(f"      {f.demonstrated_impact}")
                lines.append("")
                lines.append(f"  • Limitaciones de la Comprobación:")
                lines.append(f"      {f.limitations}")
                lines.append("")
                lines.append(f"  • Evidencia Redactada:")
                safe_ev = SecretRedactor.redact(f.evidence)
                for ev_line in safe_ev.splitlines()[:15]:
                    lines.append(f"      | {ev_line}")
                lines.append("")
                if f.reproduction_steps:
                    lines.append(f"  • Pasos de Reproducción Segura:")
                    lines.append(f"      {f.reproduction_steps}")
                    lines.append("")
                lines.append(f"  • Recomendación de Remediación:")
                lines.append(f"      {f.remediation}")
                lines.append("=" * 74)
                lines.append("")

        # 9. Evidencias y referencias seguras
        add_banner("7. EVIDENCIAS Y REFERENCIAS SEGURAS")
        lines.append("Todas las evidencias han sido redactadas para suprimir contraseñas, claves y datos personales.")
        lines.append(f"Carpeta de evidencias asociadas:  {case_path / 'evidence'}")
        lines.append(f"Carpeta de referencias externas:  {case_path / 'references'}")
        lines.append("")

        # 10. Impacto demostrado y limitaciones
        add_banner("8. IMPACTO DEMOSTRADO VS. HIPÓTESIS")
        lines.append("En estricto cumplimiento ético y defensivo:")
        lines.append("1. Hechos Demostrados: Únicamente los códigos de respuesta, cabeceras y fragmentos")
        lines.append("   de configuración accesibles sin autenticación capturados de forma directa.")
        lines.append("2. Hipótesis / Indicios: Coincidencias en repositorios externos, índices de búsqueda")
        lines.append("   o registros pasivos cuya explotación no ha sido ni debe ser ensayada.")
        lines.append("3. No se realizaron accesos no autorizados, descargas masivas de tablas ni pruebas")
        lines.append("   de credenciales contra servicios en producción.")
        lines.append("")

        # 11. Nivel de riesgo justificado
        add_banner("9. JUSTIFICACIÓN DE NIVELES DE RIESGO")
        lines.append("• CRÍTICO: Archivos de credenciales en producción (.env, .git expuesto) con acceso directo.")
        lines.append("• ALTO:    Backups de bases de datos accesibles (.sql, .dump) o listados de directorios sensibles.")
        lines.append("• MEDIO:   Interfaces de diagnóstico activas (phpinfo, actuator) o patrones de tokens en código.")
        lines.append("• BAJO:    Archivos de configuración con información no sensible o páginas informativas.")
        lines.append("• INFO:    Referencias pasivas OSINT, subdominios en certificados o enlaces de búsqueda.")
        lines.append("")

        # 12. Pasos de reproducción de bajo impacto
        add_banner("10. PAUTAS DE REPRODUCCIÓN DE BAJO IMPACTO")
        lines.append("Para validar los hallazgos sin afectar la disponibilidad del servicio:")
        lines.append("  curl -I -s -A 'SecurityAudit/1.0' '<URL_DEL_HALLAZGO>'")
        lines.append("Verifique el código HTTP devuelto y las cabeceras Content-Type sin descargar el cuerpo completo.")
        lines.append("")

        # 13. Recomendaciones concretas de remediación
        add_banner("11. RECOMENDACIONES GENERALES DE REMEDIACIÓN")
        lines.append("1. Configuración de Servidor Web (Nginx / Apache / IIS):")
        lines.append("   - Denegar explícitamente el acceso a archivos y directorios ocultos (.*).")
        lines.append("   - Desactivar de forma global el listado de directorios (Options -Indexes en Apache,")
        lines.append("     autoindex off en Nginx).")
        lines.append("2. Manejo de Copias de Seguridad y Bases de Datos:")
        lines.append("   - Almacenar los respaldos (.sql, .bak, .zip) fuera de la raíz web pública (document root).")
        lines.append("   - Proteger los directorios de subidas y descargas con autenticación adecuada.")
        lines.append("3. Rotación Inmediata de Secretos:")
        lines.append("   - Si un archivo .env o repositorio público expuso credenciales, revocar y rotar")
        lines.append("     inmediatamente las claves afectadas en el proveedor de nube o servicio.")
        lines.append("4. Control de Versiones:")
        lines.append("   - Incorporar reglas en .gitignore para evitar la inclusión accidental de claves y .env.")
        lines.append("   - Implementar escaneos automáticos de secretos (pre-commit hooks) en CI/CD.")
        lines.append("")

        # 14. Limitaciones de cobertura
        add_banner("12. LIMITACIONES DE COBERTURA")
        lines.append("• Las consultas pasivas reflejan el estado histórico o indexado por terceros y pueden no")
        lines.append("  reflejar cambios recientes en la infraestructura.")
        lines.append("• No se realizan intentos de elusión de WAF, evasión de CAPTCHA ni pruebas intrusivas.")
        lines.append("• Las fuentes de inteligencia con requerimiento de API Key no configurada no aportaron datos.")
        lines.append("")

        # 15. Anexos y ubicación de las evidencias
        add_banner("13. ANEXOS Y ARCHIVOS DEL EXPEDIENTE")
        lines.append(f"  • Reporte técnico consolidado:  {case_path / 'report.txt'}")
        lines.append(f"  • Estructura de hallazgos JSON: {case_path / 'findings.json'}")
        lines.append(f"  • Resumen de fuentes:           {case_path / 'sources.json'}")
        lines.append(f"  • Metadatos y alcance:          {case_path / 'README.txt'}")
        lines.append(f"  • Directorio de evidencias:     {case_path / 'evidence'}")
        lines.append(f"  • Directorio de referencias:    {case_path / 'references'}")
        lines.append("")

        # 16. Aviso de revisión humana obligatoria
        add_banner("14. AVISO DE REVISIÓN HUMANA OBLIGATORIA")
        lines.append("IMPORTANTE:")
        lines.append("Este informe fue generado por un sistema automatizado de asistencia en auditoría defensiva.")
        lines.append("Antes de compartir este documento con la organización o clientes finales, un auditor de")
        lines.append("seguridad calificado DEBE revisar, validar y contextualizar cada uno de los hallazgos.")
        lines.append("=" * 80)

        report_file = case_path / "report.txt"
        report_content = "\n".join(lines)
        report_file.write_text(report_content, encoding="utf-8")
        return report_file
