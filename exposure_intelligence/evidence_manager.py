# -*- coding: utf-8 -*-
"""
Gestor seguro de expedientes, evidencias y referencias.
Organiza los hallazgos en carpetas independientes, evita sobrescrituras,
previene directory traversal y almacena únicamente evidencias redactadas y de tamaño limitado.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AuditScope, Finding, SourceStatus, ExternalReference
from .redactor import SecretRedactor


class EvidenceManager:
    """Gestiona la estructura de carpetas y persistencia del expediente de auditoría."""

    MAX_EVIDENCE_SIZE_BYTES = 64 * 1024  # Máximo 64 KB por archivo de evidencia para evitar descarga masiva

    def __init__(self, base_results_dir: Optional[Path] = None):
        if base_results_dir is None:
            # results/exposure_audits/ relativo a la raíz del proyecto
            self.base_dir = Path(__file__).resolve().parent.parent / "results" / "exposure_audits"
        else:
            self.base_dir = Path(base_results_dir)

    @staticmethod
    def sanitize_filename(name: str) -> str:
        """Sanitiza nombres de archivo previniendo directory traversal y caracteres inválidos."""
        clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name)
        # Evitar referencias a carpetas padre '..'
        clean = re.sub(r"\.{2,}", ".", clean)
        return clean.strip("._ ") or "archivo"

    def create_case_folder(self, root_domain: str, custom_id: Optional[str] = None) -> Tuple[Path, str]:
        """
        Crea una carpeta de expediente única, evitando sobrescribir expedientes previos.
        Devuelve (ruta_carpeta, id_expediente).
        """
        safe_domain = self.sanitize_filename(root_domain)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        if custom_id:
            safe_id = self.sanitize_filename(custom_id)
            case_id = f"{safe_id}_{ts}"
        else:
            case_id = f"EXP_{safe_domain}_{ts}"

        case_path = self.base_dir / case_id

        # Si por alguna razón colisiona, añadir sufijo numérico
        counter = 1
        original_case_id = case_id
        while case_path.exists():
            case_id = f"{original_case_id}_{counter}"
            case_path = self.base_dir / case_id
            counter += 1

        # Crear estructura de subdirectorios
        try:
            case_path.mkdir(parents=True, exist_ok=False)
            (case_path / "evidence").mkdir(exist_ok=True)
            (case_path / "references").mkdir(exist_ok=True)
        except Exception as e:
            raise IOError(f"No se pudo crear la carpeta de expediente en {case_path}: {e}")

        return case_path, case_id

    def save_readme(self, case_path: Path, scope: AuditScope) -> bool:
        """Escribe el archivo README.txt con el alcance y metadatos de autorización."""
        lines = [
            "=" * 74,
            "ATLASSCAN — EXPEDIENTE DE AUDITORÍA DE EXPOSICIÓN Y LEAKS",
            "=" * 74,
            f"ID de Expediente:      {scope.expediente_id}",
            f"Dominio Raíz:          {scope.root_domain}",
            f"Fecha y Hora:          {scope.timestamp}",
            f"Autorización Activo:   {'AUTORIZADO Y CONFIRMADO' if scope.authorization_confirmed else 'NO CONFIRMADO'}",
            f"Política de WARP:      {scope.warp_policy}",
            f"Límite de Peticiones:  {scope.rate_limit_rps} req/seg",
            "",
            "--- ALCANCE AUTORIZADO ---",
            "Subdominios incluidos:",
        ]
        if scope.authorized_subdomains:
            for s in scope.authorized_subdomains:
                lines.append(f"  • {s}")
        else:
            lines.append("  (Solo dominio raíz)")

        lines.append("\nExclusiones expresas:")
        if scope.excluded_subdomains:
            for s in scope.excluded_subdomains:
                lines.append(f"  • {s}")
        else:
            lines.append("  (Ninguna exclusión configurada)")

        lines.append("\nFuentes habilitadas:")
        for src in scope.enabled_sources:
            lines.append(f"  • {src}")

        if scope.notes:
            lines.append(f"\nNotas del auditor: {scope.notes}")

        lines.append("\n" + "=" * 74)
        lines.append("AVISO LEGAL Y DE PRIVACIDAD:")
        lines.append("Este expediente contiene evidencias redactadas de una evaluación de seguridad")
        lines.append("autorizada. Todo contenido sensible, secretos y contraseñas han sido enmascarados.")
        lines.append("=" * 74)

        try:
            (case_path / "README.txt").write_text("\n".join(lines), encoding="utf-8")
            return True
        except Exception as e:
            print(f"[!] Error al escribir README.txt en {case_path}: {e}")
            return False

    def save_evidence_snippet(self, case_path: Path, finding_id: str, snippet: str, extension: str = "txt") -> Optional[str]:
        """
        Guarda un fragmento de evidencia estrictamente redactado, respetando el límite de tamaño.
        Devuelve el nombre relativo del archivo guardado o None si falló.
        """
        if not snippet:
            return None

        # Redactar inmediatamente antes de persistir
        safe_content = SecretRedactor.redact(snippet)

        # Truncar si excede el tamaño máximo permitido
        safe_bytes = safe_content.encode("utf-8", errors="ignore")
        if len(safe_bytes) > self.MAX_EVIDENCE_SIZE_BYTES:
            safe_content = safe_bytes[:self.MAX_EVIDENCE_SIZE_BYTES].decode("utf-8", errors="ignore")
            safe_content += "\n\n... [CONTENIDO TRUNCADO POR POLÍTICA DE SEGURIDAD: LÍMITE DE TAMAÑO ALCANZADO] ..."

        safe_finding_id = self.sanitize_filename(finding_id)
        filename = f"ev_{safe_finding_id}.{self.sanitize_filename(extension)}"
        target_path = case_path / "evidence" / filename

        # Prevenir traversal
        try:
            resolved = target_path.resolve()
            if not str(resolved).startswith(str((case_path / "evidence").resolve())):
                raise ValueError("Intento de path traversal detectado.")
            resolved.write_text(safe_content, encoding="utf-8")
            return f"evidence/{filename}"
        except Exception as e:
            print(f"[!] Error al guardar evidencia {filename}: {e}")
            return None

    def save_references(self, case_path: Path, references: List[ExternalReference]) -> bool:
        """Guarda referencias externas y dominios de terceros encontrados sin escanear."""
        try:
            data = [r.to_dict() for r in references]
            ref_file = case_path / "references" / "external_references.json"
            ref_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            return True
        except Exception as e:
            print(f"[!] Error al guardar external_references.json: {e}")
            return False

    def save_sources(self, case_path: Path, sources: List[SourceStatus]) -> bool:
        """Guarda el estado y resultado de cada una de las fuentes consultadas."""
        try:
            data = [s.to_dict() for s in sources]
            src_file = case_path / "sources.json"
            src_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            return True
        except Exception as e:
            print(f"[!] Error al guardar sources.json: {e}")
            return False

    def save_findings_json(self, case_path: Path, findings: List[Finding]) -> bool:
        """Guarda los hallazgos estructurados en findings.json asegurando redacción."""
        try:
            data = []
            for f in findings:
                f_dict = f.to_dict()
                # Doble pasada de redacción sobre evidencia
                f_dict["evidence"] = SecretRedactor.redact(f_dict.get("evidence", ""))
                data.append(f_dict)
            findings_file = case_path / "findings.json"
            findings_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            return True
        except Exception as e:
            print(f"[!] Error al guardar findings.json: {e}")
            return False
