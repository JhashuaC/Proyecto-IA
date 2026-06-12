"""Generación de reportes PDF básicos sin dependencias externas."""

from datetime import datetime
from pathlib import Path
import re


def create_pdf_report(request, result_payload, output_dir="codigo/data/reports"):
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.pdf"
    path = target_dir / filename
    lines = _report_lines(request, result_payload)
    _write_simple_pdf(path, lines)
    return path


def _report_lines(request, result):
    techniques = result.get("technique_scores", [])
    reasons = result.get("reasons", [])
    summary = result.get("email_summary", {})
    attachments = summary.get("attachments", [])
    lines = [
        "SentinelMail AI - Reporte de análisis",
        f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Decisión: {result.get('decision', '')}",
        f"Nivel: {result.get('level', '')}",
        f"Riesgo final: {result.get('final_score', 0)}%",
        f"Asunto: {request.subject or 'No indicado'}",
        f"URL: {request.url or 'No indicada'}",
        f"Origen: {summary.get('source_name', request.source_name)}",
        "",
        "Técnicas:",
    ]
    lines.extend(f"- {item['name']}: {item['score']}%" for item in techniques)
    lines.append("")
    lines.append("Señales encontradas:")
    lines.extend(f"- {reason}" for reason in reasons[:14])
    lines.append("")
    lines.append("Adjuntos:")
    if attachments:
        for item in attachments[:8]:
            digest = item.get("sha256", "")
            notes = ", ".join(item.get("risk_notes", [])) or "Sin señales internas"
            lines.append(f"- {item.get('filename')} ({item.get('content_type')}): {notes}")
            if digest:
                lines.append(f"  SHA-256: {digest}")
    else:
        lines.append("- No se detectaron adjuntos.")
    return _wrap_lines(lines)


def _wrap_lines(lines, width=92):
    wrapped = []
    for line in lines:
        current = line
        while len(current) > width:
            split_at = current.rfind(" ", 0, width)
            if split_at <= 0:
                split_at = width
            wrapped.append(current[:split_at])
            current = "  " + current[split_at:].strip()
        wrapped.append(current)
    return wrapped[:48]


def _pdf_text(value):
    replacements = {
        "á": "a", "é": "e", "í": "i", "ó": "o", "ú": "u",
        "Á": "A", "É": "E", "Í": "I", "Ó": "O", "Ú": "U",
        "ñ": "n", "Ñ": "N", "ü": "u", "Ü": "U",
    }
    for source, target in replacements.items():
        value = value.replace(source, target)
    return re.sub(r"[^\x20-\x7e]", "?", value)


def _write_simple_pdf(path, lines):
    text_commands = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
    for index, line in enumerate(lines):
        safe = _pdf_text(line).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if index == 0:
            text_commands.append(f"({safe}) Tj")
        else:
            text_commands.append(f"T* ({safe}) Tj")
    text_commands.append("ET")
    stream = "\n".join(text_commands).encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]

    content = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(content))
        content.extend(f"{number} 0 obj\n".encode("ascii"))
        content.extend(obj)
        content.extend(b"\nendobj\n")
    xref = len(content)
    content.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets:
        content.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    content.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    path.write_bytes(content)
