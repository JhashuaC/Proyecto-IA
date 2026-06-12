"""Sistema experto basado en reglas de ciberseguridad."""

from urllib.parse import urlparse
import re

from phishing_detector.domain.entities import EmailAnalysisRequest

from .feature_extractor import CREDENTIAL_WORDS, MONEY_WORDS, SHORTENERS, SUSPICIOUS_TLDS, URGENCY_WORDS, tokenize


class SecurityExpertSystem:
    def __init__(self, indicator_provider=None):
        self.indicator_provider = indicator_provider or (lambda: [])

    def evaluate(self, request: EmailAnalysisRequest):
        text = f"{request.subject} {request.body} {request.sender} {request.reply_to} {request.authentication_results}".lower()
        tokens = set(tokenize(text))
        parsed = urlparse(request.url if "://" in request.url else ("http://" + request.url if request.url else ""))
        domain = parsed.netloc.lower()
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        score = 0
        reasons = []
        matches = []
        attachment_names = " ".join(item.filename for item in request.attachments)
        auth = request.authentication_results.lower()

        def add(points, reason, category="Regla experta", indicator="Regla interna"):
            nonlocal score
            score += points
            reasons.append(reason)
            matches.append({"name": indicator, "category": category, "weight": points, "evidence": reason})

        if request.url and not request.url.startswith("https://"):
            add(15, "La URL no usa HTTPS.", "URL", "Transporte inseguro")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):
            add(18, "La URL usa una dirección IP en lugar de un dominio legible.", "URL", "IP en URL")
        if any(short in domain for short in SHORTENERS):
            add(12, "El enlace parece usar un acortador o dominio opaco.", "URL", "Acortador")
        if tld in SUSPICIOUS_TLDS:
            add(10, "El dominio usa una terminación común en campañas sospechosas.", "Dominio", "TLD sospechoso")
        if domain.count("-") >= 2 or domain.count(".") >= 3:
            add(10, "El dominio contiene muchos subdominios o guiones.", "Dominio", "Dominio complejo")
        if "xn--" in domain:
            add(18, "El dominio usa punycode, posible homógrafo visual.", "Dominio", "Punycode")
        if tokens & URGENCY_WORDS:
            add(12, "El mensaje presiona con urgencia o vencimiento.", "Ingeniería social", "Urgencia")
        if tokens & CREDENTIAL_WORDS:
            add(14, "Solicita credenciales, inicio de sesión o token.", "Credenciales", "Solicitud de credenciales")
        if tokens & MONEY_WORDS:
            add(10, "Incluye dinero, bancos, pagos, premios o tarjetas.", "Financiero", "Señuelo financiero")
        if re.search(r"\.(exe|scr|bat|cmd|js|vbs|msi|iso|lnk|zip|rar)\b", text + " " + request.url.lower() + " " + attachment_names.lower()):
            add(16, "Menciona adjuntos o rutas potencialmente peligrosas.", "Adjuntos", "Extensión riesgosa")
        for attachment in request.attachments:
            for note in attachment.risk_notes:
                add(8, f"Adjunto '{attachment.filename}': {note}", "Adjuntos", "Análisis interno de adjunto")
            if attachment.has_double_extension:
                add(10, f"El adjunto '{attachment.filename}' usa doble extensión.", "Adjuntos", "Doble extensión")
            if attachment.macro_suspected:
                add(12, f"El adjunto '{attachment.filename}' parece contener macros.", "Adjuntos", "Macros sospechosas")
        if "haga clic" in text or "clic aqui" in text or "clic aquí" in text:
            add(8, "Invita a abrir un enlace sin contexto suficiente.", "Ingeniería social", "Llamado genérico")
        if len(request.links) >= 5:
            add(8, "El correo contiene muchos enlaces.", "URL", "Múltiples enlaces")
        if request.reply_to and request.sender and request.reply_to.split("@")[-1] != request.sender.split("@")[-1]:
            add(16, "El dominio Reply-To no coincide con el dominio From.", "Cabeceras", "Reply-To distinto")
        if request.return_path and request.sender and request.return_path.split("@")[-1] != request.sender.split("@")[-1]:
            add(12, "El Return-Path no coincide con el remitente visible.", "Cabeceras", "Return-Path distinto")
        if "spf=fail" in auth:
            add(18, "SPF falló en Authentication-Results.", "Autenticación", "SPF fail")
        if "dkim=fail" in auth:
            add(18, "DKIM falló en Authentication-Results.", "Autenticación", "DKIM fail")
        if "dmarc=fail" in auth:
            add(20, "DMARC falló en Authentication-Results.", "Autenticación", "DMARC fail")
        if request.attachments and not request.body:
            add(10, "El correo contiene adjuntos pero casi no tiene cuerpo.", "Adjuntos", "Adjunto sin contexto")

        custom_text = f"{text} {request.url.lower()} {' '.join(request.links).lower()} {attachment_names.lower()}"
        for indicator in self.indicator_provider():
            if not indicator.enabled or not indicator.pattern:
                continue
            try:
                if re.search(indicator.pattern, custom_text, re.IGNORECASE):
                    add(indicator.weight, f"Indicador '{indicator.name}' coincide con el correo.", indicator.category, indicator.name)
            except re.error:
                continue

        email_summary = {
            "source_name": request.source_name,
            "sender": request.sender,
            "reply_to": request.reply_to,
            "return_path": request.return_path,
            "link_count": len(request.links) or (1 if request.url else 0),
            "attachment_count": len(request.attachments),
            "attachments": [
                {
                    "filename": item.filename,
                    "content_type": item.content_type,
                    "size": item.size,
                    "sha256": item.sha256,
                    "extension": item.extension,
                    "has_double_extension": item.has_double_extension,
                    "macro_suspected": item.macro_suspected,
                    "risk_notes": item.risk_notes,
                }
                for item in request.attachments
            ],
            "auth_present": bool(request.authentication_results),
            "headers_analyzed": len(request.headers),
        }

        return min(score, 100), reasons, matches, email_summary
