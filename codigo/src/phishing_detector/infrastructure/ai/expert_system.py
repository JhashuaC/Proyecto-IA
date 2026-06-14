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

    def explain(self, request: EmailAnalysisRequest):
        text = f"{request.subject} {request.body} {request.sender} {request.reply_to} {request.authentication_results}".lower()
        tokens = set(tokenize(text))
        parsed = urlparse(request.url if "://" in request.url else ("http://" + request.url if request.url else ""))
        domain = parsed.netloc.lower()
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        attachment_names = " ".join(item.filename for item in request.attachments)
        auth = request.authentication_results.lower()
        custom_text = f"{text} {request.url.lower()} {' '.join(request.links).lower()} {attachment_names.lower()}"

        rules = [
            ("Transporte inseguro", "SI la URL no usa HTTPS ENTONCES aumentar riesgo.", bool(request.url and not request.url.startswith("https://")), "La URL inicia con http://." if request.url and not request.url.startswith("https://") else "No hay URL o la URL usa HTTPS.", 15),
            ("IP en URL", "SI el dominio es una IP ENTONCES aumentar riesgo.", bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain)), f"Dominio evaluado: {domain or 'vacío'}.", 18),
            ("Acortador", "SI el dominio usa acortador ENTONCES aumentar riesgo.", any(short in domain for short in SHORTENERS), f"Dominio evaluado: {domain or 'vacío'}.", 12),
            ("TLD sospechoso", "SI el TLD está en la lista sospechosa ENTONCES aumentar riesgo.", tld in SUSPICIOUS_TLDS, f"TLD evaluado: {tld or 'sin TLD'}.", 10),
            ("Dominio complejo", "SI hay muchos subdominios o guiones ENTONCES aumentar riesgo.", domain.count("-") >= 2 or domain.count(".") >= 3, f"Puntos: {domain.count('.')}, guiones: {domain.count('-')}.", 10),
            ("Punycode", "SI el dominio contiene xn-- ENTONCES posible homógrafo.", "xn--" in domain, f"Dominio evaluado: {domain or 'vacío'}.", 18),
            ("Urgencia", "SI aparecen palabras de urgencia ENTONCES aumentar riesgo.", bool(tokens & URGENCY_WORDS), f"Coincidencias: {', '.join(sorted(tokens & URGENCY_WORDS)) or 'ninguna'}.", 12),
            ("Solicitud de credenciales", "SI solicita usuario, contraseña o token ENTONCES aumentar riesgo.", bool(tokens & CREDENTIAL_WORDS), f"Coincidencias: {', '.join(sorted(tokens & CREDENTIAL_WORDS)) or 'ninguna'}.", 14),
            ("Señuelo financiero", "SI menciona bancos, pagos, premios o tarjetas ENTONCES aumentar riesgo.", bool(tokens & MONEY_WORDS), f"Coincidencias: {', '.join(sorted(tokens & MONEY_WORDS)) or 'ninguna'}.", 10),
            ("Extensión riesgosa", "SI menciona adjuntos ejecutables o comprimidos ENTONCES aumentar riesgo.", bool(re.search(r"\.(exe|scr|bat|cmd|js|vbs|msi|iso|lnk|zip|rar)\b", text + " " + request.url.lower() + " " + attachment_names.lower())), f"Adjuntos: {attachment_names or 'ninguno'}.", 16),
            ("Llamado genérico", "SI invita a hacer clic sin contexto ENTONCES aumentar riesgo.", "haga clic" in text or "clic aqui" in text or "clic aquí" in text, "Se revisaron frases de llamado genérico.", 8),
            ("Múltiples enlaces", "SI contiene muchos enlaces ENTONCES aumentar riesgo.", len(request.links) >= 5, f"Enlaces detectados: {len(request.links)}.", 8),
            ("Reply-To distinto", "SI Reply-To no coincide con From ENTONCES aumentar riesgo.", bool(request.reply_to and request.sender and request.reply_to.split("@")[-1] != request.sender.split("@")[-1]), f"From: {request.sender or 'vacío'}, Reply-To: {request.reply_to or 'vacío'}.", 16),
            ("Return-Path distinto", "SI Return-Path no coincide con From ENTONCES aumentar riesgo.", bool(request.return_path and request.sender and request.return_path.split("@")[-1] != request.sender.split("@")[-1]), f"From: {request.sender or 'vacío'}, Return-Path: {request.return_path or 'vacío'}.", 12),
            ("SPF fail", "SI SPF falla ENTONCES aumentar riesgo.", "spf=fail" in auth, "Se revisó Authentication-Results.", 18),
            ("DKIM fail", "SI DKIM falla ENTONCES aumentar riesgo.", "dkim=fail" in auth, "Se revisó Authentication-Results.", 18),
            ("DMARC fail", "SI DMARC falla ENTONCES aumentar riesgo.", "dmarc=fail" in auth, "Se revisó Authentication-Results.", 20),
            ("Adjunto sin contexto", "SI hay adjuntos y casi no hay cuerpo ENTONCES aumentar riesgo.", bool(request.attachments and not request.body), f"Adjuntos: {len(request.attachments)}, cuerpo vacío: {not bool(request.body)}.", 10),
        ]

        evaluated = []
        timeline = []
        running_score = 0
        for index, (name, statement, active, evidence, weight) in enumerate(rules, start=1):
            if active:
                running_score += weight
            state = "Activada" if active else "Descartada"
            reason = "Se cumplieron las condiciones." if active else f"No se cumplieron las condiciones. {evidence}"
            item = {
                "id": index,
                "name": name,
                "rule": statement,
                "state": state,
                "active": active,
                "weight": weight,
                "evidence": evidence,
                "discard_reason": "" if active else reason,
                "partial_score": min(running_score, 100),
            }
            evaluated.append(item)
            timeline.append(f"Regla {index}: {name} -> {state}. Puntaje parcial: {min(running_score, 100)}.")

        for indicator in self.indicator_provider():
            if not indicator.enabled or not indicator.pattern:
                continue
            try:
                active = bool(re.search(indicator.pattern, custom_text, re.IGNORECASE))
            except re.error:
                active = False
            if active:
                running_score += indicator.weight
            evaluated.append({
                "id": len(evaluated) + 1,
                "name": indicator.name,
                "rule": f"SI coincide el patrón personalizado '{indicator.pattern}' ENTONCES aumentar riesgo.",
                "state": "Activada" if active else "Descartada",
                "active": active,
                "weight": indicator.weight,
                "evidence": "Patrón encontrado en texto, URL, enlaces o adjuntos." if active else "El patrón no apareció en la evidencia analizada.",
                "discard_reason": "" if active else "No hubo coincidencia con el patrón personalizado.",
                "partial_score": min(running_score, 100),
            })

        return {
            "inference_type": "Encadenamiento hacia adelante",
            "facts": {
                "domain": domain,
                "tld": tld,
                "tokens": sorted(tokens)[:40],
                "attachments": [item.filename for item in request.attachments],
                "links": request.links,
            },
            "rules": evaluated,
            "timeline": timeline,
            "intermediate_conclusions": [
                item["name"] for item in evaluated if item["active"]
            ],
            "final_score": min(running_score, 100),
            "final_class": "Phishing" if min(running_score, 100) >= 50 else "Seguro o bajo riesgo",
            "textual_explanation": "El motor revisó cada regla contra los hechos extraídos del correo y acumuló peso solo cuando la condición fue verdadera.",
        }
