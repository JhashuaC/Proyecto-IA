"""Extraccion manual de caracteristicas de correos y URLs."""

from html.parser import HTMLParser
from urllib.parse import urlparse
import re

from phishing_detector.domain.entities import EmailAnalysisRequest


SUSPICIOUS_WORDS = {
    "urgente", "suspendida", "bloqueada", "bloqueo", "verifique", "validar",
    "confirmar", "contrasena", "contraseña", "password", "token", "tarjeta", "premio",
    "gratis", "vence", "obligatoria", "reembolso", "bancaria", "expire",
    "identidad", "seguridad", "multa", "desbloquear",
}
URGENCY_WORDS = {"urgente", "inmediatamente", "hoy", "vence", "expira", "ahora", "obligatoria"}
CREDENTIAL_WORDS = {"usuario", "clave", "contrasena", "contraseña", "password", "token", "sesion", "sesión", "login"}
MONEY_WORDS = {"tarjeta", "banco", "bancaria", "pago", "reembolso", "premio", "transferencia", "fondos"}
SUSPICIOUS_TLDS = {"top", "biz", "ru", "info", "co"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "tiny.example"}

FEATURE_NAMES = [
    "URL usa HTTPS",
    "Longitud de URL",
    "Cantidad de puntos en URL",
    "Cantidad de guiones en URL",
    "Dominio es dirección IP",
    "TLD sospechoso",
    "URL contiene @",
    "Dígitos en URL",
    "Cantidad de enlaces",
    "Palabras de urgencia",
    "Palabras de credenciales",
    "Palabras financieras",
    "Acortador de URL",
    "Formulario HTML",
    "Extensión riesgosa",
    "Densidad de palabras sospechosas",
    "Cantidad de adjuntos",
    "Reply-To distinto",
    "Return-Path distinto",
    "Fallo SPF/DKIM/DMARC",
    "Enlaces extraídos del EML",
    "Dominio punycode",
    "Señales internas de adjuntos",
]


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag.lower() == "form":
            self.forms += 1


def tokenize(text):
    return re.findall(r"[a-zA-Z0-9áéíóúüñÁÉÍÓÚÜÑ]+", text.lower())


def extract_url(text):
    match = re.search(r"https?://[^\s<>\"]+", text)
    return match.group(0).strip(".,);]") if match else ""


def domain_from_url(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed.netloc.lower()


def has_ip(domain):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]))


def safe_ratio(value, divisor, cap=1.0):
    if divisor <= 0:
        return 0.0
    return min(value / divisor, cap)


class SecurityFeatureExtractor:
    feature_names = FEATURE_NAMES

    def extract(self, request: EmailAnalysisRequest):
        text = f"{request.subject} {request.body} {request.sender} {request.reply_to} {request.authentication_results}"
        found_url = request.url or extract_url(text)
        domain = domain_from_url(found_url) if found_url else ""
        tokens = tokenize(text)
        token_count = max(len(tokens), 1)
        parser = LinkParser()
        parser.feed(request.body or "")
        link_count = len(set(parser.links + request.links + ([found_url] if found_url else [])))
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        attachment_names = " ".join(item.filename for item in request.attachments)
        risky_attachment_signals = sum(
            1 for item in request.attachments
            if item.risk_notes or item.has_double_extension or item.macro_suspected
        )
        auth = request.authentication_results.lower()

        return [
            1.0 if found_url.startswith("https://") else 0.0,
            safe_ratio(len(found_url), 120),
            safe_ratio(found_url.count("."), 8),
            safe_ratio(found_url.count("-"), 6),
            1.0 if has_ip(domain) else 0.0,
            1.0 if tld in SUSPICIOUS_TLDS else 0.0,
            1.0 if "@" in found_url else 0.0,
            safe_ratio(sum(ch.isdigit() for ch in found_url), 20),
            safe_ratio(link_count, 8),
            safe_ratio(sum(1 for t in tokens if t in URGENCY_WORDS), 6),
            safe_ratio(sum(1 for t in tokens if t in CREDENTIAL_WORDS), 6),
            safe_ratio(sum(1 for t in tokens if t in MONEY_WORDS), 6),
            1.0 if any(short in domain for short in SHORTENERS) else 0.0,
            1.0 if parser.forms > 0 else 0.0,
            1.0 if re.search(r"\.(exe|scr|bat|zip|rar|js|vbs|lnk|iso)\b", (text + " " + attachment_names).lower()) else 0.0,
            safe_ratio(sum(1 for t in tokens if t in SUSPICIOUS_WORDS), token_count, 0.6),
            safe_ratio(len(request.attachments), 5),
            1.0 if request.reply_to and request.sender and request.reply_to.split("@")[-1] != request.sender.split("@")[-1] else 0.0,
            1.0 if request.return_path and request.sender and request.return_path.split("@")[-1] != request.sender.split("@")[-1] else 0.0,
            1.0 if "spf=fail" in auth or "dkim=fail" in auth or "dmarc=fail" in auth else 0.0,
            safe_ratio(len(request.links), 12),
            1.0 if "xn--" in domain else 0.0,
            safe_ratio(risky_attachment_signals, 5),
        ]

    def text(self, request: EmailAnalysisRequest):
        attachment_names = " ".join(item.filename for item in request.attachments)
        return " ".join(tokenize(f"{request.subject} {request.body} {request.url} {request.sender} {request.reply_to} {attachment_names}"))

    def describe(self, features):
        return [
            {"index": index, "name": name, "value": round(features[index], 4)}
            for index, name in enumerate(self.feature_names[:len(features)])
        ]
