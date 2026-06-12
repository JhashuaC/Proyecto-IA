"""Servidor HTTP local para la interfaz profesional del detector."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
import cgi
import html
import json
import mimetypes

from phishing_detector.domain.entities import EmailAnalysisRequest, SecurityIndicator
from phishing_detector.infrastructure.bootstrap import ApplicationContainer
from phishing_detector.infrastructure.data.analysis_history import JsonAnalysisHistory
from phishing_detector.infrastructure.email_parser import parse_eml
from phishing_detector.infrastructure.reports import create_pdf_report


HOST = "127.0.0.1"
PORT = 8000
WEB_DIR = Path(__file__).parent
TEMPLATE = WEB_DIR / "templates" / "index.html"
STATIC_DIR = WEB_DIR / "static"
SAMPLE_DIR = Path("codigo/data/samples")
REPORT_DIR = Path("codigo/data/reports")

EXAMPLES = {
    "phishing": EmailAnalysisRequest(
        subject="Cuenta bloqueada urgente",
        url="http://seguridad-banco.example.verify-login.ru/acceso",
        body="Urgente: su cuenta será suspendida. Verifique usuario, contraseña y token en menos de 10 minutos.",
    ),
    "legit": EmailAnalysisRequest(
        subject="Aviso de mantenimiento",
        url="https://hosting.example/status",
        body="El servicio tendrá una ventana de mantenimiento programada el sábado de 1 a 3 a.m.",
    ),
}


def result_to_dict(result, report_url=""):
    return {
        "decision": result.decision,
        "level": result.level,
        "final_score": result.final_score,
        "technique_scores": [
            {"name": score.name, "score": score.score, "details": score.details}
            for score in result.technique_scores
        ],
        "reasons": result.reasons,
        "indicator_matches": result.indicator_matches,
        "email_summary": result.email_summary,
        "features": result.features,
        "metrics": result.metrics,
        "is_risky": result.is_risky,
        "report_url": report_url,
    }


def json_for_script(payload):
    return json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_template(container, result=None, values=None, result_payload=None):
    values = values or EmailAnalysisRequest(subject="", body="", url="")
    result_json = "null" if result is None and result_payload is None else json_for_script(result_payload or result_to_dict(result))
    indicators = [
        {
            "name": item.name,
            "pattern": item.pattern,
            "weight": item.weight,
            "category": item.category,
            "enabled": item.enabled,
        }
        for item in container.indicator_repository.list()
    ]
    data = {
        "subject": html.escape(values.subject),
        "url": html.escape(values.url),
        "body": html.escape(values.body),
        "sender": html.escape(values.sender),
        "reply_to": html.escape(values.reply_to),
        "return_path": html.escape(values.return_path),
        "authentication_results": html.escape(values.authentication_results),
        "metrics_json": json_for_script(container.metrics),
        "result_json": result_json,
        "indicators_json": json_for_script(indicators),
        "history_json": json_for_script(container.history.list()),
    }
    template = TEMPLATE.read_text(encoding="utf-8")
    for key, value in data.items():
        template = template.replace("{{ " + key + " }}", value)
    return template


class WebHandler(BaseHTTPRequestHandler):
    container = ApplicationContainer()
    container.history = JsonAnalysisHistory()

    def _send(self, status, body, content_type):
        encoded = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _redirect(self, path):
        self.send_response(303)
        self.send_header("Location", path)
        self.end_headers()

    def _serve_static(self):
        relative = self.path.removeprefix("/static/").split("?", 1)[0]
        target = (STATIC_DIR / relative).resolve()
        if STATIC_DIR.resolve() not in target.parents or not target.exists():
            self._send(404, "Archivo no encontrado", "text/plain; charset=utf-8")
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self._send(200, target.read_bytes(), content_type)

    def do_GET(self):
        if self.path.startswith("/static/"):
            self._serve_static()
            return
        if self.path.startswith("/sample-eml/"):
            self._serve_sample_eml()
            return
        if self.path.startswith("/reports/"):
            self._serve_report()
            return
        if self.path == "/sample/phishing":
            request = EXAMPLES["phishing"]
            result = self.container.analyze_email.execute(request)
            payload = self._record_result(request, result)
            self._send(200, render_template(self.container, result, request, payload), "text/html; charset=utf-8")
            return
        if self.path == "/sample/legit":
            request = EXAMPLES["legit"]
            result = self.container.analyze_email.execute(request)
            payload = self._record_result(request, result)
            self._send(200, render_template(self.container, result, request, payload), "text/html; charset=utf-8")
            return
        self._send(200, render_template(self.container), "text/html; charset=utf-8")

    def _serve_sample_eml(self):
        name = self.path.removeprefix("/sample-eml/").split("?", 1)[0]
        allowed = {
            "phishing-completo": "phishing_completo_banco.eml",
            "phishing-basico": "phishing_demo.eml",
            "legitimo": "legit_demo.eml",
        }
        filename = allowed.get(name)
        if not filename:
            self._send(404, "Ejemplo no encontrado", "text/plain; charset=utf-8")
            return
        target = SAMPLE_DIR / filename
        if not target.exists():
            self._send(404, "Archivo de ejemplo no encontrado", "text/plain; charset=utf-8")
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "message/rfc822")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/indicators":
            self._handle_indicator_create()
            return
        request = self._read_analysis_request()
        result = self.container.analyze_email.execute(request)
        payload = self._record_result(request, result)
        if self.path == "/api/analyze":
            self._send(200, json.dumps(payload, ensure_ascii=False, indent=2), "application/json; charset=utf-8")
        else:
            self._send(200, render_template(self.container, result, request, payload), "text/html; charset=utf-8")

    def _record_result(self, request, result):
        payload = result_to_dict(result)
        report_path = create_pdf_report(request, payload)
        report_url = f"/reports/{report_path.name}"
        payload["report_url"] = report_url
        self.container.history.add(request, payload, report_url)
        return payload

    def _serve_report(self):
        relative = self.path.removeprefix("/reports/").split("?", 1)[0]
        target = (REPORT_DIR / relative).resolve()
        if REPORT_DIR.resolve() not in target.parents or not target.exists() or target.suffix.lower() != ".pdf":
            self._send(404, "Reporte no encontrado", "text/plain; charset=utf-8")
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'inline; filename="{target.name}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_analysis_request(self):
        content_type = self.headers.get("Content-Type", "")
        if content_type.startswith("multipart/form-data"):
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                    "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
                },
            )
            upload = form["eml_file"] if "eml_file" in form else None
            if upload is not None and getattr(upload, "filename", ""):
                raw = upload.file.read()
                request = parse_eml(raw, upload.filename)
                return EmailAnalysisRequest(
                    subject=request.subject or self._field(form, "subject"),
                    url=request.url or self._field(form, "url"),
                    body=request.body or self._field(form, "body"),
                    sender=request.sender or self._field(form, "sender"),
                    reply_to=request.reply_to or self._field(form, "reply_to"),
                    return_path=request.return_path or self._field(form, "return_path"),
                    authentication_results=request.authentication_results or self._field(form, "authentication_results"),
                    headers=request.headers,
                    links=request.links,
                    attachments=request.attachments,
                    source_name=request.source_name,
                )
            return EmailAnalysisRequest(
                subject=self._field(form, "subject"),
                url=self._field(form, "url"),
                body=self._field(form, "body"),
                sender=self._field(form, "sender"),
                reply_to=self._field(form, "reply_to"),
                return_path=self._field(form, "return_path"),
                authentication_results=self._field(form, "authentication_results"),
            )

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        data = {key: values[0] for key, values in parse_qs(raw).items()}
        request = EmailAnalysisRequest(
            subject=data.get("subject", ""),
            url=data.get("url", ""),
            body=data.get("body", ""),
            sender=data.get("sender", ""),
            reply_to=data.get("reply_to", ""),
            return_path=data.get("return_path", ""),
            authentication_results=data.get("authentication_results", ""),
        )
        return request

    def _field(self, form, key):
        if key not in form:
            return ""
        value = form[key]
        if isinstance(value, list):
            value = value[0]
        return value.value if isinstance(value.value, str) else ""

    def _handle_indicator_create(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        data = {key: values[0] for key, values in parse_qs(raw).items()}
        name = data.get("indicator_name", "").strip()
        pattern = data.get("indicator_pattern", "").strip()
        category = data.get("indicator_category", "Personalizado").strip() or "Personalizado"
        try:
            weight = max(1, min(30, int(data.get("indicator_weight", "8"))))
        except ValueError:
            weight = 8
        if name and pattern:
            self.container.indicator_repository.add(SecurityIndicator(name, pattern, weight, category))
        self._redirect("/")


def run(host=HOST, port=PORT):
    server = ThreadingHTTPServer((host, port), WebHandler)
    print(f"Detector iniciado en http://{host}:{port}")
    print("Presione Ctrl+C para detener.")
    server.serve_forever()
