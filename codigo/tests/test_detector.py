"""Pruebas de humo para el detector."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_detector.domain.entities import EmailAnalysisRequest
from phishing_detector.infrastructure.email_parser import parse_eml
from phishing_detector.infrastructure.bootstrap import ApplicationContainer


class DetectorSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.container = ApplicationContainer()

    def test_phishing_example_is_high_risk(self):
        result = self.container.analyze_email.execute(EmailAnalysisRequest(
            subject="Cuenta bloqueada urgente",
            url="http://seguridad-banco.example.verify-login.ru/acceso",
            body="Urgente: su cuenta será suspendida. Verifique usuario, contraseña y token.",
        ))
        self.assertEqual(result.level, "ALTO")

    def test_legitimate_example_is_low_risk(self):
        result = self.container.analyze_email.execute(EmailAnalysisRequest(
            subject="Aviso de mantenimiento",
            url="https://hosting.example/status",
            body="El servicio tendrá una ventana de mantenimiento programada el sábado.",
        ))
        self.assertEqual(result.level, "BAJO")

    def test_eml_upload_content_is_parsed(self):
        eml_path = ROOT / "data" / "samples" / "phishing_demo.eml"
        request = parse_eml(eml_path.read_bytes(), eml_path.name)
        result = self.container.analyze_email.execute(request)
        self.assertEqual(result.level, "ALTO")
        self.assertGreaterEqual(result.email_summary["attachment_count"], 1)
        self.assertTrue(result.email_summary["auth_present"])


if __name__ == "__main__":
    unittest.main()
