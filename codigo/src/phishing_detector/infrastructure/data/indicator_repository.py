"""Repositorio local de indicadores configurables."""

from pathlib import Path
import json

from phishing_detector.domain.entities import SecurityIndicator


DEFAULT_INDICATORS = [
    SecurityIndicator("Solicitud de credenciales", r"\b(usuario|clave|contrasena|password|token|login)\b", 12, "Credenciales"),
    SecurityIndicator("Urgencia o amenaza", r"\b(urgente|inmediatamente|suspendida|bloqueada|vence|expira|ahora)\b", 10, "Ingenieria social"),
    SecurityIndicator("Datos financieros", r"\b(tarjeta|cvv|cuenta bancaria|transferencia|reembolso|premio)\b", 10, "Financiero"),
    SecurityIndicator("Adjunto ejecutable", r"\.(exe|scr|bat|cmd|js|vbs|msi|iso|lnk)\b", 16, "Adjuntos"),
    SecurityIndicator("Marca suplantada comun", r"\b(paypal|microsoft|apple|google|banco|netflix|dhl|amazon)\b", 8, "Suplantacion"),
]


class JsonIndicatorRepository:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def list(self):
        indicators = list(DEFAULT_INDICATORS)
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8") or "[]")
            for item in data:
                indicators.append(SecurityIndicator(
                    name=str(item.get("name", "Indicador personalizado")),
                    pattern=str(item.get("pattern", "")),
                    weight=int(item.get("weight", 8)),
                    category=str(item.get("category", "Personalizado")),
                    enabled=bool(item.get("enabled", True)),
                ))
        return indicators

    def custom_only(self):
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text(encoding="utf-8") or "[]")

    def add(self, indicator):
        current = self.custom_only()
        current.append({
            "name": indicator.name,
            "pattern": indicator.pattern,
            "weight": indicator.weight,
            "category": indicator.category,
            "enabled": indicator.enabled,
        })
        self.path.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")

