"""Historial local de análisis realizados."""

from datetime import datetime
from pathlib import Path
import json


class JsonAnalysisHistory:
    def __init__(self, path="codigo/data/history/analysis_history.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, request, result_payload, report_url=""):
        rows = self.list()
        rows.append({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "subject": request.subject,
            "url": request.url,
            "source_name": request.source_name,
            "decision": result_payload.get("decision", ""),
            "level": result_payload.get("level", ""),
            "final_score": result_payload.get("final_score", 0),
            "report_url": report_url,
        })
        self.path.write_text(json.dumps(rows[-100:], ensure_ascii=False, indent=2), encoding="utf-8")

    def list(self):
        if not self.path.exists():
            return []
        return json.loads(self.path.read_text(encoding="utf-8") or "[]")
