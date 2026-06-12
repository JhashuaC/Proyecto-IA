"""Carga datasets externos de correos para entrenamiento y validación."""

from pathlib import Path
import csv
import json

from phishing_detector.infrastructure.email_parser import parse_eml


class ExternalEmailDataset:
    """Lee corpus públicos guardados localmente en CSV, JSON, JSONL o EML."""

    def __init__(self, root="codigo/data/datasets"):
        self.root = Path(root)

    def load(self):
        if not self.root.exists():
            return []
        rows = []
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix == ".csv":
                rows.extend(self._load_csv(path))
            elif suffix == ".json":
                rows.extend(self._load_json(path))
            elif suffix == ".jsonl":
                rows.extend(self._load_jsonl(path))
            elif suffix == ".eml":
                label = self._label_from_path(path)
                if label is not None:
                    rows.append(self._row_from_eml(path, label))
        return [row for row in rows if row]

    def _load_csv(self, path):
        rows = []
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for item in csv.DictReader(handle):
                row = self._row_from_mapping(item, path)
                if row:
                    rows.append(row)
        return rows

    def _load_json(self, path):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = data.get("rows", [])
        return [row for item in data if (row := self._row_from_mapping(item, path))]

    def _load_jsonl(self, path):
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = self._row_from_mapping(json.loads(line), path)
                if row:
                    rows.append(row)
        return rows

    def _row_from_eml(self, path, label):
        request = parse_eml(path.read_bytes(), path.name)
        return {
            "subject": request.subject,
            "url": request.url,
            "body": request.body,
            "label": label,
            "source": str(path),
        }

    def _row_from_mapping(self, item, path):
        label = self._normalize_label(item.get("label") or item.get("class") or item.get("type") or self._label_from_path(path))
        if label is None:
            return None
        subject = str(item.get("subject") or item.get("asunto") or "")
        body = str(item.get("body") or item.get("text") or item.get("message") or item.get("contenido") or "")
        url = str(item.get("url") or item.get("link") or "")
        if not subject and not body and not url:
            return None
        return {
            "subject": subject,
            "url": url,
            "body": body,
            "label": label,
            "source": str(path),
        }

    def _label_from_path(self, path):
        parts = {part.lower() for part in path.parts}
        if parts & {"phishing", "malicious", "spam", "fraud"}:
            return 1
        if parts & {"legit", "legitimate", "ham", "normal"}:
            return 0
        return None

    def _normalize_label(self, value):
        if value is None:
            return None
        text = str(value).strip().lower()
        if text in {"1", "true", "phishing", "malicious", "spam", "fraud"}:
            return 1
        if text in {"0", "false", "legit", "legitimate", "ham", "normal"}:
            return 0
        return None
