"""Entidades principales del dominio."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AttachmentInfo:
    filename: str
    content_type: str
    size: int = 0
    sha256: str = ""
    extension: str = ""
    has_double_extension: bool = False
    macro_suspected: bool = False
    risk_notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SecurityIndicator:
    name: str
    pattern: str
    weight: int
    category: str = "Personalizado"
    enabled: bool = True


@dataclass(frozen=True)
class EmailAnalysisRequest:
    subject: str
    body: str
    url: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    authentication_results: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    links: list[str] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    source_name: str = "manual"


@dataclass(frozen=True)
class TechniqueScore:
    name: str
    score: float
    details: str


@dataclass(frozen=True)
class AnalysisResult:
    decision: str
    level: str
    final_score: float
    technique_scores: list[TechniqueScore]
    reasons: list[str] = field(default_factory=list)
    indicator_matches: list[dict] = field(default_factory=list)
    email_summary: dict = field(default_factory=dict)
    features: list[float] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    @property
    def is_risky(self):
        return self.level in {"MEDIO", "ALTO"}
