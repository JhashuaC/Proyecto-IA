"""Puertos que la aplicacion necesita para analizar phishing."""

from abc import ABC, abstractmethod

from .entities import EmailAnalysisRequest


class FeatureExtractorPort(ABC):
    @abstractmethod
    def extract(self, request: EmailAnalysisRequest) -> list[float]:
        raise NotImplementedError

    @abstractmethod
    def text(self, request: EmailAnalysisRequest) -> str:
        raise NotImplementedError


class RiskModelPort(ABC):
    @abstractmethod
    def train(self, examples):
        raise NotImplementedError

    @abstractmethod
    def predict_probability(self, value) -> float:
        raise NotImplementedError


class ExpertSystemPort(ABC):
    @abstractmethod
    def evaluate(self, request: EmailAnalysisRequest) -> tuple[float, list[str]]:
        raise NotImplementedError


class DatasetPort(ABC):
    @abstractmethod
    def load(self) -> list[dict]:
        raise NotImplementedError

