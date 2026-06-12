"""Caso de uso principal para analizar correos y URLs."""

from phishing_detector.domain.entities import EmailAnalysisRequest
from phishing_detector.domain.policies import RiskScoringPolicy


class AnalyzeEmailUseCase:
    def __init__(self, feature_extractor, neural_model, bayes_model, tree_model, expert_system, metrics):
        self.feature_extractor = feature_extractor
        self.neural_model = neural_model
        self.bayes_model = bayes_model
        self.tree_model = tree_model
        self.expert_system = expert_system
        self.policy = RiskScoringPolicy()
        self.metrics = metrics

    def execute(self, request: EmailAnalysisRequest):
        features = self.feature_extractor.extract(request)
        text = self.feature_extractor.text(request)
        neural_score = self.neural_model.predict_probability(features) * 100
        bayes_score = self.bayes_model.predict_probability(text) * 100
        tree_score = self.tree_model.predict_probability(features) * 100
        expert_score, reasons, indicator_matches, email_summary = self.expert_system.evaluate(request)

        return self.policy.classify(
            neural_score=neural_score,
            bayes_score=bayes_score,
            tree_score=tree_score,
            expert_score=expert_score,
            reasons=reasons,
            indicator_matches=indicator_matches,
            email_summary=email_summary,
            features=features,
            metrics=self.metrics,
        )
