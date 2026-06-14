"""Caso de uso principal para analizar correos y URLs."""

from time import perf_counter

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
        feature_details = self.feature_extractor.describe(features)
        text = self.feature_extractor.text(request)
        timings = {}

        start = perf_counter()
        neural_score = self.neural_model.predict_probability(features) * 100
        timings["Red neuronal"] = round((perf_counter() - start) * 1000, 3)

        start = perf_counter()
        bayes_score = self.bayes_model.predict_probability(text) * 100
        timings["Naive Bayes"] = round((perf_counter() - start) * 1000, 3)

        start = perf_counter()
        tree_score = self.tree_model.predict_probability(features) * 100
        timings["Árbol de decisión"] = round((perf_counter() - start) * 1000, 3)

        start = perf_counter()
        expert_score, reasons, indicator_matches, email_summary = self.expert_system.evaluate(request)
        timings["Sistema experto"] = round((perf_counter() - start) * 1000, 3)

        explanations = self._build_explanations(request, features, feature_details, text, {
            "Red neuronal": neural_score,
            "Naive Bayes": bayes_score,
            "Árbol de decisión": tree_score,
            "Sistema experto": expert_score,
        }, timings)

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
            explanations=explanations,
        )

    def _build_explanations(self, request, features, feature_details, text, scores, timings):
        names = self.feature_extractor.feature_names
        neural = self.neural_model.explain(features, names)
        bayes = self.bayes_model.explain(text)
        tree = self.tree_model.explain(features, names)
        expert = self.expert_system.explain(request)
        influential = sorted(feature_details, key=lambda item: item["value"], reverse=True)[:5]
        comparison = []
        summaries = {
            "Red neuronal": "Combina características normalizadas mediante pesos y función sigmoide.",
            "Naive Bayes": "Multiplica probabilidades condicionales de tokens y normaliza por clase.",
            "Árbol de decisión": "Desciende por nodos según umbrales de características.",
            "Sistema experto": "Aplica reglas explícitas de ciberseguridad por encadenamiento hacia adelante.",
        }
        for name, score in scores.items():
            comparison.append({
                "model": name,
                "result": "Phishing" if score >= 50 else "Seguro",
                "confidence": round(score if score >= 50 else 100 - score, 2),
                "score": round(score, 2),
                "time_ms": timings.get(name, 0),
                "influential_variables": [item["name"] for item in influential],
                "summary": summaries[name],
            })
        return {
            "features": feature_details,
            "neural_network": neural,
            "naive_bayes": bayes,
            "decision_tree": tree,
            "expert_system": expert,
            "timings_ms": timings,
            "comparison": comparison,
            "agreement": {
                "phishing_votes": sum(1 for value in scores.values() if value >= 50),
                "safe_votes": sum(1 for value in scores.values() if value < 50),
                "discrepancies": [name for name, value in scores.items() if (value >= 50) != (sum(1 for v in scores.values() if v >= 50) >= 2)],
            },
        }
