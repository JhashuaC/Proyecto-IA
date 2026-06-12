"""Políticas del dominio para combinar puntajes."""

from .entities import AnalysisResult, TechniqueScore


class RiskScoringPolicy:
    def __init__(self, neural_weight=0.36, bayes_weight=0.24, tree_weight=0.18, expert_weight=0.22):
        self.neural_weight = neural_weight
        self.bayes_weight = bayes_weight
        self.tree_weight = tree_weight
        self.expert_weight = expert_weight

    def classify(self, neural_score, bayes_score, tree_score, expert_score, reasons, indicator_matches, email_summary, features, metrics):
        final_score = (
            self.neural_weight * neural_score
            + self.bayes_weight * bayes_score
            + self.tree_weight * tree_score
            + self.expert_weight * expert_score
        )
        if final_score >= 70:
            level = "ALTO"
            decision = "Probable phishing"
        elif final_score >= 40:
            level = "MEDIO"
            decision = "Sospechoso"
        else:
            level = "BAJO"
            decision = "Probablemente legítimo"

        return AnalysisResult(
            decision=decision,
            level=level,
            final_score=round(final_score, 2),
            technique_scores=[
                TechniqueScore("Red neuronal", round(neural_score, 2), "Clasificación numérica por características."),
                TechniqueScore("Naive Bayes", round(bayes_score, 2), "Probabilidad textual basada en tokens."),
                TechniqueScore("Árbol de decisión", round(tree_score, 2), "Clasificación por divisiones de características."),
                TechniqueScore("Sistema experto", round(expert_score, 2), "Reglas de ciberseguridad activadas."),
            ],
            reasons=reasons or ["No se activaron reglas críticas de phishing."],
            indicator_matches=indicator_matches,
            email_summary=email_summary,
            features=[round(value, 3) for value in features],
            metrics=metrics,
        )
