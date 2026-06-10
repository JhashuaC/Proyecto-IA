"""Construccion de dependencias de la aplicacion."""

from phishing_detector.application.analyze_email import AnalyzeEmailUseCase
from phishing_detector.domain.entities import EmailAnalysisRequest
from phishing_detector.infrastructure.ai.expert_system import SecurityExpertSystem
from phishing_detector.infrastructure.ai.feature_extractor import SecurityFeatureExtractor
from phishing_detector.infrastructure.ai.naive_bayes import ManualNaiveBayes
from phishing_detector.infrastructure.ai.neural_network import ManualNeuralNetwork
from phishing_detector.infrastructure.data.indicator_repository import JsonIndicatorRepository
from phishing_detector.infrastructure.data.simulated_dataset import SimulatedPhishingDataset


class ApplicationContainer:
    def __init__(self):
        self.indicator_repository = JsonIndicatorRepository("codigo/data/custom_indicators.json")
        self.dataset = SimulatedPhishingDataset().load()
        self.feature_extractor = SecurityFeatureExtractor()
        feature_rows = []
        text_rows = []

        for item in self.dataset:
            request = EmailAnalysisRequest(
                subject=item["subject"],
                body=item["body"],
                url=item["url"],
            )
            feature_rows.append((self.feature_extractor.extract(request), item["label"]))
            text_rows.append((self.feature_extractor.text(request), item["label"]))

        self.neural_model = ManualNeuralNetwork(input_size=len(feature_rows[0][0]))
        self.neural_model.train(feature_rows)
        self.bayes_model = ManualNaiveBayes()
        self.bayes_model.train(text_rows)
        self.expert_system = SecurityExpertSystem(self.indicator_repository.list)
        self.metrics = self._evaluate(feature_rows, text_rows)
        self.analyze_email = AnalyzeEmailUseCase(
            feature_extractor=self.feature_extractor,
            neural_model=self.neural_model,
            bayes_model=self.bayes_model,
            expert_system=self.expert_system,
            metrics=self.metrics,
        )

    def _evaluate(self, feature_rows, text_rows):
        correct = tp = tn = fp = fn = 0
        for (features, label), (text, _) in zip(feature_rows, text_rows):
            neural = self.neural_model.predict_probability(features)
            bayes = self.bayes_model.predict_probability(text)
            prediction = 1 if (0.62 * neural + 0.38 * bayes) >= 0.5 else 0
            correct += prediction == label
            tp += prediction == 1 and label == 1
            tn += prediction == 0 and label == 0
            fp += prediction == 1 and label == 0
            fn += prediction == 0 and label == 1

        return {
            "accuracy": round(correct / len(feature_rows) * 100, 2),
            "total": len(feature_rows),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "loss": [round(value, 4) for value in self.neural_model.loss_history],
        }
