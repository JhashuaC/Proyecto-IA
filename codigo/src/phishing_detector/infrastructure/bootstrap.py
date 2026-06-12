"""Construcción de dependencias de la aplicación."""

import random

from phishing_detector.application.analyze_email import AnalyzeEmailUseCase
from phishing_detector.domain.entities import EmailAnalysisRequest
from phishing_detector.infrastructure.ai.decision_tree import ManualDecisionTree
from phishing_detector.infrastructure.ai.expert_system import SecurityExpertSystem
from phishing_detector.infrastructure.ai.feature_extractor import SecurityFeatureExtractor
from phishing_detector.infrastructure.ai.naive_bayes import ManualNaiveBayes
from phishing_detector.infrastructure.ai.neural_network import ManualNeuralNetwork
from phishing_detector.infrastructure.data.external_dataset import ExternalEmailDataset
from phishing_detector.infrastructure.data.indicator_repository import JsonIndicatorRepository
from phishing_detector.infrastructure.data.simulated_dataset import SimulatedPhishingDataset


class ApplicationContainer:
    def __init__(self):
        self.indicator_repository = JsonIndicatorRepository("codigo/data/custom_indicators.json")
        simulated_rows = SimulatedPhishingDataset().load()
        external_rows = ExternalEmailDataset().load()
        self.dataset = simulated_rows + external_rows
        self.feature_extractor = SecurityFeatureExtractor()
        feature_rows, text_rows = self._prepare_rows(self.dataset)
        train_features, test_features, train_texts, test_texts = self._train_test_split(feature_rows, text_rows)

        self.neural_model = ManualNeuralNetwork(input_size=len(train_features[0][0]))
        self.neural_model.train(train_features)
        self.bayes_model = ManualNaiveBayes()
        self.bayes_model.train(train_texts)
        self.tree_model = ManualDecisionTree()
        self.tree_model.train(train_features)
        self.expert_system = SecurityExpertSystem(self.indicator_repository.list)
        self.metrics = self._evaluate(train_features, train_texts, test_features, test_texts, len(simulated_rows), len(external_rows))
        self.analyze_email = AnalyzeEmailUseCase(
            feature_extractor=self.feature_extractor,
            neural_model=self.neural_model,
            bayes_model=self.bayes_model,
            tree_model=self.tree_model,
            expert_system=self.expert_system,
            metrics=self.metrics,
        )

    def _prepare_rows(self, dataset):
        feature_rows = []
        text_rows = []
        for item in dataset:
            request = EmailAnalysisRequest(
                subject=item["subject"],
                body=item["body"],
                url=item["url"],
            )
            feature_rows.append((self.feature_extractor.extract(request), item["label"]))
            text_rows.append((self.feature_extractor.text(request), item["label"]))
        return feature_rows, text_rows

    def _train_test_split(self, feature_rows, text_rows, test_ratio=0.25, seed=11):
        paired = list(zip(feature_rows, text_rows))
        random.Random(seed).shuffle(paired)
        test_size = max(2, int(len(paired) * test_ratio))
        test_rows = paired[:test_size]
        train_rows = paired[test_size:] or paired
        train_features = [feature for feature, _ in train_rows]
        train_texts = [text for _, text in train_rows]
        test_features = [feature for feature, _ in test_rows]
        test_texts = [text for _, text in test_rows]
        return train_features, test_features, train_texts, test_texts

    def _evaluate(self, train_features, train_texts, test_features, test_texts, simulated_count, external_count):
        train_metrics = self._evaluate_rows(train_features, train_texts)
        test_metrics = self._evaluate_rows(test_features, test_texts)
        return {
            "accuracy": test_metrics["accuracy"],
            "test_accuracy": test_metrics["accuracy"],
            "train_accuracy": train_metrics["accuracy"],
            "total": len(train_features) + len(test_features),
            "train_total": len(train_features),
            "test_total": len(test_features),
            "simulated_examples": simulated_count,
            "external_examples": external_count,
            "tp": test_metrics["tp"],
            "tn": test_metrics["tn"],
            "fp": test_metrics["fp"],
            "fn": test_metrics["fn"],
            "loss": [round(value, 4) for value in self.neural_model.loss_history],
        }

    def _evaluate_rows(self, feature_rows, text_rows):
        correct = tp = tn = fp = fn = 0
        for (features, label), (text, _) in zip(feature_rows, text_rows):
            neural = self.neural_model.predict_probability(features)
            bayes = self.bayes_model.predict_probability(text)
            tree = self.tree_model.predict_probability(features)
            prediction = 1 if (0.46 * neural + 0.32 * bayes + 0.22 * tree) >= 0.5 else 0
            correct += prediction == label
            tp += prediction == 1 and label == 1
            tn += prediction == 0 and label == 0
            fp += prediction == 1 and label == 0
            fn += prediction == 0 and label == 1

        return {
            "accuracy": round(correct / len(feature_rows) * 100, 2),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        }
