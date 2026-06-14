"""Clasificador Naive Bayes multinomial implementado manualmente."""

import math
from collections import Counter, defaultdict

from .feature_extractor import tokenize


class ManualNaiveBayes:
    def __init__(self):
        self.class_counts = Counter()
        self.word_counts = defaultdict(Counter)
        self.total_words = Counter()
        self.vocabulary = set()

    def train(self, examples):
        for text, label in examples:
            self.class_counts[label] += 1
            for token in tokenize(text):
                self.word_counts[label][token] += 1
                self.total_words[label] += 1
                self.vocabulary.add(token)

    def predict_probability(self, text):
        total_docs = sum(self.class_counts.values())
        vocab_size = max(len(self.vocabulary), 1)
        scores = {}
        for label in [0, 1]:
            prior = (self.class_counts[label] + 1) / (total_docs + 2)
            score = math.log(prior)
            denominator = self.total_words[label] + vocab_size
            for token in tokenize(text):
                count = self.word_counts[label][token] + 1
                score += math.log(count / denominator)
            scores[label] = score

        max_score = max(scores.values())
        legitimate = math.exp(scores[0] - max_score)
        phishing = math.exp(scores[1] - max_score)
        return phishing / (legitimate + phishing)

    def explain(self, text, max_tokens=18):
        tokens = tokenize(text)
        total_docs = sum(self.class_counts.values())
        vocab_size = max(len(self.vocabulary), 1)
        class_names = {0: "Seguro", 1: "Phishing"}
        scores = {}
        priors = {}
        token_rows = []

        for label in [0, 1]:
            prior = (self.class_counts[label] + 1) / (total_docs + 2)
            priors[label] = prior
            score = math.log(prior)
            denominator = self.total_words[label] + vocab_size
            for token in tokens:
                probability = (self.word_counts[label][token] + 1) / denominator
                score += math.log(probability)
            scores[label] = score

        max_score = max(scores.values())
        raw = {label: math.exp(scores[label] - max_score) for label in [0, 1]}
        normalizer = raw[0] + raw[1]
        posteriors = {label: raw[label] / normalizer for label in [0, 1]}

        for token in tokens[:max_tokens]:
            row = {"token": token, "classes": {}}
            for label in [0, 1]:
                denominator = self.total_words[label] + vocab_size
                count = self.word_counts[label][token] + 1
                probability = count / denominator
                row["classes"][class_names[label]] = {
                    "count_with_laplace": count,
                    "denominator": denominator,
                    "conditional_probability": round(probability, 8),
                    "log_probability": round(math.log(probability), 5),
                }
            token_rows.append(row)

        return {
            "formula": "P(clase | evidencia) = P(clase) * Π P(token | clase), normalizado entre clases.",
            "tokens_used": tokens[:max_tokens],
            "token_count": len(tokens),
            "priors": {
                class_names[label]: {
                    "documents": self.class_counts[label],
                    "probability": round(priors[label], 6),
                    "log_probability": round(math.log(priors[label]), 5),
                }
                for label in [0, 1]
            },
            "conditionals": token_rows,
            "log_scores": {class_names[label]: round(scores[label], 5) for label in [0, 1]},
            "raw_scores": {class_names[label]: round(raw[label], 8) for label in [0, 1]},
            "posteriors": {class_names[label]: round(posteriors[label] * 100, 2) for label in [0, 1]},
            "selected_class": class_names[1 if posteriors[1] >= posteriors[0] else 0],
        }

