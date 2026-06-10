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

