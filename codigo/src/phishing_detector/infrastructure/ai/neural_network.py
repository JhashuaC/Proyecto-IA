"""Red neuronal feedforward binaria implementada sin bibliotecas externas."""

import math
import random


def sigmoid(x):
    if x < -60:
        return 0.0
    if x > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


class ManualNeuralNetwork:
    def __init__(self, input_size, hidden_size=10, learning_rate=0.35, seed=7):
        rnd = random.Random(seed)
        self.learning_rate = learning_rate
        self.w1 = [[rnd.uniform(-0.7, 0.7) for _ in range(input_size)] for _ in range(hidden_size)]
        self.b1 = [rnd.uniform(-0.1, 0.1) for _ in range(hidden_size)]
        self.w2 = [rnd.uniform(-0.7, 0.7) for _ in range(hidden_size)]
        self.b2 = rnd.uniform(-0.1, 0.1)
        self.loss_history = []

    def _forward(self, x):
        hidden = [
            sigmoid(sum(weight * value for weight, value in zip(weights, x)) + bias)
            for weights, bias in zip(self.w1, self.b1)
        ]
        output = sigmoid(sum(weight * value for weight, value in zip(self.w2, hidden)) + self.b2)
        return hidden, output

    def predict_probability(self, x):
        return self._forward(x)[1]

    def explain(self, x, feature_names=None):
        feature_names = feature_names or []
        hidden_raw = [
            sum(weight * value for weight, value in zip(weights, x)) + bias
            for weights, bias in zip(self.w1, self.b1)
        ]
        hidden = [sigmoid(value) for value in hidden_raw]
        output_raw = sum(weight * value for weight, value in zip(self.w2, hidden)) + self.b2
        output = sigmoid(output_raw)
        inputs = [
            {
                "index": index,
                "name": feature_names[index] if index < len(feature_names) else f"Característica {index}",
                "value": round(value, 4),
            }
            for index, value in enumerate(x)
        ]
        neurons = [
            {
                "index": index,
                "weighted_sum": round(hidden_raw[index], 5),
                "activation": round(hidden[index], 5),
                "activation_percent": round(hidden[index] * 100, 2),
                "outgoing_weight": round(self.w2[index], 5),
                "contribution_to_output": round(hidden[index] * self.w2[index], 5),
            }
            for index in range(len(hidden))
        ]
        top_inputs = sorted(inputs, key=lambda item: item["value"], reverse=True)[:6]
        return {
            "activation_function": "sigmoid(x) = 1 / (1 + e^-x)",
            "inputs": inputs,
            "top_inputs": top_inputs,
            "layers": [
                {"name": "Entrada", "count": len(inputs)},
                {"name": "Capa oculta", "count": len(hidden)},
                {"name": "Salida", "count": 1},
            ],
            "hidden_neurons": neurons,
            "output": {
                "weighted_sum": round(output_raw, 5),
                "probability_phishing": round(output * 100, 2),
                "probability_safe": round((1 - output) * 100, 2),
                "predicted_class": "Phishing" if output >= 0.5 else "Seguro",
            },
        }

    def train(self, rows, epochs=900):
        for epoch in range(epochs):
            total_loss = 0.0
            for x, y in rows:
                hidden, output = self._forward(x)
                output = min(max(output, 1e-7), 1 - 1e-7)
                total_loss += -(y * math.log(output) + (1 - y) * math.log(1 - output))
                delta_output = output - y
                old_w2 = self.w2[:]

                for i in range(len(self.w2)):
                    self.w2[i] -= self.learning_rate * delta_output * hidden[i]
                self.b2 -= self.learning_rate * delta_output

                for i, hidden_value in enumerate(hidden):
                    delta_hidden = delta_output * old_w2[i] * hidden_value * (1 - hidden_value)
                    for j in range(len(x)):
                        self.w1[i][j] -= self.learning_rate * delta_hidden * x[j]
                    self.b1[i] -= self.learning_rate * delta_hidden

            if epoch % 100 == 0 or epoch == epochs - 1:
                self.loss_history.append(total_loss / len(rows))

