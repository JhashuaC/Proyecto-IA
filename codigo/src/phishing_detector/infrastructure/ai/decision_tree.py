"""Árbol de decisión binario implementado sin bibliotecas externas."""


class ManualDecisionTree:
    def __init__(self, max_depth=5, min_size=2):
        self.max_depth = max_depth
        self.min_size = min_size
        self.root = None

    def train(self, rows):
        self.root = self._build(rows, depth=0)

    def predict_probability(self, features):
        node = self.root
        while node and not node.get("leaf"):
            if features[node["index"]] < node["threshold"]:
                node = node["left"]
            else:
                node = node["right"]
        return node["probability"] if node else 0.5

    def _build(self, rows, depth):
        labels = [label for _, label in rows]
        probability = sum(labels) / len(labels) if labels else 0.5
        if depth >= self.max_depth or len(rows) <= self.min_size or len(set(labels)) == 1:
            return {"leaf": True, "probability": probability}

        split = self._best_split(rows)
        if split is None:
            return {"leaf": True, "probability": probability}

        left, right = split["left"], split["right"]
        if not left or not right:
            return {"leaf": True, "probability": probability}

        return {
            "leaf": False,
            "index": split["index"],
            "threshold": split["threshold"],
            "probability": probability,
            "left": self._build(left, depth + 1),
            "right": self._build(right, depth + 1),
        }

    def _best_split(self, rows):
        best = None
        best_gini = 1.0
        feature_count = len(rows[0][0])
        for index in range(feature_count):
            thresholds = sorted({features[index] for features, _ in rows})
            for threshold in thresholds:
                left = [row for row in rows if row[0][index] < threshold]
                right = [row for row in rows if row[0][index] >= threshold]
                if not left or not right:
                    continue
                gini = self._weighted_gini(left, right)
                if gini < best_gini:
                    best_gini = gini
                    best = {"index": index, "threshold": threshold, "left": left, "right": right}
        return best

    def _weighted_gini(self, left, right):
        total = len(left) + len(right)
        return (len(left) / total) * self._gini(left) + (len(right) / total) * self._gini(right)

    def _gini(self, rows):
        if not rows:
            return 0.0
        labels = [label for _, label in rows]
        positive = sum(labels) / len(labels)
        negative = 1 - positive
        return 1 - positive**2 - negative**2
