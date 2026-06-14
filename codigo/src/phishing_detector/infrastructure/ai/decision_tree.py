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

    def explain(self, features, feature_names=None):
        feature_names = feature_names or []
        path = []
        visited = set()
        node = self.root
        node_id = "0"
        while node and not node.get("leaf"):
            visited.add(node_id)
            index = node["index"]
            value = features[index]
            threshold = node["threshold"]
            direction = "izquierda" if value < threshold else "derecha"
            passed = value < threshold
            name = feature_names[index] if index < len(feature_names) else f"Característica {index}"
            path.append({
                "node_id": node_id,
                "step": len(path) + 1,
                "feature_index": index,
                "feature": name,
                "value": round(value, 4),
                "threshold": round(threshold, 4),
                "condition": f"{name} < {threshold:.4f}",
                "decision": "Sí" if passed else "No",
                "branch": direction,
                "probability_at_node": round(node.get("probability", 0.5) * 100, 2),
            })
            if passed:
                node = node["left"]
                node_id = f"{node_id}L"
            else:
                node = node["right"]
                node_id = f"{node_id}R"

        if node:
            visited.add(node_id)
        probability = node.get("probability", 0.5) if node else 0.5
        return {
            "path": path,
            "leaf": {
                "node_id": node_id,
                "probability": round(probability * 100, 2),
                "class": "Phishing" if probability >= 0.5 else "Seguro",
            },
            "tree": self._serialize(self.root, feature_names, "0", visited),
        }

    def _serialize(self, node, feature_names, node_id, visited):
        if not node:
            return None
        if node.get("leaf"):
            probability = node.get("probability", 0.5)
            return {
                "id": node_id,
                "leaf": True,
                "visited": node_id in visited,
                "label": "PHISHING" if probability >= 0.5 else "SEGURO",
                "probability": round(probability * 100, 2),
            }
        index = node["index"]
        name = feature_names[index] if index < len(feature_names) else f"Característica {index}"
        return {
            "id": node_id,
            "leaf": False,
            "visited": node_id in visited,
            "feature": name,
            "threshold": round(node["threshold"], 4),
            "probability": round(node.get("probability", 0.5) * 100, 2),
            "left": self._serialize(node["left"], feature_names, f"{node_id}L", visited),
            "right": self._serialize(node["right"], feature_names, f"{node_id}R", visited),
        }

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
