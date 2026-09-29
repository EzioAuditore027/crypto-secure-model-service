"""
Machine Learning Model Service
Implements:
- BuildModel(D) -> M
- RebuildModel(D, D') -> M'
- Query(x) -> y
Uses scikit-learn TfidfVectorizer + LogisticRegression for fast, lightweight inference.
"""
import io
import pickle
import time
from typing import Dict, Any, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from .dataset import Dataset, get_initial_dataset


class MLModel:
    """Wrapper holding trained model pipeline and metadata."""

    def __init__(self, pipeline: Pipeline, version: str = "1.0", created_at: float = None):
        self.pipeline = pipeline
        self.version = version
        self.created_at = created_at or time.time()

    def predict(self, text: str) -> Dict[str, Any]:
        probs = self.pipeline.predict_proba([text])[0]
        # Class 1: Phishing/Spam, Class 0: Legitimate/Ham
        spam_prob = float(probs[1])
        ham_prob = float(probs[0])
        pred_label = "Phishing / Malicious" if spam_prob >= 0.5 else "Legitimate / Clean"

        return {
            "version": self.version,
            "prediction": pred_label,
            "class_id": 1 if spam_prob >= 0.5 else 0,
            "confidence": round(max(spam_prob, ham_prob) * 100, 2),
            "spam_probability": round(spam_prob * 100, 2),
            "timestamp": time.time(),
        }

    def serialize(self) -> bytes:
        return pickle.dumps({
            "pipeline": self.pipeline,
            "version": self.version,
            "created_at": self.created_at,
        })

    @classmethod
    def deserialize(cls, data: bytes) -> "MLModel":
        d = pickle.loads(data)
        return cls(pipeline=d["pipeline"], version=d["version"], created_at=d["created_at"])


class ModelService:
    """Handles BuildModel(D) -> M and RebuildModel(D, D') -> M'."""

    @staticmethod
    def build_model(dataset: Dataset, version: str = "1.0") -> MLModel:
        """
        BuildModel(D) -> M:
        Constructs an initial lightweight NLP model from training dataset D.
        """
        texts, labels = dataset.get_data()
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, stop_words="english")),
            ("clf", LogisticRegression(C=1.0, max_iter=200, solver="lbfgs")),
        ])
        pipeline.fit(texts, labels)
        return MLModel(pipeline=pipeline, version=version)

    @staticmethod
    def rebuild_model(
        initial_dataset: Dataset,
        feedback_samples: List[Dict[str, Any]],
        new_version: str = "1.1",
    ) -> MLModel:
        """
        RebuildModel(D, D') -> M':
        Retrains model using combined original dataset D and newly collected feedback D'.
        """
        augmented = Dataset(initial_dataset._samples)
        for fb in feedback_samples:
            augmented.add_feedback(fb["text"], int(fb["label"]))

        texts, labels = augmented.get_data()
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, stop_words="english")),
            ("clf", LogisticRegression(C=1.0, max_iter=200, solver="lbfgs")),
        ])
        pipeline.fit(texts, labels)
        return MLModel(pipeline=pipeline, version=new_version)
