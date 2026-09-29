"""
Machine Learning Model Service Package
Pretrained Lightweight NLP Classifier for Phishing/Spam Detection
Supports BuildModel(D) -> M and RebuildModel(D, D') -> M'
"""
from .dataset import get_initial_dataset, Dataset
from .model import ModelService, MLModel

__all__ = ["get_initial_dataset", "Dataset", "ModelService", "MLModel"]
