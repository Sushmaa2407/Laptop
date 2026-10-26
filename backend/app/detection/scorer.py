"""Loads the ONNX anomaly model and turns flow features into a 0..1 score (higher = more anomalous).

The model manifest (JSON next to the .onnx file) holds the feature order, the log transform,
and the calibration constants written by ml/scripts/train_model.py. ADR-004: read the ONNX
output by NAME ('scores'), never by position.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import numpy as np
import onnxruntime as ort


class OnnxScorer:
    def __init__(self, onnx_path: str | Path, meta_path: str | Path) -> None:
        self.meta = json.loads(Path(meta_path).read_text())
        self.features: list[str] = self.meta["features"]
        self.model_version: str = self.meta["model_version"]
        self.threshold: float = float(self.meta["threshold"])
        cal = self.meta["calibration"]
        self._t, self._k = float(cal["t"]), float(cal["k"])
        self._log = self.meta.get("transform") == "log1p"
        self._session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
        self._input = self._session.get_inputs()[0].name

    def score_records(self, records: Sequence[Mapping[str, float]]) -> list[float]:
        if not records:
            return []
        x = np.asarray([[float(r[name]) for name in self.features] for r in records], dtype=np.float64)
        if self._log:
            x = np.log1p(np.maximum(x, 0.0))
        decision = np.asarray(self._session.run(["scores"], {self._input: x.astype(np.float32)})[0]).ravel()
        scores = 1.0 / (1.0 + np.exp(np.clip(self._k * (decision - self._t), -60, 60)))
        return [float(min(1.0, max(0.0, s))) for s in scores]
