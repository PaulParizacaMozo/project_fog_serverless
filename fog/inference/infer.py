from __future__ import annotations

import json
import hashlib
import logging
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


logger = logging.getLogger("fog.inference")


class SpecError(RuntimeError):
    pass


class InferenceError(RuntimeError):
    pass


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _safe_float(x: Any) -> Optional[float]:
    if x is None:
        return None
    if isinstance(x, (int, float, np.number)):
        return float(x)
    if isinstance(x, str):
        s = x.strip()
        if s == "":
            return None
        try:
            return float(s)
        except ValueError:
            return None
    return None


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise SpecError(f"Failed to read preprocess spec JSON at {path}: {e}") from e


def _extract_features_obj(payload: Dict[str, Any], features_field: str, accept_flat: bool) -> Dict[str, Any]:
    """
    Accepts either:
      - payload[features_field] as dict
      - or payload itself (flat) if accept_flat_payload=true
    """
    if features_field in payload and isinstance(payload[features_field], dict):
        return payload[features_field]
    if accept_flat:
        return payload
    raise InferenceError(
        f"Payload does not contain features field '{features_field}' and flat payload is disabled."
    )


@dataclass(frozen=True)
class InferenceResult:
    ok: bool
    label: Optional[str]
    is_abnormal: Optional[bool]
    score: Optional[float]
    threshold: Optional[float]
    model: str
    model_sha256: str
    spec_version: str
    feature_hash: Optional[str]
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "label": self.label,
            "is_abnormal": self.is_abnormal,
            "score": self.score,
            "threshold": self.threshold,
            "model": self.model,
            "model_sha256": self.model_sha256,
            "spec_version": self.spec_version,
            "feature_hash": self.feature_hash,
            "errors": self.errors,
        }


class InferenceEngine:
    """
    Loads:
      - preprocess_spec.json (schema + min/max + feature order)
      - random_forest_binary.pkl (sklearn model)

    Then provides:
      - predict(payload: dict) -> InferenceResult
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        spec_path: Optional[Path] = None,
        model_name: str = "random_forest_binary.pkl",
    ) -> None:
        base_dir = Path(__file__).resolve().parents[1]  # fog/
        self._models_dir = base_dir / "models"
        self._inference_dir = base_dir / "inference"

        self.model_path = model_path or (self._models_dir / model_name)
        self.spec_path = spec_path or (self._inference_dir / "preprocess_spec.json")
        self.model_name = self.model_path.name

        self.spec = _load_json(self.spec_path)
        self._validate_spec(self.spec)

        self.spec_version = str(self.spec.get("spec_version", "unknown"))

        # Input settings
        inp = self.spec.get("input", {})
        self.features_field = str(inp.get("features_field", "features"))
        self.accept_flat = bool(inp.get("accept_flat_payload", True))

        # Feature schema
        self.feature_order: List[str] = list(self.spec["feature_order"])
        self.defaults: Dict[str, Any] = dict(self.spec.get("defaults", {}))

        # Scaling settings
        scaler = self.spec.get("scaler", {})
        self.scaler_type = str(scaler.get("type", "none")).lower()
        self.scaler_strict = bool(scaler.get("strict", True))
        self.scaler_min = dict(scaler.get("min", {}))
        self.scaler_max = dict(scaler.get("max", {}))

        clip = scaler.get("clip", {}) if isinstance(scaler, dict) else {}
        self.clip_enabled = bool(clip.get("enabled", False))
        self.clip_min = float(clip.get("min", 0.0)) if self.clip_enabled else 0.0
        self.clip_max = float(clip.get("max", 1.0)) if self.clip_enabled else 1.0

        # Labels/thresholding
        self.label_map: Dict[str, str] = dict(self.spec.get("label_map", {}))
        self.positive_label = str(self.spec.get("positive_label", "abnormal"))
        self.threshold = float(self.spec.get("threshold", 0.5))

        telemetry = self.spec.get("telemetry", {})
        self.include_feature_hash = bool(telemetry.get("include_feature_hash", True))
        self.include_feature_vector = bool(telemetry.get("include_feature_vector", False))

        # Load model
        self.model, self.model_sha256 = self._load_model(self.model_path)

        # Precompute probability column index for "abnormal" (if predict_proba exists)
        self._positive_class_index = self._resolve_positive_class_index()

        logger.info(
            "InferenceEngine initialized: model=%s spec=%s features=%d scaler=%s",
            self.model_path,
            self.spec_path,
            len(self.feature_order),
            self.scaler_type,
        )

    def _validate_spec(self, spec: Dict[str, Any]) -> None:
        required = ["feature_order", "label_map"]
        for k in required:
            if k not in spec:
                raise SpecError(f"preprocess_spec.json missing required key: '{k}'")

        fo = spec.get("feature_order")
        if not isinstance(fo, list) or not all(isinstance(x, str) for x in fo) or len(fo) == 0:
            raise SpecError("spec.feature_order must be a non-empty list of strings")

        lm = spec.get("label_map")
        if not isinstance(lm, dict) or len(lm) == 0:
            raise SpecError("spec.label_map must be a non-empty object mapping class ids to label names")

        scaler = spec.get("scaler", {})
        if scaler:
            stype = str(scaler.get("type", "none")).lower()
            if stype not in ("none", "minmax"):
                raise SpecError(f"Unsupported scaler.type: {stype}. Allowed: none|minmax")

    def _load_model(self, model_path: Path) -> Tuple[Any, str]:
        if not model_path.exists():
            raise InferenceError(f"Model PKL not found at: {model_path}")

        b = model_path.read_bytes()
        sha = _sha256_bytes(b)

        try:
            model = pickle.loads(b)
        except Exception as e:
            raise InferenceError(f"Failed to unpickle model at {model_path}: {e}") from e

        return model, sha

    def _resolve_positive_class_index(self) -> Optional[int]:
        """
        If model supports predict_proba, it will have classes_. We map that to your label_map
        to find which proba column corresponds to positive_label (e.g., 'abnormal').
        """
        if not hasattr(self.model, "predict_proba"):
            return None

        classes = getattr(self.model, "classes_", None)
        if classes is None:
            return None

        # Convert each class to string key to match label_map keys ("0","1",...)
        # Example: classes=[0,1] -> keys "0","1"
        for idx, c in enumerate(list(classes)):
            key = str(int(c)) if isinstance(c, (int, np.integer)) else str(c)
            mapped = self.label_map.get(key)
            if mapped == self.positive_label:
                return idx

        # If we cannot find it, return None and we will degrade to predict() based decisions.
        logger.warning(
            "Could not resolve positive class index for positive_label='%s' using label_map + model.classes_. "
            "Will degrade scoring behavior.",
            self.positive_label,
        )
        return None

    def _vectorize(self, payload: Dict[str, Any]) -> Tuple[np.ndarray, List[str], List[str]]:
        """
        Returns:
          X: shape (1, n_features)
          used_features: list of features in order
          errors: list of per-feature parsing errors
        """
        errors: List[str] = []
        feat_obj = _extract_features_obj(payload, self.features_field, self.accept_flat)

        row: List[float] = []
        for f in self.feature_order:
            raw = feat_obj.get(f, None)
            val = _safe_float(raw)

            if val is None:
                # fallback to defaults if present
                if f in self.defaults:
                    dv = _safe_float(self.defaults.get(f))
                    if dv is None:
                        errors.append(f"Feature '{f}' missing/non-numeric and default is not numeric.")
                        dv = 0.0
                    val = dv
                else:
                    errors.append(f"Feature '{f}' missing/non-numeric and no default provided.")
                    val = 0.0

            row.append(float(val))

        X = np.array(row, dtype=np.float32).reshape(1, -1)
        return X, list(self.feature_order), errors

    def _apply_minmax(self, X: np.ndarray) -> Tuple[np.ndarray, List[str]]:
        errors: List[str] = []
        if self.scaler_type == "none":
            return X, errors

        if self.scaler_type != "minmax":
            raise SpecError(f"Unsupported scaler_type at runtime: {self.scaler_type}")

        Xs = X.astype(np.float32, copy=True)
        for j, f in enumerate(self.feature_order):
            mn = self.scaler_min.get(f, None)
            mx = self.scaler_max.get(f, None)

            if mn is None or mx is None:
                msg = f"Scaler min/max missing for feature '{f}'"
                if self.scaler_strict:
                    raise SpecError(msg)
                errors.append(msg)
                continue

            mn_f = _safe_float(mn)
            mx_f = _safe_float(mx)
            if mn_f is None or mx_f is None:
                msg = f"Scaler min/max not numeric for feature '{f}'"
                if self.scaler_strict:
                    raise SpecError(msg)
                errors.append(msg)
                continue

            denom = (mx_f - mn_f)
            if denom == 0.0:
                # Constant feature in training set; map to 0.0 by convention
                Xs[0, j] = 0.0
                continue

            Xs[0, j] = (Xs[0, j] - mn_f) / denom

        if self.clip_enabled:
            Xs = np.clip(Xs, self.clip_min, self.clip_max)

        return Xs, errors

    def _feature_hash(self, X: np.ndarray) -> str:
        # stable hash of the numeric vector for trace/debug (not storing raw features)
        b = X.astype(np.float32).tobytes()
        return hashlib.sha256(b).hexdigest()

    def predict(self, payload: Dict[str, Any]) -> InferenceResult:
        """
        Main public method. Never raises for typical feature issues; returns ok=false with errors.
        Raises only for truly broken configuration (missing model/spec).
        """
        errors: List[str] = []

        try:
            X, used, vec_errors = self._vectorize(payload)
            errors.extend(vec_errors)

            Xs, sc_errors = self._apply_minmax(X)
            errors.extend(sc_errors)

            # Score + decision
            score: Optional[float] = None
            label: Optional[str] = None
            is_abnormal: Optional[bool] = None

            if hasattr(self.model, "predict_proba") and self._positive_class_index is not None:
                proba = self.model.predict_proba(Xs)  # shape (1,2)
                score = float(proba[0, self._positive_class_index])
                is_abnormal = bool(score >= self.threshold)
                label = self.positive_label if is_abnormal else self._other_label()
            else:
                # degrade: use predict() only
                pred = self.model.predict(Xs)
                # pred could be [0] or [1] or strings depending on training
                cls = pred[0]
                key = str(int(cls)) if isinstance(cls, (int, np.integer)) else str(cls)
                label = self.label_map.get(key, None)
                if label is None:
                    errors.append(f"Predicted class '{key}' not found in label_map.")
                is_abnormal = (label == self.positive_label) if label is not None else None

            feature_hash = self._feature_hash(Xs) if self.include_feature_hash else None

            ok = True if (label is not None and is_abnormal is not None) else False
            if not ok and len(errors) == 0:
                errors.append("Inference returned incomplete result (label/is_abnormal missing).")

            return InferenceResult(
                ok=ok,
                label=label,
                is_abnormal=is_abnormal,
                score=score,
                threshold=self.threshold,
                model=self.model_name,
                model_sha256=self.model_sha256,
                spec_version=self.spec_version,
                feature_hash=feature_hash,
                errors=errors,
            )

        except Exception as e:
            # Do not hide hard failures; return ok=false so pipeline can decide fallback route.
            errors.append(f"Exception during inference: {type(e).__name__}: {e}")
            return InferenceResult(
                ok=False,
                label=None,
                is_abnormal=None,
                score=None,
                threshold=self.threshold,
                model=self.model_name,
                model_sha256=self.model_sha256,
                spec_version=self.spec_version,
                feature_hash=None,
                errors=errors,
            )

    def _other_label(self) -> str:
        # best-effort: pick any label different from positive_label
        for _, v in self.label_map.items():
            if v != self.positive_label:
                return v
        return "normal"


def predict_event(payload: Dict[str, Any], engine: InferenceEngine) -> Dict[str, Any]:
    """
    Convenience wrapper for pipeline usage.
    """
    return engine.predict(payload).to_dict()

