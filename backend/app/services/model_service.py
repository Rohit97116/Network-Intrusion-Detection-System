from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from app.config import Settings
from app.ml.constants import CLASS_NAMES
from app.ml.preprocessing import prepare_inference_data_with_profile
from app.ml.trainer import train_and_select_best_model

DEFAULT_THRESHOLD_POLICY: dict[str, float] = {
    "global_threshold": 0.62,
    "DoS Attack": 0.6,
    "Probe Attack": 0.68,
    "R2L Attack": 0.74,
    "U2R Attack": 0.78,
}


class ModelService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cached_artifact: dict[str, Any] | None = None
        self._threshold_policy = self._load_threshold_policy()

    def is_model_ready(self) -> bool:
        return self.settings.model_artifact_path.exists()

    def _load_threshold_policy(self) -> dict[str, float]:
        if not self.settings.threshold_policy_path.exists():
            return dict(DEFAULT_THRESHOLD_POLICY)
        try:
            payload = json.loads(self.settings.threshold_policy_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return dict(DEFAULT_THRESHOLD_POLICY)
        return self._normalized_threshold_policy(payload)

    @staticmethod
    def _normalized_threshold_policy(payload: dict[str, Any] | None) -> dict[str, float]:
        normalized = dict(DEFAULT_THRESHOLD_POLICY)
        if not payload:
            return normalized

        for key in DEFAULT_THRESHOLD_POLICY:
            if key in payload and payload[key] is not None:
                normalized[key] = float(np.clip(float(payload[key]), 0.0, 1.0))
        return normalized

    def get_threshold_policy(self) -> dict[str, float]:
        return dict(self._threshold_policy)

    def update_threshold_policy(
        self,
        updates: dict[str, Any] | None,
        *,
        persist: bool = True,
    ) -> dict[str, float]:
        normalized = self._normalized_threshold_policy({**self._threshold_policy, **(updates or {})})
        self._threshold_policy = normalized
        if persist:
            self.settings.threshold_policy_path.write_text(
                json.dumps(normalized, indent=2),
                encoding="utf-8",
            )
        return dict(self._threshold_policy)

    def reset_threshold_policy(self) -> dict[str, float]:
        self._threshold_policy = dict(DEFAULT_THRESHOLD_POLICY)
        self.settings.threshold_policy_path.write_text(
            json.dumps(self._threshold_policy, indent=2),
            encoding="utf-8",
        )
        return dict(self._threshold_policy)

    def _autotune_threshold_policy(self, recommendations: dict[str, Any]) -> dict[str, float]:
        if self.settings.threshold_policy_path.exists():
            return self.get_threshold_policy()
        policy = self.update_threshold_policy(recommendations, persist=True)
        return policy

    def train(self, df: pd.DataFrame) -> dict[str, Any]:
        trained = train_and_select_best_model(df)
        artifact = {
            "best_model_name": trained.best_model_name,
            "trained_at": trained.trained_at,
            "pipeline": trained.best_pipeline,
            "class_order": trained.class_order,
            "dataset_profile": trained.dataset_profile,
        }
        joblib.dump(artifact, self.settings.model_artifact_path)
        self._cached_artifact = artifact

        threshold_policy = self._autotune_threshold_policy(trained.threshold_recommendations)
        metadata = {
            "best_model_name": trained.best_model_name,
            "trained_at": trained.trained_at,
            "train_test_split_ratio": trained.train_test_split_ratio,
            "dataset_profile": trained.dataset_profile,
            "model_comparison": trained.model_comparison,
            "class_order": trained.class_order,
            "confusion_matrix": trained.best_confusion_matrix,
            "classification_report": trained.classification_report,
            "label_distribution": trained.label_distribution,
            "threshold_recommendations": trained.threshold_recommendations,
            "threshold_policy": threshold_policy,
        }
        self.settings.model_metadata_path.write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )
        return metadata

    def get_model_metadata(self) -> dict[str, Any]:
        if not self.settings.model_metadata_path.exists():
            raise FileNotFoundError("Model metadata does not exist yet. Train a model first.")
        metadata = json.loads(self.settings.model_metadata_path.read_text(encoding="utf-8"))
        metadata.setdefault("dataset_profile", "nsl_kdd")
        metadata.setdefault("label_distribution", {})
        metadata.setdefault("threshold_recommendations", dict(DEFAULT_THRESHOLD_POLICY))
        metadata.setdefault("threshold_policy", self.get_threshold_policy())
        return metadata

    def _load_artifact(self) -> dict[str, Any]:
        if self._cached_artifact is not None:
            return self._cached_artifact
        if not self.settings.model_artifact_path.exists():
            raise FileNotFoundError("Model artifact is missing. Train a model first.")
        artifact = joblib.load(self.settings.model_artifact_path)
        self._cached_artifact = artifact
        return artifact

    @staticmethod
    def _severity_for(predicted_label: str, confidence: float) -> str:
        if predicted_label == "Normal Traffic":
            return "Info"
        if confidence >= 0.9:
            return "Critical"
        if confidence >= 0.78:
            return "High"
        if confidence >= 0.62:
            return "Medium"
        return "Low"

    @staticmethod
    def _build_timeline(labels: list[str], max_points: int = 20) -> list[dict[str, Any]]:
        if not labels:
            return []
        chunk_size = max(1, math.ceil(len(labels) / max_points))
        timeline = []
        for bucket, start in enumerate(range(0, len(labels), chunk_size), start=1):
            chunk = labels[start : start + chunk_size]
            attacks = sum(label != "Normal Traffic" for label in chunk)
            timeline.append(
                {
                    "bucket": bucket,
                    "records": len(chunk),
                    "attack_rate": round((attacks / len(chunk)) * 100, 2),
                }
            )
        return timeline

    @staticmethod
    def _apply_threshold_policy(
        raw_predictions: np.ndarray,
        confidence: np.ndarray,
        threshold_policy: dict[str, float],
    ) -> tuple[list[str], list[bool]]:
        global_threshold = float(threshold_policy.get("global_threshold", 0.62))
        adjusted_predictions: list[str] = []
        suppressed: list[bool] = []

        for label, conf in zip(raw_predictions, confidence):
            label_text = str(label)
            if label_text == "Normal Traffic":
                adjusted_predictions.append(label_text)
                suppressed.append(False)
                continue

            class_threshold = float(threshold_policy.get(label_text, global_threshold))
            required_threshold = max(global_threshold, class_threshold)
            if float(conf) < required_threshold:
                adjusted_predictions.append("Normal Traffic")
                suppressed.append(True)
            else:
                adjusted_predictions.append(label_text)
                suppressed.append(False)
        return adjusted_predictions, suppressed

    def _score_features(
        self,
        features: pd.DataFrame,
        *,
        threshold_policy: dict[str, float] | None = None,
    ) -> pd.DataFrame:
        artifact = self._load_artifact()
        model = artifact["pipeline"]
        policy = self._normalized_threshold_policy(threshold_policy or self._threshold_policy)

        raw_predictions = model.predict(features)
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(features)
            confidence = probabilities.max(axis=1)
        else:
            confidence = np.full(len(features), 0.75)

        confidence = np.clip(confidence, 0.0, 1.0)
        adjusted_predictions, suppressed = self._apply_threshold_policy(
            raw_predictions,
            confidence,
            policy,
        )
        severity = [
            self._severity_for(predicted_label, float(conf))
            for predicted_label, conf in zip(adjusted_predictions, confidence)
        ]

        return pd.DataFrame(
            {
                "raw_predicted_label": raw_predictions,
                "predicted_label": adjusted_predictions,
                "confidence": np.round(confidence, 4),
                "threshold_suppressed": suppressed,
                "severity": severity,
            }
        )

    def detect(
        self,
        df: pd.DataFrame,
        *,
        source_filename: str,
        max_preview_rows: int = 500,
        threshold_policy: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        features, dataset_profile = prepare_inference_data_with_profile(df)
        effective_policy = self._normalized_threshold_policy(threshold_policy or self._threshold_policy)
        score_frame = self._score_features(features, threshold_policy=effective_policy)

        protocol_values = features["protocol_type"].astype(str).fillna("unknown")
        service_values = features["service"].astype(str).fillna("unknown")
        flag_values = features["flag"].astype(str).fillna("unknown")

        result_frame = pd.DataFrame(
            {
                "row_id": np.arange(1, len(features) + 1),
                "protocol_type": protocol_values,
                "service": service_values,
                "flag": flag_values,
                "raw_predicted_label": score_frame["raw_predicted_label"],
                "predicted_label": score_frame["predicted_label"],
                "confidence": score_frame["confidence"],
                "threshold_suppressed": score_frame["threshold_suppressed"],
                "severity": score_frame["severity"],
            }
        )

        total_records = int(len(result_frame))
        distribution = result_frame["predicted_label"].value_counts().to_dict()
        attack_records = int(
            sum(count for label, count in distribution.items() if label != "Normal Traffic")
        )
        normal_records = int(distribution.get("Normal Traffic", 0))
        non_normal_distribution = {
            label: int(count)
            for label, count in distribution.items()
            if label != "Normal Traffic"
        }
        top_attack = (
            max(non_normal_distribution, key=non_normal_distribution.get)
            if non_normal_distribution
            else "No active attack"
        )
        avg_confidence = float(result_frame["confidence"].mean())
        threshold_suppressed_records = int(result_frame["threshold_suppressed"].sum())

        alert_rows = (
            result_frame[result_frame["predicted_label"] != "Normal Traffic"]
            .sort_values(by="confidence", ascending=False)
            .head(25)
        )
        alerts = [
            {
                "row_id": int(row["row_id"]),
                "predicted_label": str(row["predicted_label"]),
                "confidence": float(row["confidence"]),
                "severity": str(row["severity"]),
                "message": (
                    f"{row['predicted_label']} detected in "
                    f"{row['protocol_type']}/{row['service']} traffic."
                ),
            }
            for _, row in alert_rows.iterrows()
        ]

        preview = (
            result_frame.head(max_preview_rows)
            .replace({np.nan: None})
            .to_dict(orient="records")
        )
        timeline = self._build_timeline(result_frame["predicted_label"].tolist())
        created_at = datetime.now(timezone.utc).isoformat()

        return {
            "created_at": created_at,
            "source_filename": source_filename,
            "dataset_profile": dataset_profile,
            "total_records": total_records,
            "normal_records": normal_records,
            "attack_records": attack_records,
            "threshold_suppressed_records": threshold_suppressed_records,
            "top_attack": top_attack,
            "avg_confidence": round(avg_confidence, 4),
            "attack_distribution": {label: int(distribution.get(label, 0)) for label in CLASS_NAMES},
            "threshold_policy": effective_policy,
            "timeline": timeline,
            "alerts": alerts,
            "preview": preview,
            "result_frame": result_frame,
        }

    def predict_single_feature_row(
        self,
        feature_row: pd.DataFrame,
        *,
        threshold_policy: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        score_frame = self._score_features(feature_row, threshold_policy=threshold_policy)
        row = score_frame.iloc[0]
        return {
            "raw_predicted_label": str(row["raw_predicted_label"]),
            "predicted_label": str(row["predicted_label"]),
            "confidence": float(row["confidence"]),
            "severity": str(row["severity"]),
            "threshold_suppressed": bool(row["threshold_suppressed"]),
        }

    def export_predictions(self, run_id: int, result_frame: pd.DataFrame) -> Path:
        export_path = self.settings.exports_dir / f"detection_run_{run_id}.csv"
        result_frame.to_csv(export_path, index=False)
        return export_path
