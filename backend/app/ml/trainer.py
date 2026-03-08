from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from inspect import signature
from time import perf_counter
from typing import Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import SelectPercentile, f_classif
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from app.ml.constants import CATEGORICAL_COLUMNS, CLASS_NAMES, NUMERIC_COLUMNS
from app.ml.preprocessing import prepare_training_data_with_profile


@dataclass
class TrainedModelOutput:
    best_model_name: str
    best_pipeline: Pipeline
    trained_at: str
    model_comparison: list[dict[str, Any]]
    best_confusion_matrix: list[list[int]]
    class_order: list[str]
    classification_report: dict[str, Any]
    train_test_split_ratio: float
    dataset_profile: str
    label_distribution: dict[str, int]
    threshold_recommendations: dict[str, float]


def _build_preprocessor() -> ColumnTransformer:
    return ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                CATEGORICAL_COLUMNS,
            ),
            ("numeric", StandardScaler(), NUMERIC_COLUMNS),
        ],
        remainder="drop",
    )


def _build_logistic_regression() -> LogisticRegression:
    supported = signature(LogisticRegression.__init__).parameters
    candidate_kwargs = {
        "max_iter": 650,
        "random_state": 42,
        "solver": "saga",
        "class_weight": "balanced",
        "n_jobs": -1,
    }
    kwargs = {
        key: value for key, value in candidate_kwargs.items() if key in supported
    }
    return LogisticRegression(**kwargs)


def _build_models(dataset_profile: str) -> dict[str, Any]:
    if dataset_profile == "cicids2017":
        return {
            "Random Forest": RandomForestClassifier(
                n_estimators=460,
                random_state=42,
                n_jobs=-1,
                class_weight="balanced_subsample",
                max_depth=36,
                min_samples_leaf=1,
            ),
            "Logistic Regression": _build_logistic_regression(),
            "Decision Tree": DecisionTreeClassifier(
                random_state=42,
                class_weight="balanced",
                max_depth=34,
                min_samples_leaf=3,
            ),
        }

    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=320,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced_subsample",
        ),
        "Logistic Regression": _build_logistic_regression(),
        "Decision Tree": DecisionTreeClassifier(
            random_state=42,
            class_weight="balanced",
            max_depth=30,
            min_samples_leaf=2,
        ),
    }


def _to_float_dict(report: dict[str, Any]) -> dict[str, Any]:
    converted: dict[str, Any] = {}
    for key, value in report.items():
        if isinstance(value, dict):
            converted[key] = {
                sub_key: float(sub_value) if isinstance(sub_value, (float, np.floating)) else sub_value
                for sub_key, sub_value in value.items()
            }
        elif isinstance(value, (float, np.floating)):
            converted[key] = float(value)
        else:
            converted[key] = value
    return converted


def _compute_cv_f1(
    pipeline: Pipeline,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    random_state: int,
) -> float:
    min_class_count = int(y_train.value_counts().min())
    n_splits = min(5, max(2, min_class_count))
    if n_splits < 2:
        return 0.0

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    try:
        scores = cross_val_score(
            pipeline,
            X_train,
            y_train,
            cv=cv,
            scoring="f1_macro",
            n_jobs=1,
        )
    except Exception:  # noqa: BLE001
        return 0.0
    return float(np.mean(scores))


def _derive_threshold_recommendations(report: dict[str, Any]) -> dict[str, float]:
    defaults = {
        "global_threshold": 0.62,
        "DoS Attack": 0.6,
        "Probe Attack": 0.68,
        "R2L Attack": 0.74,
        "U2R Attack": 0.78,
    }
    for attack_class in ("DoS Attack", "Probe Attack", "R2L Attack", "U2R Attack"):
        class_metrics = report.get(attack_class, {})
        precision = float(class_metrics.get("precision", 0.0))
        recall = float(class_metrics.get("recall", 0.0))
        threshold = defaults[attack_class]

        # Bias toward stronger precision when class precision is weak.
        if precision < 0.7:
            threshold += 0.08
        elif precision < 0.8:
            threshold += 0.04

        # Avoid suppressing too aggressively on low-recall classes.
        if recall < 0.5:
            threshold -= 0.05
        elif recall < 0.65:
            threshold -= 0.02

        defaults[attack_class] = float(np.clip(threshold, 0.45, 0.92))

    return defaults


def train_and_select_best_model(
    df: pd.DataFrame,
    test_size: float = 0.2,
    random_state: int = 42,
) -> TrainedModelOutput:
    X, y, dataset_profile = prepare_training_data_with_profile(df)
    if len(X) < 200:
        raise ValueError("Training dataset is too small. Provide at least 200 records.")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    models = _build_models(dataset_profile)
    comparison: list[dict[str, Any]] = []
    trained_pipelines: dict[str, Pipeline] = {}
    best_score = -1.0
    best_model_name = ""
    best_confusion_matrix: list[list[int]] = []
    best_report: dict[str, Any] = {}

    for model_name, classifier in models.items():
        percentile = 92 if dataset_profile == "cicids2017" else 85
        pipeline = Pipeline(
            steps=[
                ("preprocessor", _build_preprocessor()),
                ("feature_selector", SelectPercentile(score_func=f_classif, percentile=percentile)),
                ("classifier", classifier),
            ]
        )

        start = perf_counter()
        pipeline.fit(X_train, y_train)
        duration = perf_counter() - start

        cv_f1 = _compute_cv_f1(pipeline, X_train, y_train, random_state)
        predictions = pipeline.predict(X_test)
        metrics = {
            "model_name": model_name,
            "accuracy": float(accuracy_score(y_test, predictions)),
            "balanced_accuracy": float(balanced_accuracy_score(y_test, predictions)),
            "precision_macro": float(
                precision_score(y_test, predictions, average="macro", zero_division=0)
            ),
            "recall_macro": float(
                recall_score(y_test, predictions, average="macro", zero_division=0)
            ),
            "f1_macro": float(f1_score(y_test, predictions, average="macro", zero_division=0)),
            "cv_f1_macro": float(cv_f1),
            "selection_score": float(
                (f1_score(y_test, predictions, average="macro", zero_division=0) * 0.8)
                + (cv_f1 * 0.2)
            ),
            "train_seconds": round(duration, 3),
        }
        comparison.append(metrics)
        trained_pipelines[model_name] = pipeline

        if metrics["selection_score"] > best_score:
            best_score = metrics["selection_score"]
            best_model_name = model_name
            best_confusion_matrix = confusion_matrix(
                y_test, predictions, labels=CLASS_NAMES
            ).tolist()
            best_report = _to_float_dict(
                classification_report(
                    y_test,
                    predictions,
                    labels=CLASS_NAMES,
                    output_dict=True,
                    zero_division=0,
                )
            )

    comparison.sort(key=lambda item: item["selection_score"], reverse=True)
    trained_at = datetime.now(timezone.utc).isoformat()
    label_distribution = {label: int(count) for label, count in y.value_counts().to_dict().items()}
    threshold_recommendations = _derive_threshold_recommendations(best_report)

    return TrainedModelOutput(
        best_model_name=best_model_name,
        best_pipeline=trained_pipelines[best_model_name],
        trained_at=trained_at,
        model_comparison=comparison,
        best_confusion_matrix=best_confusion_matrix,
        class_order=CLASS_NAMES,
        classification_report=best_report,
        train_test_split_ratio=test_size,
        dataset_profile=dataset_profile,
        label_distribution=label_distribution,
        threshold_recommendations=threshold_recommendations,
    )
