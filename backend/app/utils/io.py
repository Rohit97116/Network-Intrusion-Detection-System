from __future__ import annotations

import re
from io import BytesIO

import pandas as pd

from app.ml.constants import DIFFICULTY_COLUMN, FEATURE_COLUMNS, TARGET_COLUMN


def safe_filename(filename: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", filename or "uploaded.csv").strip("_")
    return cleaned or "uploaded.csv"


def _looks_like_header(columns: pd.Index) -> bool:
    normalized = {str(column).strip().lower() for column in columns}
    expected = set(FEATURE_COLUMNS + [TARGET_COLUMN, DIFFICULTY_COLUMN])
    overlap = len(normalized.intersection(expected))
    return overlap >= 5


def read_csv_bytes(content: bytes) -> pd.DataFrame:
    if not content:
        raise ValueError("Uploaded file is empty.")

    try:
        inferred = pd.read_csv(BytesIO(content), engine="python")
        if _looks_like_header(inferred.columns):
            return inferred
    except Exception:  # noqa: S110
        inferred = None

    try:
        return pd.read_csv(BytesIO(content), header=None, engine="python")
    except Exception as exc:
        raise ValueError(f"Unable to parse CSV file: {exc}") from exc
