from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    project_root: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[2]
    )
    model_dir: Path = field(init=False)
    dataset_dir: Path = field(init=False)
    history_db_path: Path = field(init=False)
    exports_dir: Path = field(init=False)
    model_artifact_path: Path = field(init=False)
    model_metadata_path: Path = field(init=False)
    threshold_policy_path: Path = field(init=False)
    allowed_origins: list[str] = field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_dir", self.project_root / "models")
        object.__setattr__(self, "dataset_dir", self.project_root / "datasets")
        object.__setattr__(self, "exports_dir", self.model_dir / "exports")
        object.__setattr__(self, "history_db_path", self.model_dir / "history.sqlite3")
        object.__setattr__(
            self, "model_artifact_path", self.model_dir / "nids_best_model.joblib"
        )
        object.__setattr__(
            self, "model_metadata_path", self.model_dir / "nids_model_metadata.json"
        )
        object.__setattr__(
            self, "threshold_policy_path", self.model_dir / "threshold_policy.json"
        )

        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.dataset_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
