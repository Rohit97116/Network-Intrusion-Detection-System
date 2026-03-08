from __future__ import annotations

from pydantic import BaseModel, Field


class ModelMetric(BaseModel):
    model_name: str
    accuracy: float
    balanced_accuracy: float | None = None
    precision_macro: float
    recall_macro: float
    f1_macro: float
    cv_f1_macro: float | None = None
    selection_score: float | None = None
    train_seconds: float


class TrainingResponse(BaseModel):
    best_model_name: str
    trained_at: str
    train_test_split_ratio: float
    dataset_profile: str
    model_comparison: list[ModelMetric]
    class_order: list[str]
    confusion_matrix: list[list[int]]
    classification_report: dict[str, dict[str, float] | float]
    label_distribution: dict[str, int]
    threshold_recommendations: dict[str, float]


class AlertItem(BaseModel):
    row_id: int
    predicted_label: str
    confidence: float
    severity: str
    message: str


class TimelinePoint(BaseModel):
    bucket: int
    records: int
    attack_rate: float


class PredictionPreview(BaseModel):
    row_id: int
    protocol_type: str
    service: str
    flag: str
    predicted_label: str
    raw_predicted_label: str | None = None
    confidence: float
    severity: str
    threshold_suppressed: bool | None = None


class DetectionResponse(BaseModel):
    run_id: int
    created_at: str
    source_filename: str
    dataset_profile: str
    total_records: int
    normal_records: int
    attack_records: int
    threshold_suppressed_records: int
    top_attack: str
    avg_confidence: float
    attack_distribution: dict[str, int]
    threshold_policy: dict[str, float]
    timeline: list[TimelinePoint]
    alerts: list[AlertItem]
    preview: list[PredictionPreview]


class HistoryItem(BaseModel):
    id: int
    created_at: str
    source_filename: str
    total_records: int
    normal_records: int
    attack_records: int
    top_attack: str
    avg_confidence: float
    attack_distribution: dict[str, int]
    export_path: str | None = None


class ModelMetadataResponse(BaseModel):
    trained_at: str
    best_model_name: str
    train_test_split_ratio: float
    dataset_profile: str
    model_comparison: list[ModelMetric]
    class_order: list[str]
    confusion_matrix: list[list[int]]
    label_distribution: dict[str, int]
    threshold_recommendations: dict[str, float]


class ThresholdPolicyResponse(BaseModel):
    global_threshold: float = Field(ge=0.0, le=1.0)
    DoS_Attack: float = Field(alias="DoS Attack", ge=0.0, le=1.0)
    Probe_Attack: float = Field(alias="Probe Attack", ge=0.0, le=1.0)
    R2L_Attack: float = Field(alias="R2L Attack", ge=0.0, le=1.0)
    U2R_Attack: float = Field(alias="U2R Attack", ge=0.0, le=1.0)


class ThresholdPolicyUpdate(BaseModel):
    global_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    DoS_Attack: float | None = Field(default=None, alias="DoS Attack", ge=0.0, le=1.0)
    Probe_Attack: float | None = Field(default=None, alias="Probe Attack", ge=0.0, le=1.0)
    R2L_Attack: float | None = Field(default=None, alias="R2L Attack", ge=0.0, le=1.0)
    U2R_Attack: float | None = Field(default=None, alias="U2R Attack", ge=0.0, le=1.0)


class LiveEvent(BaseModel):
    packet_id: int
    timestamp: str
    protocol_type: str
    service: str
    src_ip: str
    dst_ip: str
    predicted_label: str
    confidence: float
    severity: str
    threshold_suppressed: bool = False


class LiveStatusResponse(BaseModel):
    running: bool
    interface: str | None = None
    bpf_filter: str | None = None
    started_at: str | None = None
    total_packets: int = 0
    attack_packets: int = 0
    threshold_suppressed_packets: int = 0
    top_attack: str = "No active attack"
    recent_events: list[LiveEvent] = Field(default_factory=list)


class LiveStartRequest(BaseModel):
    interface: str | None = None
    bpf_filter: str | None = "ip"
