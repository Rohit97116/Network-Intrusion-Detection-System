from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.config import get_settings
from app.schemas import (
    DetectionResponse,
    HistoryItem,
    LiveStartRequest,
    LiveStatusResponse,
    ModelMetadataResponse,
    ThresholdPolicyUpdate,
    TrainingResponse,
)
from app.services.live_monitor import LiveMonitorService
from app.services.model_service import ModelService
from app.utils.history_store import HistoryStore
from app.utils.io import read_csv_bytes, safe_filename
from app.utils.logger import get_logger

settings = get_settings()
logger = get_logger("nids.api")
history_store = HistoryStore(settings.history_db_path)
model_service = ModelService(settings)
live_monitor = LiveMonitorService(model_service=model_service, logger=logger)

app = FastAPI(
    title="Network Intrusion Detection System API",
    version="1.0.0",
    description="Professional ML-based NIDS backend with training, detection, history, and export.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "message": "NIDS backend is running",
        "docs": "/docs",
    }


@app.get("/api/health")
def health() -> dict[str, str | bool]:
    return {
        "status": "ok",
        "model_ready": model_service.is_model_ready(),
        "live_monitor_running": live_monitor.status()["running"],
    }


async def _read_upload(file: UploadFile) -> tuple[str, object]:
    filename = safe_filename(file.filename or "uploaded.csv")
    content = await file.read()
    try:
        frame = read_csv_bytes(content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return filename, frame


@app.post("/api/train", response_model=TrainingResponse)
async def train_model(file: UploadFile = File(...)) -> TrainingResponse:
    filename, frame = await _read_upload(file)
    logger.info("Training requested for %s with %s rows", filename, len(frame))
    try:
        metadata = model_service.train(frame)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Training failed")
        raise HTTPException(status_code=500, detail=f"Training failed: {exc}") from exc
    return TrainingResponse(**metadata)


@app.post("/api/retrain", response_model=TrainingResponse)
async def retrain_model(file: UploadFile = File(...)) -> TrainingResponse:
    return await train_model(file)


@app.get("/api/model/metrics", response_model=ModelMetadataResponse)
def get_model_metrics() -> ModelMetadataResponse:
    try:
        metadata = model_service.get_model_metadata()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ModelMetadataResponse(**metadata)


@app.post("/api/detect", response_model=DetectionResponse)
async def detect_intrusions(
    file: UploadFile = File(...),
    max_preview_rows: int = Form(default=500),
    global_threshold: float | None = Form(default=None),
    dos_threshold: float | None = Form(default=None),
    probe_threshold: float | None = Form(default=None),
    r2l_threshold: float | None = Form(default=None),
    u2r_threshold: float | None = Form(default=None),
) -> DetectionResponse:
    if not model_service.is_model_ready():
        raise HTTPException(status_code=404, detail="Model not found. Train a model first.")

    filename, frame = await _read_upload(file)
    safe_preview_size = max(50, min(int(max_preview_rows), 3000))
    logger.info(
        "Detection requested for %s with %s rows (preview=%s)",
        filename,
        len(frame),
        safe_preview_size,
    )
    threshold_override = {
        "global_threshold": global_threshold,
        "DoS Attack": dos_threshold,
        "Probe Attack": probe_threshold,
        "R2L Attack": r2l_threshold,
        "U2R Attack": u2r_threshold,
    }
    threshold_override = {key: value for key, value in threshold_override.items() if value is not None}

    try:
        detection_output = model_service.detect(
            frame,
            source_filename=filename,
            max_preview_rows=safe_preview_size,
            threshold_policy=threshold_override or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Detection failed")
        raise HTTPException(status_code=500, detail=f"Detection failed: {exc}") from exc

    run_id = history_store.create_run(
        created_at=detection_output["created_at"],
        source_filename=detection_output["source_filename"],
        total_records=detection_output["total_records"],
        normal_records=detection_output["normal_records"],
        attack_records=detection_output["attack_records"],
        top_attack=detection_output["top_attack"],
        avg_confidence=detection_output["avg_confidence"],
        attack_distribution=detection_output["attack_distribution"],
    )

    export_path = model_service.export_predictions(run_id, detection_output["result_frame"])
    history_store.update_export_path(run_id, str(export_path))

    response_payload = {key: value for key, value in detection_output.items() if key != "result_frame"}
    response_payload["run_id"] = run_id
    return DetectionResponse(**response_payload)


@app.get("/api/history", response_model=list[HistoryItem])
def get_detection_history(limit: int = 100) -> list[HistoryItem]:
    safe_limit = max(1, min(limit, 500))
    rows = history_store.list_runs(limit=safe_limit)
    return [HistoryItem(**row) for row in rows]


def _normalize_threshold_payload(payload: dict[str, float | None]) -> dict[str, float]:
    key_map = {
        "global_threshold": "global_threshold",
        "dos_threshold": "DoS Attack",
        "probe_threshold": "Probe Attack",
        "r2l_threshold": "R2L Attack",
        "u2r_threshold": "U2R Attack",
        "DoS Attack": "DoS Attack",
        "Probe Attack": "Probe Attack",
        "R2L Attack": "R2L Attack",
        "U2R Attack": "U2R Attack",
        "DoS_Attack": "DoS Attack",
        "Probe_Attack": "Probe Attack",
        "R2L_Attack": "R2L Attack",
        "U2R_Attack": "U2R Attack",
    }

    normalized: dict[str, float] = {}
    for key, value in payload.items():
        if value is None:
            continue
        mapped = key_map.get(key)
        if not mapped:
            continue
        try:
            normalized[mapped] = float(value)
        except (TypeError, ValueError):
            continue
    return normalized


@app.get("/api/thresholds")
def get_thresholds() -> dict[str, float]:
    return model_service.get_threshold_policy()


@app.put("/api/thresholds")
def update_thresholds(payload: ThresholdPolicyUpdate) -> dict[str, float]:
    normalized = _normalize_threshold_payload(payload.model_dump(by_alias=True))
    try:
        return model_service.update_threshold_policy(normalized, persist=True)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Unable to update thresholds: {exc}") from exc


@app.post("/api/thresholds/reset")
def reset_thresholds() -> dict[str, float]:
    return model_service.reset_threshold_policy()


@app.get("/api/live/interfaces")
def get_live_interfaces() -> dict[str, list[str]]:
    return {"interfaces": live_monitor.available_interfaces()}


@app.post("/api/live/start", response_model=LiveStatusResponse)
def start_live_monitor(payload: LiveStartRequest) -> LiveStatusResponse:
    try:
        status = live_monitor.start(interface=payload.interface, bpf_filter=payload.bpf_filter)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return LiveStatusResponse(**status)


@app.post("/api/live/stop", response_model=LiveStatusResponse)
def stop_live_monitor() -> LiveStatusResponse:
    status = live_monitor.stop()
    return LiveStatusResponse(**status)


@app.get("/api/live/status", response_model=LiveStatusResponse)
def get_live_status() -> LiveStatusResponse:
    status = live_monitor.status()
    return LiveStatusResponse(**status)


@app.get("/api/history/{run_id}/export")
def export_run_predictions(run_id: int) -> FileResponse:
    row = history_store.get_run(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="Run not found.")

    export_path = row.get("export_path")
    if not export_path:
        raise HTTPException(status_code=404, detail="Export file is unavailable for this run.")

    export_file = Path(export_path)
    if not export_file.exists():
        raise HTTPException(status_code=404, detail="Export file no longer exists on disk.")

    return FileResponse(
        path=export_file,
        media_type="text/csv",
        filename=export_file.name,
    )
