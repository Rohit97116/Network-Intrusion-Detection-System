# Network Intrusion Detection System (NIDS)

Production-style full-stack NIDS platform using Python, FastAPI, and machine learning with a modern React dashboard.

## Highlights
- Multi-model ML training pipeline (`Random Forest`, `Logistic Regression`, `Decision Tree`)
- Dataset-aware tuning for `NSL-KDD` and `CICIDS2017` style CSV inputs
- Automatic model comparison, cross-validation stability scoring, and best-model selection
- Attack classification into:
  - `Normal Traffic`
  - `DoS Attack`
  - `Probe Attack`
  - `R2L Attack`
  - `U2R Attack`
- One-click detection with CSV upload
- False-positive reduction controls with configurable global and per-class thresholds
- Optional live packet monitoring with packet sniffing + real-time inference
- Dashboard with:
  - real-time-style detection output panels
  - attack distribution chart
  - detection timeline chart
  - model comparison chart
  - confusion matrix visualization
  - live monitoring status and recent packet events
  - detection history and CSV export
- Model retraining and run history persistence

## Architecture

```text
+---------------------+         HTTP/JSON          +----------------------------+
| React Dashboard     | <------------------------> | FastAPI Backend            |
| (frontend/)         |                            | (backend/app/main.py)      |
+---------------------+                            +-------------+--------------+
                                                                  |
                                                                  v
                                              +-------------------+------------------+
                                              | ML Pipeline (scikit-learn)           |
                                              | - preprocessing + feature selection   |
                                              | - train/evaluate/select best model    |
                                              | - inference + confidence scoring      |
                                              +-------------------+------------------+
                                                                  |
                                       +--------------------------+-------------------------+
                                       |                                                    |
                                       v                                                    v
                       +-------------------------------+                    +-------------------------------+
                       | models/nids_best_model.joblib|                    | models/history.sqlite3        |
                       | models/nids_model_metadata...|                    | models/exports/*.csv          |
                       +-------------------------------+                    +-------------------------------+
```

## Project Structure

```text
backend/
  app/
    main.py
    config.py
    schemas.py
    ml/
    services/
    utils/
  requirements.txt
  run.py
frontend/
  src/
    api/
    components/
    pages/
    styles/
  package.json
datasets/
models/
utils/
  generate_demo_data.py
  prepare_nsl_kdd.py
requirements.txt
README.md
```

## Installation

1. Create and activate a virtual environment.
2. Install backend dependencies:

```bash
pip install -r requirements.txt
```

3. Install frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

## Dataset Setup

### Option A: Generate demo data quickly

```bash
python utils/generate_demo_data.py --train-rows 2500 --traffic-rows 800
```

Generated files:
- `datasets/sample_training_nsl_kdd.csv`
- `datasets/sample_traffic_nsl_kdd.csv`

### Option B: Download NSL-KDD

```bash
python utils/prepare_nsl_kdd.py
```

Generated files:
- `datasets/KDDTrain+.csv`
- `datasets/KDDTest+.csv`

## Run the Application

### Start backend API

```bash
python backend/run.py
```

Backend URL: `http://127.0.0.1:8000`  
API docs: `http://127.0.0.1:8000/docs`

### Start frontend dashboard

```bash
cd frontend
npm run dev
```

Frontend URL: `http://127.0.0.1:5173`

## Usage Flow

1. Open dashboard.
2. Upload training CSV and click `Train ML Models`.
3. Optionally tune false-positive thresholds in `False Positive Control`.
4. Upload traffic CSV and click `Run Intrusion Detection`.
5. (Optional) start `Real-time Packet Monitoring` for live packet scoring.
6. Review:
   - alerts
   - attack distribution
   - timeline
   - confusion matrix
   - model accuracy comparison
   - live packet events and severity
7. Export run results from `Detection History`.

## False Positive Controls

The dashboard includes a threshold policy panel:
- `Global Threshold`: minimum confidence required for any non-normal prediction
- `DoS / Probe / R2L / U2R thresholds`: class-specific minimum confidence

If a predicted attack confidence is below threshold, it is suppressed to `Normal Traffic`.
This reduces noisy alerts in production traffic.

## Live Packet Monitoring

Live monitoring uses `scapy` packet sniffing and classifies packets in near real-time.

Notes:
- Requires admin/root privileges in many environments
- You can set interface and BPF filter (for example: `ip`, `tcp`, `udp`)
- If scapy capture is unavailable, API returns a clear runtime error

## API Endpoints

- `GET /api/health`
- `POST /api/train`
- `POST /api/retrain`
- `GET /api/model/metrics`
- `POST /api/detect`
- `GET /api/thresholds`
- `PUT /api/thresholds`
- `POST /api/thresholds/reset`
- `GET /api/live/interfaces`
- `POST /api/live/start`
- `POST /api/live/stop`
- `GET /api/live/status`
- `GET /api/history`
- `GET /api/history/{run_id}/export`

## Notes on Production Hardening

- Add authentication (JWT/OAuth2) and role-based access
- Run FastAPI with multiple workers behind reverse proxy (Nginx)
- Add centralized logging and SIEM forwarding
- Add CI for tests, linting, and security scanning
- Add packet-capture integration for live traffic ingestion
