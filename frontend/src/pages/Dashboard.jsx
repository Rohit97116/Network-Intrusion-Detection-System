import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Cpu, Database, RadioTower, Radar } from "lucide-react";
import {
  exportUrl,
  fetchLiveInterfaces,
  fetchLiveStatus,
  fetchHistory,
  fetchModelMetrics,
  fetchThresholds,
  healthCheck,
  resetThresholds,
  runDetectionWithThresholds,
  startLiveMonitor,
  stopLiveMonitor,
  trainModel,
  updateThresholds
} from "../api/client";
import ActionPanel from "../components/ActionPanel";
import AlertsPanel from "../components/AlertsPanel";
import HistoryTable from "../components/HistoryTable";
import LiveMonitorPanel from "../components/LiveMonitorPanel";
import MetricCards from "../components/MetricCards";
import PredictionTable from "../components/PredictionTable";
import ThresholdPanel from "../components/ThresholdPanel";
import AttackDistributionChart from "../components/charts/AttackDistributionChart";
import ConfusionMatrixChart from "../components/charts/ConfusionMatrixChart";
import ModelComparisonChart from "../components/charts/ModelComparisonChart";
import TimelineChart from "../components/charts/TimelineChart";

const DEFAULT_THRESHOLDS = {
  global_threshold: 0.62,
  "DoS Attack": 0.6,
  "Probe Attack": 0.68,
  "R2L Attack": 0.74,
  "U2R Attack": 0.78
};

function Dashboard() {
  const [trainFile, setTrainFile] = useState(null);
  const [detectFile, setDetectFile] = useState(null);
  const [health, setHealth] = useState(null);
  const [modelMetrics, setModelMetrics] = useState(null);
  const [detection, setDetection] = useState(null);
  const [historyRows, setHistoryRows] = useState([]);
  const [training, setTraining] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [thresholds, setThresholds] = useState(DEFAULT_THRESHOLDS);
  const [savingThresholds, setSavingThresholds] = useState(false);
  const [liveStatus, setLiveStatus] = useState(null);
  const [liveInterfaces, setLiveInterfaces] = useState([]);
  const [liveInterface, setLiveInterface] = useState("");
  const [liveFilter, setLiveFilter] = useState("ip");
  const [liveBusy, setLiveBusy] = useState(false);

  const modelReady = useMemo(
    () => Boolean(modelMetrics?.best_model_name || health?.model_ready),
    [health, modelMetrics]
  );

  async function loadInitialData() {
    setLoading(true);
    setError("");
    try {
      const [healthData, historyData, thresholdData, liveData, interfaceData] = await Promise.all([
        healthCheck(),
        fetchHistory(100),
        fetchThresholds(),
        fetchLiveStatus(),
        fetchLiveInterfaces()
      ]);
      setHealth(healthData);
      setHistoryRows(historyData);
      setThresholds({ ...DEFAULT_THRESHOLDS, ...thresholdData });
      setLiveStatus(liveData);
      setLiveInterfaces(interfaceData?.interfaces || []);
      try {
        const metrics = await fetchModelMetrics();
        setModelMetrics(metrics);
      } catch (metricsError) {
        if (metricsError?.response?.status !== 404) {
          throw metricsError;
        }
      }
    } catch (loadError) {
      setError(loadError?.response?.data?.detail || "Unable to load dashboard data.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadInitialData();
  }, []);

  useEffect(() => {
    if (!liveStatus?.running) {
      return undefined;
    }
    const intervalId = window.setInterval(async () => {
      try {
        const status = await fetchLiveStatus();
        setLiveStatus(status);
      } catch {
        // Silent polling error to avoid noisy UI interruptions.
      }
    }, 2500);
    return () => window.clearInterval(intervalId);
  }, [liveStatus?.running]);

  async function refreshHistory() {
    const historyData = await fetchHistory(100);
    setHistoryRows(historyData);
  }

  async function handleTrain() {
    if (!trainFile) {
      return;
    }
    setError("");
    setMessage("");
    setTraining(true);
    try {
      const result = await trainModel(trainFile);
      setModelMetrics(result);
      setMessage(`Training complete. Best model: ${result.best_model_name}.`);
      const healthData = await healthCheck();
      setHealth(healthData);
    } catch (trainError) {
      setError(trainError?.response?.data?.detail || "Model training failed.");
    } finally {
      setTraining(false);
    }
  }

  async function handleDetect() {
    if (!detectFile) {
      return;
    }
    setError("");
    setMessage("");
    setDetecting(true);
    try {
      const result = await runDetectionWithThresholds(detectFile, {
        maxPreviewRows: 600,
        globalThreshold: thresholds.global_threshold,
        dosThreshold: thresholds["DoS Attack"],
        probeThreshold: thresholds["Probe Attack"],
        r2lThreshold: thresholds["R2L Attack"],
        u2rThreshold: thresholds["U2R Attack"]
      });
      setDetection(result);
      setMessage(
        `Detection completed: ${result.attack_records} suspicious records identified in ${result.total_records} events.`
      );
      await refreshHistory();
    } catch (detectError) {
      setError(detectError?.response?.data?.detail || "Intrusion detection failed.");
    } finally {
      setDetecting(false);
    }
  }

  function handleExport(runId) {
    const target = exportUrl(runId);
    window.open(target, "_blank", "noopener,noreferrer");
  }

  async function handleSaveThresholds() {
    setSavingThresholds(true);
    setError("");
    setMessage("");
    try {
      const updated = await updateThresholds({
        global_threshold: thresholds.global_threshold,
        "DoS Attack": thresholds["DoS Attack"],
        "Probe Attack": thresholds["Probe Attack"],
        "R2L Attack": thresholds["R2L Attack"],
        "U2R Attack": thresholds["U2R Attack"]
      });
      setThresholds({ ...DEFAULT_THRESHOLDS, ...updated });
      setMessage("Threshold policy updated. New detections will use the saved values.");
    } catch (saveError) {
      setError(saveError?.response?.data?.detail || "Unable to update threshold policy.");
    } finally {
      setSavingThresholds(false);
    }
  }

  async function handleResetThresholds() {
    setSavingThresholds(true);
    setError("");
    setMessage("");
    try {
      const defaults = await resetThresholds();
      setThresholds({ ...DEFAULT_THRESHOLDS, ...defaults });
      setMessage("Threshold policy reset to defaults.");
    } catch (resetError) {
      setError(resetError?.response?.data?.detail || "Unable to reset thresholds.");
    } finally {
      setSavingThresholds(false);
    }
  }

  async function handleLiveStart() {
    if (!modelReady) {
      setError("Train a model before starting live packet monitoring.");
      return;
    }
    setLiveBusy(true);
    setError("");
    setMessage("");
    try {
      const status = await startLiveMonitor({
        interface: liveInterface || null,
        bpf_filter: liveFilter || "ip"
      });
      setLiveStatus(status);
      setMessage("Live monitoring started.");
    } catch (liveError) {
      setError(liveError?.response?.data?.detail || "Unable to start live monitoring.");
    } finally {
      setLiveBusy(false);
    }
  }

  async function handleLiveStop() {
    setLiveBusy(true);
    setError("");
    setMessage("");
    try {
      const status = await stopLiveMonitor();
      setLiveStatus(status);
      setMessage("Live monitoring stopped.");
    } catch (liveError) {
      setError(liveError?.response?.data?.detail || "Unable to stop live monitoring.");
    } finally {
      setLiveBusy(false);
    }
  }

  if (loading) {
    return <div className="loading-screen">Loading cybersecurity dashboard...</div>;
  }

  return (
    <main className="dashboard-shell">
      <motion.header
        className="hero"
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
      >
        <div>
          <h1>NIDS Sentinel</h1>
          <p>Machine Learning-powered Intrusion Detection Dashboard</p>
        </div>
        <div className="status-strip">
          <div className={`status-pill ${modelReady ? "good" : "warn"}`}>
            <Cpu size={14} />
            Model: {modelReady ? "Ready" : "Not Trained"}
          </div>
          <div className={`status-pill ${liveStatus?.running ? "good" : "neutral"}`}>
            <RadioTower size={14} />
            Live: {liveStatus?.running ? "Running" : "Stopped"}
          </div>
          <div className="status-pill info">
            <Radar size={14} />
            API: {health?.status || "Unknown"}
          </div>
          <div className="status-pill neutral">
            <Database size={14} />
            Runs: {historyRows.length}
          </div>
        </div>
      </motion.header>

      {error && <div className="banner error">{error}</div>}
      {message && <div className="banner success">{message}</div>}

      <section className="top-grid">
        <ActionPanel
          trainFile={trainFile}
          detectFile={detectFile}
          onTrainFile={(event) => setTrainFile(event.target.files?.[0] || null)}
          onDetectFile={(event) => setDetectFile(event.target.files?.[0] || null)}
          onTrain={handleTrain}
          onDetect={handleDetect}
          training={training}
          detecting={detecting}
          modelReady={modelReady}
        />
        <section className="panel">
          <h2>Operational Overview</h2>
          <p className="subtle">
            Upload NSL-KDD or CICIDS-style CSV files. Train models once, then run one-click scans
            and export results for audit workflows.
          </p>
          <MetricCards detection={detection} modelMetrics={modelMetrics} />
        </section>
      </section>

      <section className="chart-grid">
        <ThresholdPanel
          thresholds={thresholds}
          onThresholdChange={(key, value) =>
            setThresholds((previous) => ({ ...previous, [key]: value }))
          }
          onSave={handleSaveThresholds}
          onReset={handleResetThresholds}
          saving={savingThresholds}
        />
        <LiveMonitorPanel
          liveStatus={liveStatus}
          interfaces={liveInterfaces}
          selectedInterface={liveInterface}
          onInterfaceChange={setLiveInterface}
          bpfFilter={liveFilter}
          onFilterChange={setLiveFilter}
          onStart={handleLiveStart}
          onStop={handleLiveStop}
          busy={liveBusy}
        />
      </section>

      <section className="chart-grid">
        <section className="panel">
          <h3>Attack Distribution</h3>
          <AttackDistributionChart distribution={detection?.attack_distribution || {}} />
        </section>
        <section className="panel">
          <h3>Detection Timeline</h3>
          <TimelineChart timeline={detection?.timeline || []} />
        </section>
        <section className="panel">
          <h3>Model Accuracy Comparison</h3>
          <ModelComparisonChart models={modelMetrics?.model_comparison || []} />
        </section>
        <section className="panel">
          <h3>Confusion Matrix</h3>
          <ConfusionMatrixChart
            matrix={modelMetrics?.confusion_matrix || []}
            labels={modelMetrics?.class_order || []}
          />
        </section>
      </section>

      <AlertsPanel alerts={detection?.alerts || []} />
      <PredictionTable preview={detection?.preview || []} />
      <HistoryTable rows={historyRows} onExport={handleExport} />
    </main>
  );
}

export default Dashboard;
