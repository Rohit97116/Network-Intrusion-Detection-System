import { motion } from "framer-motion";
import { PlayCircle, ShieldAlert, UploadCloud } from "lucide-react";

function ActionPanel({
  trainFile,
  detectFile,
  onTrainFile,
  onDetectFile,
  onTrain,
  onDetect,
  training,
  detecting,
  modelReady
}) {
  return (
    <motion.section
      className="panel action-panel"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
    >
      <h2>Operations</h2>
      <p className="subtle">Upload CSV files and run model training or intrusion detection.</p>

      <div className="stacked-step">
        <label className="step-label">
          <UploadCloud size={16} />
          1. Upload training dataset
        </label>
        <input type="file" accept=".csv" onChange={onTrainFile} />
        <div className="filename">{trainFile?.name || "No file selected"}</div>
        <button className="primary-btn" onClick={onTrain} disabled={!trainFile || training}>
          <PlayCircle size={16} />
          {training ? "Training..." : "Train ML Models"}
        </button>
      </div>

      <div className="stacked-step">
        <label className="step-label">
          <ShieldAlert size={16} />
          2. Upload traffic CSV and detect
        </label>
        <input type="file" accept=".csv" onChange={onDetectFile} />
        <div className="filename">{detectFile?.name || "No file selected"}</div>
        <button
          className="danger-btn"
          onClick={onDetect}
          disabled={!detectFile || detecting || !modelReady}
        >
          <PlayCircle size={16} />
          {detecting ? "Scanning..." : "Run Intrusion Detection"}
        </button>
        {!modelReady && (
          <div className="hint">Train a model first to unlock detection mode.</div>
        )}
      </div>
    </motion.section>
  );
}

export default ActionPanel;
