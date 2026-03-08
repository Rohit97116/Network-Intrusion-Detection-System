import { SlidersHorizontal } from "lucide-react";

const THRESHOLD_KEYS = [
  { key: "global_threshold", label: "Global Threshold" },
  { key: "DoS Attack", label: "DoS Attack" },
  { key: "Probe Attack", label: "Probe Attack" },
  { key: "R2L Attack", label: "R2L Attack" },
  { key: "U2R Attack", label: "U2R Attack" }
];

function formatPct(value) {
  return `${(value * 100).toFixed(0)}%`;
}

function ThresholdPanel({ thresholds, onThresholdChange, onSave, onReset, saving }) {
  return (
    <section className="panel">
      <h3>
        <SlidersHorizontal size={16} />
        False Positive Control
      </h3>
      <p className="subtle">
        Increase thresholds to suppress low-confidence attack flags. Higher values reduce false
        positives but can miss weak attacks.
      </p>
      <div className="threshold-grid">
        {THRESHOLD_KEYS.map((item) => (
          <label key={item.key} className="threshold-item">
            <div className="threshold-head">
              <span>{item.label}</span>
              <strong>{formatPct(Number(thresholds[item.key] ?? 0.62))}</strong>
            </div>
            <input
              type="range"
              min="0.35"
              max="0.95"
              step="0.01"
              value={Number(thresholds[item.key] ?? 0.62)}
              onChange={(event) => onThresholdChange(item.key, Number(event.target.value))}
            />
          </label>
        ))}
      </div>
      <div className="threshold-actions">
        <button className="primary-btn" onClick={onSave} disabled={saving}>
          {saving ? "Saving..." : "Save Threshold Policy"}
        </button>
        <button className="ghost-btn" onClick={onReset} disabled={saving}>
          Reset Defaults
        </button>
      </div>
    </section>
  );
}

export default ThresholdPanel;
