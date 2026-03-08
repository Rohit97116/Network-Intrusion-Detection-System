import { AlertOctagon } from "lucide-react";

function AlertsPanel({ alerts }) {
  if (!alerts || alerts.length === 0) {
    return (
      <section className="panel">
        <h3>Active Alerts</h3>
        <div className="empty-state">No suspicious activity detected in the latest scan.</div>
      </section>
    );
  }

  return (
    <section className="panel">
      <h3>Active Alerts</h3>
      <div className="alerts-list">
        {alerts.map((alert) => (
          <div key={`${alert.row_id}-${alert.predicted_label}`} className="alert-item">
            <div className="alert-icon">
              <AlertOctagon size={16} />
            </div>
            <div>
              <div className="alert-head">
                Row #{alert.row_id} - {alert.predicted_label}
              </div>
              <div className="alert-sub">{alert.message}</div>
            </div>
            <div className={`severity severity-${alert.severity.toLowerCase()}`}>
              {alert.severity}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export default AlertsPanel;
