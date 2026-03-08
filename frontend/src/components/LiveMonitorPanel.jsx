import { Activity, RadioTower } from "lucide-react";

function LiveMonitorPanel({
  liveStatus,
  interfaces,
  selectedInterface,
  onInterfaceChange,
  bpfFilter,
  onFilterChange,
  onStart,
  onStop,
  busy
}) {
  const running = Boolean(liveStatus?.running);
  const recentEvents = liveStatus?.recent_events || [];

  return (
    <section className="panel">
      <h3>
        <RadioTower size={16} />
        Real-time Packet Monitoring
      </h3>
      <p className="subtle">
        Capture live packets and score them with the trained model for continuous intrusion
        visibility.
      </p>

      <div className="live-controls">
        <label>
          Interface
          <select value={selectedInterface} onChange={(event) => onInterfaceChange(event.target.value)}>
            <option value="">Default Interface</option>
            {interfaces.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label>
          Packet Filter
          <input
            type="text"
            value={bpfFilter}
            onChange={(event) => onFilterChange(event.target.value)}
            placeholder="ip or tcp or udp"
          />
        </label>
        <div className="live-buttons">
          <button className="primary-btn" onClick={onStart} disabled={running || busy}>
            Start Monitoring
          </button>
          <button className="danger-btn" onClick={onStop} disabled={!running || busy}>
            Stop
          </button>
        </div>
      </div>

      <div className="live-stats">
        <article>
          <div>Total Packets</div>
          <strong>{liveStatus?.total_packets || 0}</strong>
        </article>
        <article>
          <div>Attack Packets</div>
          <strong>{liveStatus?.attack_packets || 0}</strong>
        </article>
        <article>
          <div>Suppressed Alerts</div>
          <strong>{liveStatus?.threshold_suppressed_packets || 0}</strong>
        </article>
        <article>
          <div>Top Live Attack</div>
          <strong>{liveStatus?.top_attack || "No active attack"}</strong>
        </article>
      </div>

      <h4 className="live-events-title">
        <Activity size={14} />
        Recent Live Events
      </h4>
      {recentEvents.length === 0 ? (
        <div className="empty-state">Start monitoring to view live packet detections.</div>
      ) : (
        <div className="table-wrap">
          <table className="history-table">
            <thead>
              <tr>
                <th>Packet</th>
                <th>Time (UTC)</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Prediction</th>
                <th>Confidence</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.map((event) => (
                <tr key={`${event.packet_id}-${event.timestamp}`}>
                  <td>{event.packet_id}</td>
                  <td>{new Date(event.timestamp).toLocaleTimeString()}</td>
                  <td>{event.src_ip}</td>
                  <td>{event.dst_ip}</td>
                  <td>{event.protocol_type}</td>
                  <td>{event.service}</td>
                  <td>{event.predicted_label}</td>
                  <td>{(event.confidence * 100).toFixed(1)}%</td>
                  <td>
                    <span className={`severity severity-${event.severity.toLowerCase()}`}>
                      {event.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default LiveMonitorPanel;
