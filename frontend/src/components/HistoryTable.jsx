import { Download } from "lucide-react";

function HistoryTable({ rows, onExport }) {
  return (
    <section className="panel">
      <h3>Detection History</h3>
      {rows.length === 0 ? (
        <div className="empty-state">No detection runs yet.</div>
      ) : (
        <div className="table-wrap">
          <table className="history-table">
            <thead>
              <tr>
                <th>Run</th>
                <th>Timestamp (UTC)</th>
                <th>Source</th>
                <th>Total</th>
                <th>Attacks</th>
                <th>Top Attack</th>
                <th>Confidence</th>
                <th>Export</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.id}</td>
                  <td>{new Date(row.created_at).toLocaleString()}</td>
                  <td>{row.source_filename}</td>
                  <td>{row.total_records}</td>
                  <td>{row.attack_records}</td>
                  <td>{row.top_attack}</td>
                  <td>{(row.avg_confidence * 100).toFixed(1)}%</td>
                  <td>
                    <button className="ghost-btn" onClick={() => onExport(row.id)}>
                      <Download size={14} />
                      CSV
                    </button>
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

export default HistoryTable;
