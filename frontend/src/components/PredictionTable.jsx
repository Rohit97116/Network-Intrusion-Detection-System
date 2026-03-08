function PredictionTable({ preview }) {
  return (
    <section className="panel">
      <h3>Latest Prediction Preview</h3>
      {preview.length === 0 ? (
        <div className="empty-state">Run a detection scan to view predictions.</div>
      ) : (
        <div className="table-wrap">
          <table className="history-table">
            <thead>
              <tr>
                <th>Row</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Flag</th>
                <th>Prediction</th>
                <th>Confidence</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {preview.map((item) => (
                <tr key={item.row_id}>
                  <td>{item.row_id}</td>
                  <td>{item.protocol_type}</td>
                  <td>{item.service}</td>
                  <td>{item.flag}</td>
                  <td>{item.predicted_label}</td>
                  <td>{(item.confidence * 100).toFixed(1)}%</td>
                  <td>
                    <span className={`severity severity-${item.severity.toLowerCase()}`}>
                      {item.severity}
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

export default PredictionTable;
