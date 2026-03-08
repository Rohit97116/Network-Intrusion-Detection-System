function cellOpacity(value, maxValue) {
  if (maxValue <= 0) {
    return 0.08;
  }
  return Math.max(0.08, value / maxValue);
}

function ConfusionMatrixChart({ matrix, labels }) {
  if (!Array.isArray(matrix) || matrix.length === 0) {
    return <div className="empty-state">Confusion matrix is available after training.</div>;
  }

  const flattened = matrix.flat();
  const maxValue = Math.max(...flattened, 0);

  return (
    <div className="confusion-wrapper">
      <div className="confusion-hint">Rows = actual class, columns = predicted class</div>
      <div className="table-wrap">
        <table className="matrix-table">
          <thead>
            <tr>
              <th>Actual \\ Predicted</th>
              {labels.map((label) => (
                <th key={`head-${label}`}>{label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.map((row, rowIndex) => (
              <tr key={`row-${labels[rowIndex]}`}>
                <th>{labels[rowIndex]}</th>
                {row.map((value, colIndex) => (
                  <td
                    key={`${rowIndex}-${colIndex}`}
                    style={{
                      background: `rgba(25, 132, 255, ${cellOpacity(value, maxValue)})`
                    }}
                  >
                    {value}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default ConfusionMatrixChart;
