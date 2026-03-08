import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  Tooltip
} from "chart.js";
import { Bar } from "react-chartjs-2";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

function ModelComparisonChart({ models }) {
  const hasData = Array.isArray(models) && models.length > 0;
  if (!hasData) {
    return <div className="empty-state">Train a model to compare algorithm performance.</div>;
  }

  const labels = models.map((model) => model.model_name);
  const data = {
    labels,
    datasets: [
      {
        label: "Accuracy",
        data: models.map((model) => Number((model.accuracy * 100).toFixed(2))),
        backgroundColor: "#1984ff"
      },
      {
        label: "F1 Macro",
        data: models.map((model) => Number((model.f1_macro * 100).toFixed(2))),
        backgroundColor: "#00b28c"
      },
      {
        label: "Recall Macro",
        data: models.map((model) => Number((model.recall_macro * 100).toFixed(2))),
        backgroundColor: "#f59e0b"
      }
    ]
  };

  const options = {
    responsive: true,
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        ticks: { color: "#334155" },
        grid: { color: "rgba(15, 23, 42, 0.08)" }
      },
      x: {
        ticks: { color: "#334155" },
        grid: { display: false }
      }
    },
    plugins: {
      legend: {
        labels: {
          color: "#0f172a",
          font: { family: "IBM Plex Sans" }
        }
      }
    }
  };

  return <Bar data={data} options={options} />;
}

export default ModelComparisonChart;
