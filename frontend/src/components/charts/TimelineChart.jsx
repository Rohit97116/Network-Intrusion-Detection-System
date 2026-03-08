import {
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip
} from "chart.js";
import { Line } from "react-chartjs-2";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
);

function TimelineChart({ timeline }) {
  const hasData = Array.isArray(timeline) && timeline.length > 0;
  if (!hasData) {
    return <div className="empty-state">Detection timeline appears after a scan completes.</div>;
  }

  const data = {
    labels: timeline.map((point) => `W${point.bucket}`),
    datasets: [
      {
        label: "Attack Rate (%)",
        data: timeline.map((point) => point.attack_rate),
        borderColor: "#ff5f46",
        backgroundColor: "rgba(255, 95, 70, 0.22)",
        tension: 0.35,
        fill: true,
        pointRadius: 2
      },
      {
        label: "Traffic Volume",
        data: timeline.map((point) => point.records),
        borderColor: "#1984ff",
        backgroundColor: "rgba(25, 132, 255, 0.18)",
        tension: 0.2,
        pointRadius: 2
      }
    ]
  };

  const options = {
    responsive: true,
    interaction: { mode: "index", intersect: false },
    scales: {
      y: {
        beginAtZero: true,
        ticks: { color: "#334155" },
        grid: { color: "rgba(15, 23, 42, 0.08)" }
      },
      x: {
        ticks: { color: "#334155" },
        grid: { color: "rgba(15, 23, 42, 0.05)" }
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

  return <Line data={data} options={options} />;
}

export default TimelineChart;
