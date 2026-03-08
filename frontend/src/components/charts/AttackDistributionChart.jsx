import {
  ArcElement,
  Chart as ChartJS,
  Legend,
  Tooltip
} from "chart.js";
import { Doughnut } from "react-chartjs-2";

ChartJS.register(ArcElement, Tooltip, Legend);

const COLORS = ["#1984ff", "#ff5f46", "#f59e0b", "#ff3d71", "#00b28c"];

function AttackDistributionChart({ distribution }) {
  const labels = Object.keys(distribution || {});
  const values = labels.map((label) => distribution[label]);
  const hasData = values.some((value) => value > 0);

  const chartData = {
    labels,
    datasets: [
      {
        label: "Traffic Share",
        data: values,
        backgroundColor: COLORS,
        borderColor: "#f8fafc",
        borderWidth: 2,
        hoverOffset: 6
      }
    ]
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: "bottom",
        labels: {
          color: "#0f172a",
          font: { family: "IBM Plex Sans", size: 12 }
        }
      }
    }
  };

  if (!hasData) {
    return <div className="empty-state">Run detection to visualize attack distribution.</div>;
  }

  return <Doughnut data={chartData} options={options} />;
}

export default AttackDistributionChart;
