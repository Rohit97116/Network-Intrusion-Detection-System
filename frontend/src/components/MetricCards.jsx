import { motion } from "framer-motion";
import { Activity, AlertTriangle, Brain, GaugeCircle, ShieldCheck } from "lucide-react";

function metricValue(value, suffix = "") {
  if (value === null || value === undefined) {
    return "-";
  }
  return `${value}${suffix}`;
}

function MetricCards({ detection, modelMetrics }) {
  const bestModel = modelMetrics?.best_model_name || "-";
  const bestScore = modelMetrics?.model_comparison?.[0]?.accuracy;

  const cards = [
    {
      title: "Total Records",
      value: metricValue(detection?.total_records),
      icon: Activity
    },
    {
      title: "Detected Attacks",
      value: metricValue(detection?.attack_records),
      icon: AlertTriangle
    },
    {
      title: "Top Attack",
      value: metricValue(detection?.top_attack),
      icon: ShieldCheck
    },
    {
      title: "Avg Confidence",
      value: metricValue(
        detection?.avg_confidence ? (detection.avg_confidence * 100).toFixed(1) : null,
        "%"
      ),
      icon: GaugeCircle
    },
    {
      title: "Best Model",
      value: bestModel,
      icon: Brain
    },
    {
      title: "Model Accuracy",
      value: metricValue(bestScore ? (bestScore * 100).toFixed(2) : null, "%"),
      icon: Brain
    }
  ];

  return (
    <section className="metric-grid">
      {cards.map((card, index) => {
        const Icon = card.icon;
        return (
          <motion.article
            key={card.title}
            className="metric-card"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.28, delay: index * 0.04 }}
          >
            <div className="metric-title">{card.title}</div>
            <div className="metric-value">{card.value}</div>
            <Icon size={18} />
          </motion.article>
        );
      })}
    </section>
  );
}

export default MetricCards;
