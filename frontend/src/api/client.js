import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://127.0.0.1:8000",
  timeout: 180000
});

export async function healthCheck() {
  const { data } = await api.get("/api/health");
  return data;
}

export async function trainModel(file) {
  const form = new FormData();
  form.append("file", file);
  const { data } = await api.post("/api/train", form, {
    headers: { "Content-Type": "multipart/form-data" }
  });
  return data;
}

export async function runDetection(file, maxPreviewRows = 500) {
  return runDetectionWithThresholds(file, {
    maxPreviewRows
  });
}

export async function runDetectionWithThresholds(
  file,
  {
    maxPreviewRows = 500,
    globalThreshold = null,
    dosThreshold = null,
    probeThreshold = null,
    r2lThreshold = null,
    u2rThreshold = null
  } = {}
) {
  const form = new FormData();
  form.append("file", file);
  form.append("max_preview_rows", String(maxPreviewRows));
  if (globalThreshold !== null && globalThreshold !== undefined) {
    form.append("global_threshold", String(globalThreshold));
  }
  if (dosThreshold !== null && dosThreshold !== undefined) {
    form.append("dos_threshold", String(dosThreshold));
  }
  if (probeThreshold !== null && probeThreshold !== undefined) {
    form.append("probe_threshold", String(probeThreshold));
  }
  if (r2lThreshold !== null && r2lThreshold !== undefined) {
    form.append("r2l_threshold", String(r2lThreshold));
  }
  if (u2rThreshold !== null && u2rThreshold !== undefined) {
    form.append("u2r_threshold", String(u2rThreshold));
  }
  const { data } = await api.post("/api/detect", form, {
    headers: { "Content-Type": "multipart/form-data" }
  });
  return data;
}

export async function fetchModelMetrics() {
  const { data } = await api.get("/api/model/metrics");
  return data;
}

export async function fetchHistory(limit = 100) {
  const { data } = await api.get("/api/history", { params: { limit } });
  return data;
}

export async function fetchThresholds() {
  const { data } = await api.get("/api/thresholds");
  return data;
}

export async function updateThresholds(payload) {
  const { data } = await api.put("/api/thresholds", payload);
  return data;
}

export async function resetThresholds() {
  const { data } = await api.post("/api/thresholds/reset");
  return data;
}

export async function fetchLiveStatus() {
  const { data } = await api.get("/api/live/status");
  return data;
}

export async function fetchLiveInterfaces() {
  const { data } = await api.get("/api/live/interfaces");
  return data;
}

export async function startLiveMonitor(payload) {
  const { data } = await api.post("/api/live/start", payload);
  return data;
}

export async function stopLiveMonitor() {
  const { data } = await api.post("/api/live/stop");
  return data;
}

export function exportUrl(runId) {
  return `${api.defaults.baseURL}/api/history/${runId}/export`;
}
