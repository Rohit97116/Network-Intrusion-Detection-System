from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any

import pandas as pd

from app.ml.constants import FEATURE_COLUMNS
from app.services.model_service import ModelService

try:
    from scapy.all import AsyncSniffer, ICMP, IP, TCP, UDP, get_if_list  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:  # noqa: BLE001
    SCAPY_AVAILABLE = False
    AsyncSniffer = None  # type: ignore
    ICMP = object  # type: ignore
    IP = object  # type: ignore
    TCP = object  # type: ignore
    UDP = object  # type: ignore
    get_if_list = None  # type: ignore


PORT_TO_SERVICE = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "domain_u",
    80: "http",
    110: "pop_3",
    143: "imap4",
    443: "http_443",
    3306: "mysql",
    3389: "remote_job",
    8080: "http",
}


class LiveMonitorService:
    def __init__(self, model_service: ModelService, logger: Any) -> None:
        self.model_service = model_service
        self.logger = logger
        self._lock = Lock()
        self._sniffer: Any | None = None
        self._running = False
        self._started_at: str | None = None
        self._interface: str | None = None
        self._bpf_filter: str | None = None
        self._packet_id = 0
        self._total_packets = 0
        self._attack_packets = 0
        self._suppressed_packets = 0
        self._attack_counter: Counter[str] = Counter()
        self._events: deque[dict[str, Any]] = deque(maxlen=250)
        self._window_packets: deque[tuple[float, str, str, str]] = deque(maxlen=5000)

    def available_interfaces(self) -> list[str]:
        if not SCAPY_AVAILABLE or get_if_list is None:
            return []
        try:
            interfaces = get_if_list()
        except Exception:  # noqa: BLE001
            return []
        return sorted({str(item) for item in interfaces})

    @staticmethod
    def _protocol_service_flag(packet: Any) -> tuple[str, str, str, int]:
        packet_len = int(len(packet))
        protocol_type = "tcp"
        service = "private"
        flag = "SF"

        if packet.haslayer(TCP):
            protocol_type = "tcp"
            tcp = packet[TCP]
            dport = int(getattr(tcp, "dport", 0))
            service = PORT_TO_SERVICE.get(dport, "private")
            tcp_flags = str(getattr(tcp, "flags", ""))
            if "R" in tcp_flags:
                flag = "RSTR"
            elif "S" in tcp_flags and "A" in tcp_flags:
                flag = "S1"
            elif "S" in tcp_flags:
                flag = "S0"
            else:
                flag = "SF"
        elif packet.haslayer(UDP):
            protocol_type = "udp"
            udp = packet[UDP]
            dport = int(getattr(udp, "dport", 0))
            service = PORT_TO_SERVICE.get(dport, "private")
            flag = "SF"
        elif packet.haslayer(ICMP):
            protocol_type = "icmp"
            service = "eco_i"
            flag = "SF"

        return protocol_type, service, flag, packet_len

    @staticmethod
    def _get_ips(packet: Any) -> tuple[str, str]:
        if packet.haslayer(IP):
            return str(packet[IP].src), str(packet[IP].dst)
        return "unknown", "unknown"

    def _feature_row_from_packet(self, packet: Any) -> tuple[dict[str, Any], dict[str, str]]:
        protocol_type, service, flag, packet_len = self._protocol_service_flag(packet)
        src_ip, dst_ip = self._get_ips(packet)
        now_epoch = datetime.now(timezone.utc).timestamp()

        self._window_packets.append((now_epoch, protocol_type, service, flag))
        window_start = now_epoch - 30.0
        while self._window_packets and self._window_packets[0][0] < window_start:
            self._window_packets.popleft()

        window_size = len(self._window_packets)
        srv_count = sum(1 for _, _, srv, _ in self._window_packets if srv == service)
        serror_count = sum(1 for _, _, _, fl in self._window_packets if fl in {"S0", "RSTR"})
        rerror_count = sum(1 for _, _, _, fl in self._window_packets if fl == "RSTR")

        same_srv_rate = (srv_count / window_size) if window_size else 0.0
        serror_rate = (serror_count / window_size) if window_size else 0.0
        rerror_rate = (rerror_count / window_size) if window_size else 0.0

        features = {column: 0.0 for column in FEATURE_COLUMNS}
        features["duration"] = 0.0
        features["protocol_type"] = protocol_type
        features["service"] = service
        features["flag"] = flag
        features["src_bytes"] = float(packet_len)
        features["dst_bytes"] = 0.0
        features["land"] = float(1 if src_ip == dst_ip else 0)
        features["count"] = float(min(window_size, 511))
        features["srv_count"] = float(min(srv_count, 511))
        features["serror_rate"] = float(serror_rate)
        features["srv_serror_rate"] = float(serror_rate)
        features["rerror_rate"] = float(rerror_rate)
        features["srv_rerror_rate"] = float(rerror_rate)
        features["same_srv_rate"] = float(same_srv_rate)
        features["diff_srv_rate"] = float(max(0.0, 1.0 - same_srv_rate))
        features["srv_diff_host_rate"] = float(max(0.0, 1.0 - same_srv_rate))
        features["dst_host_count"] = float(min(window_size, 255))
        features["dst_host_srv_count"] = float(min(srv_count, 255))
        features["dst_host_same_srv_rate"] = float(same_srv_rate)
        features["dst_host_diff_srv_rate"] = float(max(0.0, 1.0 - same_srv_rate))
        features["dst_host_same_src_port_rate"] = float(same_srv_rate)
        features["dst_host_srv_diff_host_rate"] = float(max(0.0, 1.0 - same_srv_rate))
        features["dst_host_serror_rate"] = float(serror_rate)
        features["dst_host_srv_serror_rate"] = float(serror_rate)
        features["dst_host_rerror_rate"] = float(rerror_rate)
        features["dst_host_srv_rerror_rate"] = float(rerror_rate)

        metadata = {"src_ip": src_ip, "dst_ip": dst_ip}
        return features, metadata

    def _handle_packet(self, packet: Any) -> None:
        with self._lock:
            if not self._running:
                return

            self._packet_id += 1
            packet_id = self._packet_id

        try:
            feature_row, metadata = self._feature_row_from_packet(packet)
            feature_df = pd.DataFrame([feature_row])
            prediction = self.model_service.predict_single_feature_row(feature_df)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Live packet processing skipped: %s", exc)
            return

        event = {
            "packet_id": packet_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol_type": feature_row["protocol_type"],
            "service": feature_row["service"],
            "src_ip": metadata["src_ip"],
            "dst_ip": metadata["dst_ip"],
            "predicted_label": prediction["predicted_label"],
            "confidence": float(prediction["confidence"]),
            "severity": prediction["severity"],
            "threshold_suppressed": bool(prediction["threshold_suppressed"]),
        }

        with self._lock:
            self._total_packets += 1
            if event["predicted_label"] != "Normal Traffic":
                self._attack_packets += 1
                self._attack_counter[event["predicted_label"]] += 1
            if event["threshold_suppressed"]:
                self._suppressed_packets += 1
            self._events.appendleft(event)

    def start(self, interface: str | None = None, bpf_filter: str | None = "ip") -> dict[str, Any]:
        if not self.model_service.is_model_ready():
            raise RuntimeError("Model is not trained. Train a model before live monitoring.")
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Install backend dependencies including scapy for live monitoring."
            )

        with self._lock:
            if self._running:
                raise RuntimeError("Live monitor is already running.")

            self._running = True
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._interface = interface
            self._bpf_filter = bpf_filter
            self._packet_id = 0
            self._total_packets = 0
            self._attack_packets = 0
            self._suppressed_packets = 0
            self._attack_counter = Counter()
            self._events.clear()
            self._window_packets.clear()

        try:
            self._sniffer = AsyncSniffer(
                iface=interface or None,
                filter=bpf_filter or None,
                prn=self._handle_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._running = False
                self._started_at = None
            raise RuntimeError(
                f"Unable to start packet sniffer. Try running with admin rights. Details: {exc}"
            ) from exc

        self.logger.info("Live monitor started (interface=%s, filter=%s)", interface, bpf_filter)
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            sniffer = self._sniffer
            self._sniffer = None
            self._running = False

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:  # noqa: BLE001
                pass

        self.logger.info("Live monitor stopped")
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            top_attack = (
                self._attack_counter.most_common(1)[0][0]
                if self._attack_counter
                else "No active attack"
            )
            return {
                "running": self._running,
                "interface": self._interface,
                "bpf_filter": self._bpf_filter,
                "started_at": self._started_at,
                "total_packets": self._total_packets,
                "attack_packets": self._attack_packets,
                "threshold_suppressed_packets": self._suppressed_packets,
                "top_attack": top_attack,
                "recent_events": list(self._events)[:60],
            }
