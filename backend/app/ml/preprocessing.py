from __future__ import annotations

from typing import Tuple

import numpy as np
import pandas as pd

from app.ml.constants import (
    ATTACK_GROUPS,
    CATEGORICAL_COLUMNS,
    CLASS_NAMES,
    DIFFICULTY_COLUMN,
    FEATURE_COLUMNS,
    FULL_COLUMNS,
    FULL_COLUMNS_WITH_DIFFICULTY,
    NUMERIC_COLUMNS,
    TARGET_COLUMN,
)

CICIDS_HINT_COLUMNS = {
    "flow duration",
    "protocol",
    "destination port",
    "tot fwd pkts",
    "tot bwd pkts",
    "label",
}

PORT_TO_SERVICE = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain_u",
    67: "dhcp",
    68: "dhcp",
    69: "tftp_u",
    80: "http",
    110: "pop_3",
    111: "sunrpc",
    123: "ntp_u",
    137: "netbios_ns",
    138: "netbios_dgm",
    139: "netbios_ssn",
    143: "imap4",
    161: "snmp",
    162: "snmp",
    443: "http_443",
    3306: "mysql",
    3389: "remote_job",
    5060: "sip",
    8080: "http",
}


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    normalized = df.copy()
    normalized.columns = [str(column).strip().lower() for column in normalized.columns]

    if len(normalized.columns) == len(FULL_COLUMNS_WITH_DIFFICULTY):
        if not all(col in normalized.columns for col in FEATURE_COLUMNS):
            normalized.columns = FULL_COLUMNS_WITH_DIFFICULTY
    elif len(normalized.columns) == len(FULL_COLUMNS):
        if not all(col in normalized.columns for col in FEATURE_COLUMNS):
            normalized.columns = FULL_COLUMNS
    elif len(normalized.columns) == len(FEATURE_COLUMNS):
        if not all(col in normalized.columns for col in FEATURE_COLUMNS):
            normalized.columns = FEATURE_COLUMNS

    return normalized


def _first_column(frame: pd.DataFrame, candidates: tuple[str, ...]) -> pd.Series:
    for name in candidates:
        if name in frame.columns:
            return frame[name]
    return pd.Series(np.nan, index=frame.index)


def _to_numeric(series: pd.Series, default: float = 0.0) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(default).astype(float)


def _to_rate(series: pd.Series, default: float = 0.0) -> pd.Series:
    numeric = _to_numeric(series, default=default)
    if numeric.max() > 1.0:
        numeric = numeric / 100.0
    return numeric.clip(0.0, 1.0)


def _protocol_to_text(series: pd.Series) -> pd.Series:
    def _map(value: object) -> str:
        as_text = str(value).strip().lower()
        if as_text in {"tcp", "udp", "icmp"}:
            return as_text
        if as_text in {"6", "17", "1"}:
            return {"6": "tcp", "17": "udp", "1": "icmp"}[as_text]
        return "tcp"

    return series.map(_map)


def _port_to_service(series: pd.Series) -> pd.Series:
    ports = _to_numeric(series, default=0.0).astype(int)
    return ports.map(lambda port: PORT_TO_SERVICE.get(port, "private"))


def _flag_from_cicids(frame: pd.DataFrame) -> pd.Series:
    if "flag" in frame.columns:
        return frame["flag"].astype(str).str.upper().replace({"": "SF"})

    syn = _to_numeric(_first_column(frame, ("syn flag cnt",)), default=0.0)
    rst = _to_numeric(_first_column(frame, ("rst flag cnt",)), default=0.0)
    ack = _to_numeric(_first_column(frame, ("ack flag cnt",)), default=0.0)
    psh = _to_numeric(
        _first_column(frame, ("fwd psh flags", "bwd psh flags")),
        default=0.0,
    )
    urg = _to_numeric(_first_column(frame, ("urg flag cnt",)), default=0.0)

    flag = np.where(syn > 0, "S0", "SF")
    flag = np.where(rst > 0, "RSTR", flag)
    flag = np.where((ack > 0) & (syn > 0), "S1", flag)
    flag = np.where((psh > 0) & (ack > 0), "SF", flag)
    flag = np.where(urg > 0, "OTH", flag)
    return pd.Series(flag, index=frame.index)


def _convert_cicids_to_nsl(frame: pd.DataFrame) -> pd.DataFrame:
    converted = pd.DataFrame(index=frame.index)

    duration = _to_numeric(
        _first_column(frame, ("duration", "flow duration")),
        default=0.0,
    )
    if duration.max() > 10_000:
        duration = duration / 1_000_000.0
    converted["duration"] = duration.clip(lower=0.0)

    converted["protocol_type"] = _protocol_to_text(
        _first_column(frame, ("protocol_type", "protocol"))
    )
    converted["service"] = _port_to_service(
        _first_column(frame, ("destination port", "dst port", "dest port"))
    )
    converted["flag"] = _flag_from_cicids(frame)

    converted["src_bytes"] = _to_numeric(
        _first_column(
            frame,
            (
                "src_bytes",
                "total length of fwd packets",
                "totlen fwd pkts",
                "fwd packet length max",
            ),
        ),
        default=0.0,
    )
    converted["dst_bytes"] = _to_numeric(
        _first_column(
            frame,
            (
                "dst_bytes",
                "total length of bwd packets",
                "totlen bwd pkts",
                "bwd packet length max",
            ),
        ),
        default=0.0,
    )

    src_ip = _first_column(frame, ("source ip", "src ip", "srcip"))
    dst_ip = _first_column(frame, ("destination ip", "dst ip", "dstip"))
    src_port = _to_numeric(_first_column(frame, ("source port", "src port")), default=-1.0)
    dst_port = _to_numeric(
        _first_column(frame, ("destination port", "dst port", "dest port")),
        default=-2.0,
    )
    land = ((src_ip.astype(str) == dst_ip.astype(str)) & (src_port == dst_port)).astype(int)
    converted["land"] = land.fillna(0)

    converted["wrong_fragment"] = _to_numeric(
        _first_column(frame, ("fwd header length", "bwd header length")),
        default=0.0,
    ).clip(0.0, 3.0)
    converted["urgent"] = _to_numeric(_first_column(frame, ("urg flag cnt",)), default=0.0)
    converted["hot"] = _to_numeric(
        _first_column(frame, ("fwd psh flags", "bwd psh flags")),
        default=0.0,
    )
    converted["num_failed_logins"] = _to_numeric(
        _first_column(frame, ("num_failed_logins", "failed login attempts")),
        default=0.0,
    )
    converted["logged_in"] = (
        _to_numeric(_first_column(frame, ("ack flag cnt",)), default=0.0) > 0
    ).astype(int)
    converted["num_compromised"] = _to_numeric(
        _first_column(frame, ("active mean", "act_data_pkt_fwd", "init_win_bytes_forward")),
        default=0.0,
    ).clip(lower=0.0)
    converted["root_shell"] = _to_numeric(_first_column(frame, ("root_shell",)), default=0.0)
    converted["su_attempted"] = _to_numeric(_first_column(frame, ("su_attempted",)), default=0.0)
    converted["num_root"] = _to_numeric(_first_column(frame, ("num_root",)), default=0.0)
    converted["num_file_creations"] = _to_numeric(
        _first_column(frame, ("num_file_creations",)),
        default=0.0,
    )
    converted["num_shells"] = _to_numeric(_first_column(frame, ("num_shells",)), default=0.0)
    converted["num_access_files"] = _to_numeric(
        _first_column(frame, ("num_access_files",)),
        default=0.0,
    )
    converted["num_outbound_cmds"] = 0.0
    converted["is_host_login"] = 0.0
    converted["is_guest_login"] = _to_numeric(_first_column(frame, ("is_guest_login",)), default=0.0)

    converted["count"] = _to_numeric(
        _first_column(frame, ("flow packets/s", "flow pkts/s", "tot fwd pkts")),
        default=0.0,
    ).clip(0.0, 511.0)
    converted["srv_count"] = _to_numeric(
        _first_column(frame, ("fwd packets/s", "tot fwd pkts")),
        default=0.0,
    ).clip(0.0, 511.0)

    converted["serror_rate"] = _to_rate(_first_column(frame, ("syn flag cnt", "serror_rate")))
    converted["srv_serror_rate"] = _to_rate(
        _first_column(frame, ("fwd psh flags", "srv_serror_rate"))
    )
    converted["rerror_rate"] = _to_rate(_first_column(frame, ("rst flag cnt", "rerror_rate")))
    converted["srv_rerror_rate"] = _to_rate(
        _first_column(frame, ("bwd psh flags", "srv_rerror_rate"))
    )

    down_up = _to_numeric(_first_column(frame, ("down/up ratio",)), default=0.0)
    converted["same_srv_rate"] = (1.0 - (down_up / (1.0 + down_up))).clip(0.0, 1.0)
    converted["diff_srv_rate"] = _to_rate(
        _first_column(frame, ("flow iat std", "flow iat mean", "diff_srv_rate"))
    )
    converted["srv_diff_host_rate"] = _to_rate(
        _first_column(frame, ("flow iat std", "srv_diff_host_rate"))
    )

    converted["dst_host_count"] = _to_numeric(
        _first_column(frame, ("tot fwd pkts", "dst_host_count")),
        default=0.0,
    ).clip(0.0, 255.0)
    converted["dst_host_srv_count"] = _to_numeric(
        _first_column(frame, ("tot bwd pkts", "dst_host_srv_count")),
        default=0.0,
    ).clip(0.0, 255.0)

    converted["dst_host_same_srv_rate"] = _to_rate(
        _first_column(frame, ("average packet size", "dst_host_same_srv_rate"))
    )
    converted["dst_host_diff_srv_rate"] = _to_rate(
        _first_column(frame, ("packet length variance", "dst_host_diff_srv_rate"))
    )
    converted["dst_host_same_src_port_rate"] = _to_rate(
        _first_column(frame, ("fwd packets/s", "dst_host_same_src_port_rate"))
    )
    converted["dst_host_srv_diff_host_rate"] = _to_rate(
        _first_column(frame, ("bwd packets/s", "dst_host_srv_diff_host_rate"))
    )
    converted["dst_host_serror_rate"] = converted["serror_rate"]
    converted["dst_host_srv_serror_rate"] = converted["srv_serror_rate"]
    converted["dst_host_rerror_rate"] = converted["rerror_rate"]
    converted["dst_host_srv_rerror_rate"] = converted["srv_rerror_rate"]

    if TARGET_COLUMN in frame.columns:
        converted[TARGET_COLUMN] = frame[TARGET_COLUMN].astype(str)
    return converted


def detect_dataset_profile(df: pd.DataFrame) -> str:
    normalized = _normalize_columns(df)
    columns = set(normalized.columns)

    nsl_score = len(columns.intersection(set(FEATURE_COLUMNS)))
    cicids_score = len(columns.intersection(CICIDS_HINT_COLUMNS))

    if nsl_score >= 10:
        return "nsl_kdd"
    if cicids_score >= 4:
        return "cicids2017"
    if len(columns) in {len(FULL_COLUMNS), len(FULL_COLUMNS_WITH_DIFFICULTY), len(FEATURE_COLUMNS)}:
        return "nsl_kdd"
    return "generic"


def map_attack_category(raw_label: str) -> str:
    clean = str(raw_label).strip().lower().replace(".", "")
    if clean in {"normal", "normal_traffic", "benign"}:
        return "Normal Traffic"

    for category, signatures in ATTACK_GROUPS.items():
        if clean in signatures:
            return category

    keyword_rules = {
        "DoS Attack": ("dos", "ddos", "flood", "slowloris", "slowhttptest", "hulk", "goldeneye", "heartbleed"),
        "Probe Attack": ("probe", "scan", "sweep", "portscan", "recon", "infiltration"),
        "R2L Attack": ("r2l", "password", "ftp", "imap", "mail", "patator", "brute", "bot", "web attack", "xss"),
        "U2R Attack": ("u2r", "root", "overflow", "xterm", "sql", "command injection", "backdoor"),
    }
    for category, keywords in keyword_rules.items():
        if any(keyword in clean for keyword in keywords):
            return category

    # Unknown attacks are treated as Probe by default for conservative detection.
    return "Probe Attack"


def sanitize_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    frame = _normalize_columns(df)
    profile = detect_dataset_profile(frame)

    if profile == "cicids2017":
        frame = _convert_cicids_to_nsl(frame)

    for feature in FEATURE_COLUMNS:
        if feature not in frame.columns:
            frame[feature] = np.nan

    features = frame[FEATURE_COLUMNS].copy()
    for column in CATEGORICAL_COLUMNS:
        features[column] = (
            features[column]
            .replace({np.nan: "unknown"})
            .astype(str)
            .str.strip()
            .replace({"": "unknown"})
        )
    for column in NUMERIC_COLUMNS:
        features[column] = pd.to_numeric(features[column], errors="coerce").fillna(0.0)

    return features


def prepare_training_data_with_profile(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, str]:
    frame = _normalize_columns(df)
    dataset_profile = detect_dataset_profile(frame)

    if dataset_profile == "cicids2017":
        frame = _convert_cicids_to_nsl(frame)

    if TARGET_COLUMN not in frame.columns:
        raise ValueError(
            "Training file must contain a label column or match NSL-KDD/CICIDS format."
        )

    if DIFFICULTY_COLUMN in frame.columns:
        frame = frame.drop(columns=[DIFFICULTY_COLUMN], errors="ignore")

    X = sanitize_feature_frame(frame)
    y_raw = frame[TARGET_COLUMN].fillna("normal").astype(str)
    y = y_raw.map(map_attack_category)

    if y.empty:
        raise ValueError("Training labels are empty after preprocessing.")

    y = y.where(y.isin(CLASS_NAMES), "Probe Attack")
    return X, y, dataset_profile


def prepare_training_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    X, y, _ = prepare_training_data_with_profile(df)
    return X, y


def prepare_inference_data_with_profile(df: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    frame = _normalize_columns(df)
    dataset_profile = detect_dataset_profile(frame)
    features = sanitize_feature_frame(frame)
    return features, dataset_profile


def prepare_inference_data(df: pd.DataFrame) -> pd.DataFrame:
    features, _ = prepare_inference_data_with_profile(df)
    return features
