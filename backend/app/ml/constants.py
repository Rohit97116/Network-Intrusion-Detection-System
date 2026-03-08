from __future__ import annotations

FEATURE_COLUMNS: list[str] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

TARGET_COLUMN = "label"
DIFFICULTY_COLUMN = "difficulty"

FULL_COLUMNS = FEATURE_COLUMNS + [TARGET_COLUMN]
FULL_COLUMNS_WITH_DIFFICULTY = FULL_COLUMNS + [DIFFICULTY_COLUMN]

CATEGORICAL_COLUMNS: list[str] = ["protocol_type", "service", "flag"]
NUMERIC_COLUMNS: list[str] = [col for col in FEATURE_COLUMNS if col not in CATEGORICAL_COLUMNS]

CLASS_NAMES: list[str] = [
    "Normal Traffic",
    "DoS Attack",
    "Probe Attack",
    "R2L Attack",
    "U2R Attack",
]

ATTACK_GROUPS: dict[str, set[str]] = {
    "DoS Attack": {
        "back",
        "land",
        "neptune",
        "pod",
        "smurf",
        "teardrop",
        "apache2",
        "udpstorm",
        "processtable",
        "mailbomb",
        "worm",
        "dos",
        "ddos",
    },
    "Probe Attack": {
        "satan",
        "ipsweep",
        "nmap",
        "portsweep",
        "mscan",
        "saint",
        "probe",
        "scan",
    },
    "R2L Attack": {
        "guess_passwd",
        "ftp_write",
        "imap",
        "phf",
        "multihop",
        "warezmaster",
        "warezclient",
        "spy",
        "xlock",
        "xsnoop",
        "snmpguess",
        "snmpgetattack",
        "httptunnel",
        "sendmail",
        "named",
        "r2l",
    },
    "U2R Attack": {
        "buffer_overflow",
        "loadmodule",
        "perl",
        "rootkit",
        "ps",
        "sqlattack",
        "xterm",
        "u2r",
    },
}
