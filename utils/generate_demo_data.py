from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

FEATURE_COLUMNS = [
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

LABELS = ["normal", "neptune", "satan", "guess_passwd", "buffer_overflow"]


def bounded(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(value, upper))


def random_row(label: str) -> dict[str, str | int | float]:
    protocol = random.choice(["tcp", "udp", "icmp"])
    service = random.choice(["http", "ftp_data", "private", "domain_u", "smtp", "eco_i"])
    flag = random.choice(["SF", "S0", "REJ", "RSTR", "S1"])

    base = {
        "duration": random.randint(0, 500),
        "protocol_type": protocol,
        "service": service,
        "flag": flag,
        "src_bytes": random.randint(0, 60000),
        "dst_bytes": random.randint(0, 60000),
        "land": random.randint(0, 1),
        "wrong_fragment": random.randint(0, 3),
        "urgent": random.randint(0, 3),
        "hot": random.randint(0, 25),
        "num_failed_logins": random.randint(0, 5),
        "logged_in": random.randint(0, 1),
        "num_compromised": random.randint(0, 15),
        "root_shell": random.randint(0, 1),
        "su_attempted": random.randint(0, 1),
        "num_root": random.randint(0, 15),
        "num_file_creations": random.randint(0, 10),
        "num_shells": random.randint(0, 2),
        "num_access_files": random.randint(0, 4),
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": random.randint(0, 1),
        "count": random.randint(1, 511),
        "srv_count": random.randint(1, 511),
        "serror_rate": round(random.random(), 3),
        "srv_serror_rate": round(random.random(), 3),
        "rerror_rate": round(random.random(), 3),
        "srv_rerror_rate": round(random.random(), 3),
        "same_srv_rate": round(random.random(), 3),
        "diff_srv_rate": round(random.random(), 3),
        "srv_diff_host_rate": round(random.random(), 3),
        "dst_host_count": random.randint(1, 255),
        "dst_host_srv_count": random.randint(1, 255),
        "dst_host_same_srv_rate": round(random.random(), 3),
        "dst_host_diff_srv_rate": round(random.random(), 3),
        "dst_host_same_src_port_rate": round(random.random(), 3),
        "dst_host_srv_diff_host_rate": round(random.random(), 3),
        "dst_host_serror_rate": round(random.random(), 3),
        "dst_host_srv_serror_rate": round(random.random(), 3),
        "dst_host_rerror_rate": round(random.random(), 3),
        "dst_host_srv_rerror_rate": round(random.random(), 3),
    }

    if label == "normal":
        base["logged_in"] = 1
        base["serror_rate"] = round(random.uniform(0.0, 0.15), 3)
        base["srv_serror_rate"] = round(random.uniform(0.0, 0.15), 3)
        base["same_srv_rate"] = round(random.uniform(0.6, 1.0), 3)
        base["diff_srv_rate"] = round(random.uniform(0.0, 0.2), 3)
    elif label == "neptune":
        base["service"] = "private"
        base["flag"] = "S0"
        base["count"] = random.randint(300, 511)
        base["srv_count"] = random.randint(300, 511)
        base["serror_rate"] = round(random.uniform(0.8, 1.0), 3)
        base["srv_serror_rate"] = round(random.uniform(0.8, 1.0), 3)
    elif label == "satan":
        base["service"] = random.choice(["private", "ftp_data", "eco_i"])
        base["diff_srv_rate"] = round(random.uniform(0.5, 1.0), 3)
        base["srv_diff_host_rate"] = round(random.uniform(0.3, 0.9), 3)
        base["rerror_rate"] = round(random.uniform(0.2, 0.8), 3)
    elif label == "guess_passwd":
        base["service"] = random.choice(["ftp_data", "smtp"])
        base["num_failed_logins"] = random.randint(2, 5)
        base["is_guest_login"] = 1
        base["logged_in"] = 0
    elif label == "buffer_overflow":
        base["hot"] = random.randint(10, 30)
        base["num_compromised"] = random.randint(4, 20)
        base["num_root"] = random.randint(5, 20)
        base["root_shell"] = random.randint(0, 1)

    # Keep rates bounded after profile overrides.
    for rate_column in [
        "serror_rate",
        "srv_serror_rate",
        "rerror_rate",
        "srv_rerror_rate",
        "same_srv_rate",
        "diff_srv_rate",
        "srv_diff_host_rate",
        "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
    ]:
        base[rate_column] = round(bounded(float(base[rate_column])), 3)

    return base


def generate_training_csv(path: Path, rows: int) -> None:
    weights = [0.62, 0.18, 0.1, 0.06, 0.04]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEATURE_COLUMNS + ["label"])
        writer.writeheader()
        for _ in range(rows):
            label = random.choices(LABELS, weights=weights, k=1)[0]
            row = random_row(label)
            row["label"] = label
            writer.writerow(row)


def generate_detection_csv(path: Path, rows: int) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()
        for _ in range(rows):
            label = random.choice(LABELS)
            writer.writerow(random_row(label))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate demo NSL-KDD style CSV files.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("datasets"),
        help="Output directory",
    )
    parser.add_argument(
        "--train-rows",
        type=int,
        default=2500,
        help="Number of training records",
    )
    parser.add_argument(
        "--traffic-rows",
        type=int,
        default=800,
        help="Number of traffic records for detection testing",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible datasets",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    random.seed(args.seed)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    training_file = args.out_dir / "sample_training_nsl_kdd.csv"
    traffic_file = args.out_dir / "sample_traffic_nsl_kdd.csv"

    generate_training_csv(training_file, args.train_rows)
    generate_detection_csv(traffic_file, args.traffic_rows)

    print(f"Generated training dataset: {training_file} ({args.train_rows} rows)")
    print(f"Generated traffic dataset : {traffic_file} ({args.traffic_rows} rows)")


if __name__ == "__main__":
    main()
