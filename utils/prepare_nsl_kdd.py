from __future__ import annotations

import argparse
import csv
import urllib.request
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
    "label",
    "difficulty",
]

DEFAULT_SOURCES = {
    "train": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
    "test": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt",
}


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, destination)  # noqa: S310


def convert_to_csv(raw_file: Path, csv_file: Path) -> None:
    with raw_file.open("r", encoding="utf-8", newline="") as source, csv_file.open(
        "w", encoding="utf-8", newline=""
    ) as target:
        writer = csv.writer(target)
        writer.writerow(FEATURE_COLUMNS)
        for line in source:
            values = [item.strip() for item in line.strip().split(",")]
            if len(values) == len(FEATURE_COLUMNS):
                writer.writerow(values)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download and prepare NSL-KDD dataset files.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("datasets"),
        help="Folder where dataset files will be stored",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    train_raw = out_dir / "KDDTrain+.txt"
    test_raw = out_dir / "KDDTest+.txt"
    train_csv = out_dir / "KDDTrain+.csv"
    test_csv = out_dir / "KDDTest+.csv"

    print("Downloading NSL-KDD source files...")
    download_file(DEFAULT_SOURCES["train"], train_raw)
    download_file(DEFAULT_SOURCES["test"], test_raw)

    print("Converting to headered CSV files...")
    convert_to_csv(train_raw, train_csv)
    convert_to_csv(test_raw, test_csv)

    print(f"Saved: {train_csv}")
    print(f"Saved: {test_csv}")


if __name__ == "__main__":
    main()
