#!/usr/bin/env python3

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


DEFAULT_REPORT_CANDIDATES = (
    Path("/var/log/sniffster.traffic.log"),
    Path("sniffster.traffic.log"),
    Path("traffic.log"),
)

TIMESTAMP_FIELDS = ("first_ts", "latest_ts")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read newline-delimited JSON report data and rewrite known timestamp "
            "fields into human-readable local time strings."
        )
    )
    parser.add_argument(
        "report",
        nargs="?",
        help="Path to the report file. If omitted, known default locations are probed.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the transformed output to this file instead of stdout.",
    )
    return parser.parse_args()


def resolve_report_path(raw_path: str | None) -> Path:
    if raw_path:
        report_path = Path(raw_path).expanduser()
        if not report_path.is_file():
            raise FileNotFoundError(f"report file not found: {report_path}")
        return report_path

    for candidate in DEFAULT_REPORT_CANDIDATES:
        if candidate.is_file():
            return candidate

    searched = ", ".join(str(path) for path in DEFAULT_REPORT_CANDIDATES)
    raise FileNotFoundError(
        "report file not specified and none of the default locations exist: "
        f"{searched}"
    )


def detect_epoch_unit(value: int) -> tuple[int, int]:
    abs_value = abs(value)
    if abs_value >= 10**17:
        return 1_000_000_000, 9
    if abs_value >= 10**14:
        return 1_000_000, 6
    if abs_value >= 10**11:
        return 1_000, 3
    return 1, 0


def format_epoch_local(value: int) -> str:
    scale, fractional_digits = detect_epoch_unit(value)
    whole_seconds, fraction = divmod(value, scale)
    local_dt = datetime.fromtimestamp(whole_seconds).astimezone()
    base = local_dt.strftime("%Y-%m-%d %H:%M:%S")
    offset = local_dt.strftime("%z")

    if fractional_digits == 0:
        return f"{base}{offset}"

    return f"{base}.{fraction:0{fractional_digits}d}{offset}"


def rewrite_timestamp_fields(payload: dict[str, object]) -> dict[str, object]:
    rewritten = dict(payload)
    for field in TIMESTAMP_FIELDS:
        value = rewritten.get(field)
        if isinstance(value, int):
            rewritten[field] = format_epoch_local(value)
    return rewritten


def open_output(path: str | None):
    if path is None:
        return sys.stdout
    return open(path, "w", encoding="utf-8")


def main() -> int:
    args = parse_args()
    report_path = resolve_report_path(args.report)

    try:
        with report_path.open("r", encoding="utf-8") as src:
            with open_output(args.output) as dst:
                for line_number, raw_line in enumerate(src, start=1):
                    line = raw_line.rstrip("\n")
                    if not line:
                        continue

                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"{report_path}:{line_number}: invalid JSON input"
                        ) from exc

                    if not isinstance(payload, dict):
                        raise ValueError(
                            f"{report_path}:{line_number}: expected a JSON object per line"
                        )

                    dst.write(json.dumps(rewrite_timestamp_fields(payload)))
                    dst.write("\n")
    except BrokenPipeError:
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
