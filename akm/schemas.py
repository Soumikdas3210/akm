"""
Output contracts — FROZEN in Week 1 and sent to Member D (Execution Plan §2.5).

D builds all plotting scripts against these exact headers using fake data,
so that the day real CSVs appear, `python make_figures.py` just works.
Changing a column name after Week 1 breaks D's work: don't, or tell D first.
"""
import csv
from pathlib import Path

SCORES_COLUMNS = [
    "run_id", "seed", "N", "size", "tau", "k", "fault", "eps", "verifier",
    "mode", "trial", "verdict", "tp", "fp", "fn", "detected",
]
TIMINGS_COLUMNS = [
    "run_id", "phase", "verifier", "N", "size", "tau", "fsync_policy", "rep",
    "wall_s", "cpu_s", "peak_rss_mb",
]
STORAGE_COLUMNS = [
    "run_id", "N", "size", "tau", "verifier",
    "tuple_bytes_per_rec", "receipt_bytes_per_rec", "merkle_bytes_per_rec",
    "total_bytes_per_rec", "pct_payload", "pct_tuple",
]


def append_row(path: str | Path, columns: list[str], row: dict) -> None:
    """Append one row, writing the header first if the file is new.
    Refuses rows with missing or extra keys, so a typo can't silently corrupt a CSV."""
    missing = set(columns) - row.keys()
    extra = row.keys() - set(columns)
    if missing or extra:
        raise ValueError(f"bad row: missing={missing} extra={extra}")
    path = Path(path)
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        if new:
            w.writeheader()
        w.writerow(row)


def append_rows(path: str | Path, columns: list[str], rows: list[dict]) -> None:
    """Bulk version of append_row (RQ4 writes ~72,000 rows). Same checks."""
    for row in rows:
        missing, extra = set(columns) - row.keys(), row.keys() - set(columns)
        if missing or extra:
            raise ValueError(f"bad row: missing={missing} extra={extra}")
    path = Path(path)
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        if new:
            w.writeheader()
        w.writerows(rows)
