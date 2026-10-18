"""Run configured Bias and Spike attacks without changing the shared engine."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

import pandas as pd

from attack_engine import EVENT_COLUMNS, LABEL_COLUMNS, TARGET_COLUMN, attack_data


PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_VERSION = 1
ONE_HOUR = pd.Timedelta(hours=1)
OUTPUT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def _project_path(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty path string")
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _range(value, name, *, integer=False):
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError(f"{name} must be a two-item range")
    low, high = value
    if integer:
        if any(isinstance(item, bool) or not isinstance(item, int) for item in value):
            raise ValueError(f"{name} must contain integers")
        if low < 1 or high < low:
            raise ValueError(f"{name} must satisfy 1 <= minimum <= maximum")
    else:
        if any(isinstance(item, bool) for item in value):
            raise ValueError(f"{name} must contain numbers, not booleans")
        try:
            low, high = float(low), float(high)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must contain numbers") from exc
        if not math.isfinite(low) or not math.isfinite(high) or high < low:
            raise ValueError(f"{name} must contain finite values with minimum <= maximum")
    return [low, high]


def validate_config(config):
    """Check the runner configuration without reading or changing datasets."""
    if not isinstance(config, dict):
        raise ValueError("configuration root must be a JSON object")
    if config.get("config_version") != CONFIG_VERSION:
        raise ValueError(f"config_version must be {CONFIG_VERSION}")
    if config.get("target_column") != TARGET_COLUMN:
        raise ValueError(f"target_column must be {TARGET_COLUMN}")
    _project_path(config.get("input_data"), "input_data")
    _project_path(config.get("output_dir"), "output_dir")

    profiles = config.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("profiles must be a non-empty JSON object")
    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ValueError(f"profile {name!r} must be a JSON object")
        if name not in {"bias", "spike"}:
            raise ValueError(f"unsupported profile name {name!r}; use 'bias' or 'spike'")
        if not isinstance(profile.get("enabled"), bool):
            raise ValueError(f"profile {name!r} must set enabled to true or false")
        mode = profile.get("mode")
        if mode not in {"constant_offset", "spike"}:
            raise ValueError(f"profile {name!r} has unsupported mode {mode!r}")
        if profile.get("target_column", TARGET_COLUMN) != TARGET_COLUMN:
            raise ValueError(f"profile {name!r} target_column must be {TARGET_COLUMN}")
        years = profile.get("years")
        if not isinstance(years, list) or not years:
            raise ValueError(f"profile {name!r} must have a non-empty years list")
        if any(isinstance(year, bool) or not isinstance(year, int) or year not in (2024, 2025) for year in years):
            raise ValueError(f"profile {name!r} years may contain only 2024 and/or 2025")
        if len(set(years)) != len(years):
            raise ValueError(f"profile {name!r} years must not contain duplicates")

        # Disabled profiles may intentionally be incomplete until a scenario is approved.
        if not profile["enabled"]:
            continue
        _range(profile.get("duration_hours_range"), f"profiles.{name}.duration_hours_range", integer=True)
        if mode == "constant_offset":
            _range(profile.get("offset_range"), f"profiles.{name}.offset_range")
        else:
            _range(profile.get("spike_count_range"), f"profiles.{name}.spike_count_range", integer=True)
            _range(profile.get("spike_magnitude_range"), f"profiles.{name}.spike_magnitude_range")

    runs = config.get("runs")
    if not isinstance(runs, list):
        raise ValueError("runs must be a JSON list; use an empty list until allocation is specified")
    seen_ids = set()
    for position, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"runs[{position}] must be a JSON object")
        run_id = run.get("id")
        profile_name = run.get("profile")
        if not isinstance(run_id, str) or not OUTPUT_ID_RE.fullmatch(run_id):
            raise ValueError(f"runs[{position}].id must contain only letters, digits, underscore, or hyphen")
        if run_id in seen_ids:
            raise ValueError(f"run id {run_id!r} is duplicated")
        seen_ids.add(run_id)
        if profile_name not in profiles:
            raise ValueError(f"runs[{position}] references unknown profile {profile_name!r}")
        if not profiles[profile_name]["enabled"]:
            raise ValueError(f"runs[{position}] references disabled profile {profile_name!r}")
        if not isinstance(run.get("station"), str) or not OUTPUT_ID_RE.fullmatch(run["station"]):
            raise ValueError(f"runs[{position}].station must be a safe station identifier")
        seed = run.get("seed")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError(f"runs[{position}].seed must be an integer")
        year = run.get("year")
        if isinstance(year, bool) or not isinstance(year, int) or year not in profiles[profile_name]["years"]:
            raise ValueError(
                f"runs[{position}].year must be one of profiles.{profile_name}.years"
            )
    return config


def load_config(path):
    """Read and validate a UTF-8 JSON runner configuration."""
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = PROJECT_ROOT / config_path
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read JSON configuration {config_path}: {exc}") from exc
    return validate_config(config)


def _read_clean(path):
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    raise ValueError("input_data must point to a .parquet or .csv file")


def _run_params(profile, run):
    params = {
        key: value
        for key, value in profile.items()
        if key not in {"enabled", "target_column", "description"}
    }
    params.update(
        {
            "attack_type": "bias",
            "station": run["station"],
            "seed": run["seed"],
            "years": [run["year"]],
            "run_config_id": run["id"],
        }
    )
    return params


def _diagnostics(clean_data, params):
    """Count observed missing values, timestamp gaps, and bound-blocked readings.

    These counts describe contributing conditions; they do not claim a single
    cause when the engine reports that no feasible window exists.
    """
    station_rows = clean_data.loc[clean_data["station"].eq(params["station"])].copy()
    if station_rows.empty:
        return {"station_rows": 0, "missing_target_rows": 0, "hourly_gaps": 0, "bound_blocked_rows": 0}
    parsed_time = pd.to_datetime(station_rows["time"], errors="coerce", utc=True)
    year_mask = parsed_time.dt.year.isin(params["years"])
    selected = station_rows.loc[year_mask].copy()
    selected_times = parsed_time.loc[year_mask]
    selected = selected.assign(_time=selected_times.to_numpy())
    selected = selected.sort_values("_time")
    missing = selected[TARGET_COLUMN].isna()
    gaps = int((selected["_time"].diff().dropna() != ONE_HOUR).sum())

    low, high = params.get("offset_range", params.get("spike_magnitude_range", [0, 0]))
    try:
        low, high = float(low), float(high)
    except (TypeError, ValueError):
        low, high = 0.0, 0.0
    valid_values = pd.to_numeric(selected[TARGET_COLUMN], errors="coerce")
    candidate_offsets = [low, high]
    blocked = 0
    for value in valid_values.dropna().tolist():
        possible = False
        for offset in candidate_offsets:
            updated = round((float(value) + offset) * 1000) / 1000
            if 0.0 <= updated <= 0.65 and updated != float(value):
                possible = True
                break
        if not possible:
            blocked += 1
    return {
        "station_rows": int(len(selected)),
        "missing_target_rows": int(missing.sum()),
        "hourly_gaps": gaps,
        "bound_blocked_rows_at_range_endpoints": blocked,
    }


def _generate_run(clean_data, run, profile):
    params = _run_params(profile, run)
    try:
        attacked, labels, event = attack_data(clean_data, params)
    except ValueError as exc:
        return ({
            "id": run["id"],
            "station": run["station"],
            "year": run["year"],
            "profile": run["profile"],
            "status": "not_applied",
            "reason": str(exc),
            "diagnostics": _diagnostics(clean_data, params),
            "changed_rows": 0,
        }, None, None, None)

    changed_rows = int(labels["is_attacked"].sum())
    event_params = json.loads(event["params_json"])
    expected_rows = (
        event_params["selected_duration_hours"]
        if params["mode"] == "constant_offset"
        else event_params["selected_spike_count"]
    )
    partial = changed_rows != expected_rows
    report = {
        "id": run["id"],
        "station": run["station"],
        "year": run["year"],
        "profile": run["profile"],
        "status": "partial" if partial else "applied",
        "changed_rows": changed_rows,
        "expected_changed_rows": int(expected_rows),
        "attack_run_id": event["attack_run_id"],
    }
    return report, attacked, labels, event


def run_config(config, clean_data=None):
    """Run explicitly configured profiles and return a per-station report."""
    validate_config(config)
    if not config["runs"]:
        return {
            "configured_runs": 0,
            "applied_runs": 0,
            "not_applied_runs": 0,
            "partial_runs": 0,
            "stations": {},
            "message": "No runs are configured; no attack dataset files were written.",
        }
    if clean_data is None:
        clean_data = _read_clean(_project_path(config["input_data"], "input_data"))
    if "annee" not in clean_data.columns:
        raise ValueError("input data must include the interval-start year column 'annee'")
    # A fresh index lets us copy individual changed cells back without relying
    # on the caller's index being unique. The caller's DataFrame is untouched.
    source = clean_data.reset_index(drop=True).copy(deep=True)
    results = []
    groups = {}
    event_rows = []
    for run in config["runs"]:
        key = (run["station"], run["year"])
        if key not in groups:
            base = source.loc[
                source["station"].eq(run["station"]) & source["annee"].eq(run["year"])
            ].copy()
            groups[key] = {
                "base": base,
                "attacked": base.copy(deep=True),
                "labels": pd.DataFrame(
                    {
                        "is_attacked": pd.Series(False, index=base.index, dtype=bool),
                        "attack_type": pd.Series("", index=base.index, dtype="string"),
                        "attack_run_id": pd.Series("", index=base.index, dtype="string"),
                    },
                    index=base.index,
                    columns=LABEL_COLUMNS,
                ),
                "reserved": set(),
                "events": [],
            }
        group = groups[key]
        available = group["base"].drop(index=list(group["reserved"]))
        report, attacked, labels, event = _generate_run(
            available, run, config["profiles"][run["profile"]]
        )
        if report["status"] == "partial":
            report["reason"] = "engine changed fewer readings than the selected attack parameters require"
        if report["status"] != "applied":
            results.append(report)
            continue
        event_params = json.loads(event["params_json"])
        reserve_start = event_params.get("selected_window_start", event["start"])
        reserve_end = event_params.get("selected_window_end", event["end"])
        times = pd.to_datetime(group["base"]["time"], errors="coerce", utc=True)
        reserved_now = set(group["base"].index[
            times.between(pd.Timestamp(reserve_start, tz="UTC"), pd.Timestamp(reserve_end, tz="UTC"))
        ])
        changed_index = labels.index[labels["is_attacked"].astype(bool)]
        if not set(changed_index).issubset(reserved_now):
            raise RuntimeError("engine changed a reading outside its reported attack window")
        group["reserved"].update(reserved_now)
        group["attacked"].loc[changed_index, TARGET_COLUMN] = attacked.loc[changed_index, TARGET_COLUMN]
        group["labels"].loc[changed_index, "is_attacked"] = True
        group["labels"].loc[changed_index, "attack_type"] = str(event["attack_type"])
        group["labels"].loc[changed_index, "attack_run_id"] = str(event["attack_run_id"])
        group["events"].append(event)
        event_rows.append(event)
        results.append(report)

    output_dir = _project_path(config["output_dir"], "output_dir")
    applied_groups = [(key, group) for key, group in sorted(groups.items()) if group["events"]]
    output_paths = [output_dir / f"{station}_{year}.csv" for (station, year), _ in applied_groups]
    if event_rows:
        output_paths.append(output_dir / "attack_events.csv")
    # Check the whole batch before creating any file. Exclusive create also
    # protects a destination that appears between this check and writing.
    existing = [path for path in output_paths if path.exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite existing output: {existing[0]}")
    if output_paths:
        output_dir.mkdir(parents=True, exist_ok=True)
    for (station, year), group in applied_groups:
        output_path = output_dir / f"{station}_{year}.csv"
        with output_path.open("x", encoding="utf-8", newline="") as handle:
            pd.concat([group["attacked"], group["labels"]], axis=1).to_csv(handle, index=False)
    if event_rows:
        with (output_dir / "attack_events.csv").open("x", encoding="utf-8", newline="") as handle:
            pd.DataFrame(event_rows, columns=EVENT_COLUMNS).to_csv(handle, index=False)

    station_report = {}
    for station in sorted({result["station"] for result in results}):
        station_runs = [result for result in results if result["station"] == station]
        station_report[station] = {
            "bias_runs_configured": sum(result["profile"] == "bias" for result in station_runs),
            "spike_runs_configured": sum(result["profile"] == "spike" for result in station_runs),
            "successfully_applied": sum(result["status"] == "applied" for result in station_runs),
            "not_applied": sum(result["status"] == "not_applied" for result in station_runs),
            "partial": sum(result["status"] == "partial" for result in station_runs),
            "runs": station_runs,
        }
    return {
        "configured_runs": len(results),
        "applied_runs": sum(result["status"] == "applied" for result in results),
        "not_applied_runs": sum(result["status"] == "not_applied" for result in results),
        "partial_runs": sum(result["status"] == "partial" for result in results),
        "output_files": [
            str(path.relative_to(PROJECT_ROOT)) if path.is_relative_to(PROJECT_ROOT) else str(path)
            for path in output_paths
        ],
        "stations": station_report,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="path to the JSON run configuration")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        report = run_config(config)
    except (ValueError, OSError, FileExistsError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
