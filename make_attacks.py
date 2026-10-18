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


def _write_run(clean_data, config, run, profile):
    params = _run_params(profile, run)
    try:
        attacked, labels, event = attack_data(clean_data, params)
    except ValueError as exc:
        return {
            "id": run["id"],
            "station": run["station"],
            "profile": run["profile"],
            "status": "not_applied",
            "reason": str(exc),
            "diagnostics": _diagnostics(clean_data, params),
            "changed_rows": 0,
        }

    changed_rows = int(labels["is_attacked"].sum())
    event_params = json.loads(event["params_json"])
    expected_rows = (
        event_params["selected_duration_hours"]
        if params["mode"] == "constant_offset"
        else event_params["selected_spike_count"]
    )
    partial = changed_rows != expected_rows
    output_dir = _project_path(config["output_dir"], "output_dir")
    stem = f"{params['mode']}_provisional_v2_{run['station']}_{run['id']}"
    observation_path = output_dir / f"{stem}.csv"
    event_path = output_dir / f"{stem}_events.csv"
    if observation_path.exists() or event_path.exists():
        raise FileExistsError(
            f"refusing to overwrite existing run output {observation_path} or {event_path}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    combined = pd.concat([attacked, labels], axis=1)
    combined.to_csv(observation_path, index=False)
    pd.DataFrame([event], columns=EVENT_COLUMNS).to_csv(event_path, index=False)
    return {
        "id": run["id"],
        "station": run["station"],
        "profile": run["profile"],
        "status": "partial" if partial else "applied",
        "changed_rows": changed_rows,
        "expected_changed_rows": int(expected_rows),
        "observation_file": str(observation_path.relative_to(PROJECT_ROOT)) if observation_path.is_relative_to(PROJECT_ROOT) else str(observation_path),
        "event_file": str(event_path.relative_to(PROJECT_ROOT)) if event_path.is_relative_to(PROJECT_ROOT) else str(event_path),
        "attack_run_id": event["attack_run_id"],
    }


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
    results = []
    for run in config["runs"]:
        profile = config["profiles"][run["profile"]]
        results.append(_write_run(clean_data, config, run, profile))

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
