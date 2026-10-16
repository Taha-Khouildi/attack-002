"""Small, deterministic Bias attacks on the protected 5 cm soil-moisture reading.

Labels are returned separately so callers can keep them out of signing and
detector inputs. Supported Bias modes are constant offsets and isolated spikes.
"""

from __future__ import annotations

import json
import hashlib
import math
import random
from bisect import bisect_left
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP

import pandas as pd


ENGINE_VERSION = "0.1.0"
TARGET_COLUMN = "SOIL_MOISTURE_5"
LABEL_COLUMNS = ["is_attacked", "attack_type", "attack_run_id"]
EVENT_COLUMNS = [
    "attack_run_id",
    "station",
    "attack_type",
    "target_columns",
    "start",
    "end",
    "params_json",
    "seed",
    "engine_version",
]
RESOLUTION = Decimal("0.001")
LOWER_BOUND = Decimal("0")
UPPER_BOUND = Decimal("0.65")
SUPPORTED_YEARS = {2024, 2025}
_ONE_HOUR = pd.Timedelta(hours=1)


def _integer_range(value, name):
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ValueError(f"{name} must be a two-item [minimum, maximum] range")
    low, high = value
    if isinstance(low, bool) or isinstance(high, bool):
        raise ValueError(f"{name} values must be integers")
    if not isinstance(low, int) or not isinstance(high, int):
        raise ValueError(f"{name} values must be integers")
    if low < 1 or high < low:
        raise ValueError(f"{name} must satisfy 1 <= minimum <= maximum")
    return low, high


def _decimal_range(value, name):
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ValueError(f"{name} must be a two-item [minimum, maximum] range")
    try:
        low, high = (Decimal(str(item)) for item in value)
    except Exception as exc:
        raise ValueError(f"{name} values must be finite numbers") from exc
    if not low.is_finite() or not high.is_finite() or high < low:
        raise ValueError(f"{name} must contain finite values with minimum <= maximum")
    low_tick = int((low / RESOLUTION).to_integral_value(rounding=ROUND_CEILING))
    high_tick = int((high / RESOLUTION).to_integral_value(rounding=ROUND_FLOOR))
    if low_tick > high_tick:
        raise ValueError(f"{name} contains no values at the 0.001 resolution")
    return low, high, low_tick, high_tick


def _choose_nonzero_offset(rng, low_tick, high_tick):
    """Choose uniformly from the 0.001 grid in a range, excluding zero."""
    count = high_tick - low_tick + 1
    if low_tick <= 0 <= high_tick:
        count -= 1
    if count <= 0:
        raise ValueError("offset_range must allow a non-zero offset at 0.001 resolution")

    choice = rng.randrange(count)
    if low_tick <= 0 <= high_tick:
        zero_index = -low_tick
        if choice >= zero_index:
            choice += 1
    return Decimal(low_tick + choice) * RESOLUTION


def _valid_runs(clean_data, station, years, include_missing=False):
    station_values = clean_data["station"]
    station_positions = [
        pos for pos, value in enumerate(station_values.tolist()) if value == station
    ]
    if not station_positions:
        raise ValueError(f"station {station!r} is not present in clean_data")

    times = pd.to_datetime(clean_data["time"], errors="coerce", utc=True)
    moisture = pd.to_numeric(clean_data[TARGET_COLUMN], errors="coerce")
    raw_moisture = clean_data[TARGET_COLUMN]
    bad_numeric = raw_moisture.notna() & moisture.isna()
    if bad_numeric.any():
        raise ValueError(f"{TARGET_COLUMN} contains non-numeric readings")

    selected_times = [times.iloc[pos] for pos in station_positions]
    if any(pd.isna(value) for value in selected_times):
        raise ValueError(f"station {station!r} has an invalid time value")
    if len(set(selected_times)) != len(selected_times):
        raise ValueError(f"station {station!r} has duplicate timestamps")

    by_year = {year: [] for year in years}
    for pos, timestamp in zip(station_positions, selected_times):
        if timestamp.year in by_year:
            by_year[timestamp.year].append((timestamp, pos))

    runs = []
    for year in years:
        entries = sorted(by_year[year], key=lambda pair: pair[0])
        current = []
        previous_time = None
        for timestamp, pos in entries:
            value = moisture.iloc[pos]
            is_valid_value = pd.notna(value) and math.isfinite(float(value))
            if not is_valid_value:
                if include_missing:
                    if current and timestamp - previous_time != _ONE_HOUR:
                        runs.append(current)
                        current = []
                    current.append((timestamp, pos))
                    previous_time = timestamp
                    continue
                if current:
                    runs.append(current)
                    current = []
                previous_time = None
                continue

            if current and timestamp - previous_time != _ONE_HOUR:
                runs.append(current)
                current = []
            current.append((timestamp, pos))
            previous_time = timestamp
        if current:
            runs.append(current)
    return runs, moisture


def _feasible_runs(runs, moisture, offset):
    """Keep contiguous rows that change and remain inside the temporary bounds."""
    feasible_runs = []
    for run in runs:
        current = []
        for timestamp, pos in run:
            original = Decimal(str(moisture.iloc[pos]))
            updated = (original + offset).quantize(
                RESOLUTION, rounding=ROUND_HALF_UP
            )
            can_attack = (
                LOWER_BOUND <= updated <= UPPER_BOUND and updated != original
            )
            if can_attack:
                current.append((timestamp, pos, updated))
            else:
                if current:
                    feasible_runs.append(current)
                    current = []
        if current:
            feasible_runs.append(current)
    return feasible_runs


def _spike_ticks(original, low_tick, high_tick):
    """Return supplied non-zero magnitude ticks that make this row feasible."""
    feasible = []
    for tick in range(low_tick, high_tick + 1):
        if tick == 0:
            continue
        updated = (original + Decimal(tick) * RESOLUTION).quantize(
            RESOLUTION, rounding=ROUND_HALF_UP
        )
        if LOWER_BOUND <= updated <= UPPER_BOUND and updated != original:
            feasible.append(tick)
    return feasible


def _max_spaced_spikes(entries):
    """Count the most timestamps possible with a full unchanged hour between."""
    count = 0
    previous = None
    for entry in entries:
        timestamp = entry[0]
        if previous is None or timestamp - previous >= 2 * _ONE_HOUR:
            count += 1
            previous = timestamp
    return count


def _choose_spaced_spikes(entries, count, rng):
    """Choose a reproducible feasible set without generating combinations."""
    times = [entry[0] for entry in entries]
    size = len(entries)
    next_index = [
        bisect_left(times, timestamp + 2 * _ONE_HOUR, index + 1)
        for index, timestamp in enumerate(times)
    ]

    best = [0] * (size + 1)
    for index in range(size - 1, -1, -1):
        best[index] = max(best[index + 1], 1 + best[next_index[index]])

    chosen = []
    cursor = 0
    remaining = count
    while remaining:
        options = [
            index
            for index in range(cursor, size)
            if 1 + best[next_index[index]] >= remaining
        ]
        if not options:
            raise RuntimeError("could not select the requested number of spaced spikes")
        selected = rng.choice(options)
        chosen.append(entries[selected])
        cursor = next_index[selected]
        remaining -= 1
    return chosen


def _attack_spike(clean_data, params, station, seed, years, min_duration, max_duration):
    count_low, count_high = _integer_range(
        params.get("spike_count_range"), "spike_count_range"
    )
    _, _, low_tick, high_tick = _decimal_range(
        params.get("spike_magnitude_range"), "spike_magnitude_range"
    )
    if not any(tick != 0 for tick in range(low_tick, high_tick + 1)):
        raise ValueError("spike_magnitude_range must include a non-zero magnitude")
    if count_high > (max_duration + 1) // 2:
        raise ValueError(
            "spike_count_range maximum cannot fit in duration_hours_range with "
            "at least one unchanged hourly reading between spikes"
        )

    rng = random.Random(seed)
    runs, moisture = _valid_runs(clean_data, station, years, include_missing=True)
    spike_runs = []
    longest_run = 0
    for run in runs:
        enriched = []
        for timestamp, pos in run:
            value = moisture.iloc[pos]
            ticks = (
                _spike_ticks(Decimal(str(value)), low_tick, high_tick)
                if pd.notna(value) and math.isfinite(float(value))
                else []
            )
            enriched.append((timestamp, pos, ticks))
        spike_runs.append(enriched)
        longest_run = max(longest_run, len(run))

    max_count_from_data = max(
        (_max_spaced_spikes([entry for entry in run if entry[2]]) for run in spike_runs),
        default=0,
    )
    possible_count_high = min(count_high, (max_duration + 1) // 2, max_count_from_data)
    if possible_count_high < count_low:
        raise ValueError(
            "requested spike count cannot fit the available valid readings with "
            "at least one unchanged hourly reading between spikes"
        )
    spike_count = rng.randint(count_low, possible_count_high)

    duration_ceiling = min(max_duration, longest_run)
    shortest_fitting_duration = max(min_duration, 2 * spike_count - 1)
    durations = list(range(shortest_fitting_duration, duration_ceiling + 1))
    rng.shuffle(durations)
    feasible_windows = []
    selected_duration = None
    for duration in durations:
        windows = []
        for run in spike_runs:
            if len(run) < duration:
                continue
            for start in range(len(run) - duration + 1):
                eligible = [entry for entry in run[start : start + duration] if entry[2]]
                if _max_spaced_spikes(eligible) >= spike_count:
                    windows.append((run, start, eligible))
        if windows:
            feasible_windows = windows
            selected_duration = duration
            break

    if selected_duration is None:
        raise ValueError(
            "no feasible contiguous Spike window satisfies the requested station, "
            "years, duration, magnitude range, count, spacing, and temporary bounds"
        )

    run, window_start, eligible = rng.choice(feasible_windows)
    selected_window = run[window_start : window_start + selected_duration]
    chosen_entries = _choose_spaced_spikes(eligible, spike_count, rng)
    selected_spikes = []
    changed_positions = []
    changed_values = []
    for timestamp, pos, feasible_ticks in chosen_entries:
        tick = rng.choice(feasible_ticks)
        magnitude = Decimal(tick) * RESOLUTION
        original = Decimal(str(moisture.iloc[pos]))
        updated = (original + magnitude).quantize(RESOLUTION, rounding=ROUND_HALF_UP)
        changed_positions.append(pos)
        changed_values.append(float(updated))
        selected_spikes.append(
            {
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "magnitude": float(magnitude),
            }
        )

    first_attack_time = chosen_entries[0][0]
    last_attack_time = chosen_entries[-1][0]
    window_start_time = selected_window[0][0]
    window_end_time = selected_window[-1][0]
    selected_parameters = {
        "station": station,
        "window_start": window_start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "window_end": window_end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_hours": selected_duration,
        "spikes": selected_spikes,
    }
    identity_json = json.dumps(
        {"configuration": params, "selected_parameters": selected_parameters},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    config_hash = hashlib.sha256(identity_json.encode("utf-8")).hexdigest()
    run_id = (
        f"bias-spike-{station}-{first_attack_time.strftime('%Y%m%dT%H%M%S')}-{config_hash}"
    )

    attacked_data = clean_data.copy(deep=True)
    target_position = attacked_data.columns.get_loc(TARGET_COLUMN)
    for pos, value in zip(changed_positions, changed_values):
        attacked_data.iloc[pos, target_position] = value

    attacked_flags = [False] * len(clean_data)
    attack_types = [""] * len(clean_data)
    run_ids = [""] * len(clean_data)
    for pos in changed_positions:
        attacked_flags[pos] = True
        attack_types[pos] = "bias"
        run_ids[pos] = run_id
    labels = pd.DataFrame(
        {
            "is_attacked": attacked_flags,
            "attack_type": attack_types,
            "attack_run_id": run_ids,
        },
        index=clean_data.index,
        columns=LABEL_COLUMNS,
    )

    chosen_params = {
        "attack_type": "bias",
        "mode": "spike",
        "station": station,
        "seed": seed,
        "years": list(years),
        "duration_hours_range": [min_duration, max_duration],
        "selected_window_start": selected_parameters["window_start"],
        "selected_window_end": selected_parameters["window_end"],
        "selected_duration_hours": selected_duration,
        "spike_count_range": [count_low, count_high],
        "selected_spike_count": spike_count,
        "spike_magnitude_range": [
            float(Decimal(str(params["spike_magnitude_range"][0]))),
            float(Decimal(str(params["spike_magnitude_range"][1]))),
        ],
        "spikes": selected_spikes,
        "configuration": params,
    }
    event = {
        "attack_run_id": run_id,
        "station": station,
        "attack_type": "bias",
        "target_columns": TARGET_COLUMN,
        "start": first_attack_time.strftime("%Y-%m-%d %H:%M:%S"),
        "end": last_attack_time.strftime("%Y-%m-%d %H:%M:%S"),
        "params_json": json.dumps(
            chosen_params,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ),
        "seed": seed,
        "engine_version": ENGINE_VERSION,
    }
    return attacked_data, labels, event


def attack_data(clean_data, params):
    """Return a reproducible Bias copy, separate labels, and event metadata.

    ``params`` must contain ``attack_type="bias"``,
    Use ``mode="constant_offset"`` with an explicit ``offset_range`` or
    ``mode="spike"`` with explicit ``spike_count_range`` and signed
    ``spike_magnitude_range``. Both modes also require ``station``, integer
    ``seed``, a non-empty ``years`` list drawn from 2024 and 2025, and an
    inclusive ``duration_hours_range``. The caller supplies station-derived
    magnitude ranges; this function does not invent them. Spike timestamps
    are selected reproducibly with at least one unchanged hourly reading
    between attacks. It never edits ``clean_data`` or writes an attack file.

    For this phase, output moisture must lie in the intersection of the two
    conflicting contract bounds: 0 through 0.65 inclusive. This temporary
    guard does not resolve that contract disagreement.
    """
    if not isinstance(clean_data, pd.DataFrame):
        raise TypeError("clean_data must be a pandas DataFrame")
    required = {"time", "station", TARGET_COLUMN}
    missing = sorted(required.difference(clean_data.columns))
    if missing:
        raise ValueError(f"clean_data is missing required columns: {missing}")
    if params.get("attack_type") != "bias":
        raise ValueError("supported attack_type is 'bias' only")
    mode = params.get("mode")
    if mode not in {"constant_offset", "spike"}:
        raise ValueError("supported Bias modes are 'constant_offset' and 'spike'")

    station = params.get("station")
    if not isinstance(station, str) or not station:
        raise ValueError("station must be a non-empty string")
    seed = params.get("seed")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")

    years = params.get("years")
    if not isinstance(years, (list, tuple)) or not years:
        raise ValueError("years must be a non-empty list containing 2024 and/or 2025")
    if any(isinstance(year, bool) or not isinstance(year, int) for year in years):
        raise ValueError("years must contain integers")
    if len(set(years)) != len(years) or not set(years).issubset(SUPPORTED_YEARS):
        raise ValueError("years may contain unique values from 2024 and 2025 only")

    min_duration, max_duration = _integer_range(
        params.get("duration_hours_range"), "duration_hours_range"
    )
    if mode == "spike":
        return _attack_spike(
            clean_data, params, station, seed, years, min_duration, max_duration
        )

    _, _, low_tick, high_tick = _decimal_range(
        params.get("offset_range"), "offset_range"
    )

    rng = random.Random(seed)
    offset = _choose_nonzero_offset(rng, low_tick, high_tick)
    runs, moisture = _valid_runs(clean_data, station, years)
    feasible_runs = _feasible_runs(runs, moisture, offset)
    longest_run = max((len(run) for run in feasible_runs), default=0)
    if longest_run < min_duration:
        raise ValueError(
            "no feasible contiguous window satisfies the requested station, years, "
            f"duration, offset, and temporary bounds (minimum duration "
            f"{min_duration} hour(s))"
        )

    duration_high = min(max_duration, longest_run)
    duration = rng.randint(min_duration, duration_high)
    window_count = sum(len(run) - duration + 1 for run in feasible_runs)
    if window_count <= 0:
        raise ValueError("no feasible contiguous window exists for the selected duration")

    # Select one start position by index; do not allocate a list containing
    # every possible window.
    selected_index = rng.randrange(window_count)
    selected_window = None
    for run in feasible_runs:
        starts_in_run = len(run) - duration + 1
        if selected_index < starts_in_run:
            selected_window = run[selected_index : selected_index + duration]
            break
        selected_index -= starts_in_run
    if selected_window is None:  # Defensive check for an internal counting error.
        raise RuntimeError("could not select a feasible attack window")

    changed_positions = [pos for timestamp, pos, updated in selected_window]
    changed_values = [float(updated) for timestamp, pos, updated in selected_window]
    first_changed_time = selected_window[0][0]
    last_changed_time = selected_window[-1][0]

    selected_parameters = {
        "station": station,
        "start": first_changed_time.strftime("%Y-%m-%d %H:%M:%S"),
        "end": last_changed_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_hours": duration,
        "offset": float(offset),
    }
    identity_json = json.dumps(
        {"configuration": params, "selected_parameters": selected_parameters},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    config_hash = hashlib.sha256(identity_json.encode("utf-8")).hexdigest()
    run_id = (
        f"bias-{station}-{first_changed_time.strftime('%Y%m%dT%H%M%S')}-{config_hash}"
    )

    attacked_data = clean_data.copy(deep=True)
    target_position = attacked_data.columns.get_loc(TARGET_COLUMN)
    for pos, value in zip(changed_positions, changed_values):
        attacked_data.iloc[pos, target_position] = value

    attacked_flags = [False] * len(clean_data)
    attack_types = [""] * len(clean_data)
    run_ids = [""] * len(clean_data)
    for pos in changed_positions:
        attacked_flags[pos] = True
        attack_types[pos] = "bias"
        run_ids[pos] = run_id
    labels = pd.DataFrame(
        {
            "is_attacked": attacked_flags,
            "attack_type": attack_types,
            "attack_run_id": run_ids,
        },
        index=clean_data.index,
        columns=LABEL_COLUMNS,
    )

    chosen_params = {
        "attack_type": "bias",
        "mode": "constant_offset",
        "station": station,
        "seed": seed,
        "years": list(years),
        "duration_hours_range": [min_duration, max_duration],
        "offset_range": [
            float(Decimal(str(params["offset_range"][0]))),
            float(Decimal(str(params["offset_range"][1]))),
        ],
        "selected_duration_hours": duration,
        "selected_offset": float(offset),
        "selected_start": selected_parameters["start"],
        "selected_end": selected_parameters["end"],
        "configuration": params,
    }
    event = {
        "attack_run_id": run_id,
        "station": station,
        "attack_type": "bias",
        "target_columns": TARGET_COLUMN,
        "start": first_changed_time.strftime("%Y-%m-%d %H:%M:%S"),
        "end": last_changed_time.strftime("%Y-%m-%d %H:%M:%S"),
        "params_json": json.dumps(
            chosen_params,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ),
        "seed": seed,
        "engine_version": ENGINE_VERSION,
    }
    return attacked_data, labels, event
