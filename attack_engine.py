"""Small, deterministic attacks for the TSYP14 sensor-data project.

Bias modes alter the protected 5 cm soil-moisture reading before signing; Replay
duplicates signed packet dictionaries after signing. Labels are returned
separately so callers can keep ground truth out of packets and detector inputs.
"""

from __future__ import annotations

import json
import hashlib
import math
import random
import re
from copy import deepcopy
from bisect import bisect_left
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP
from pathlib import Path

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
PACKET_FIELDS = {
    "v",
    "key_id",
    "station",
    "seq",
    "ts",
    "sent_at",
    "nonce",
    "payload",
    "payload_sha256",
    "sig",
}
PACKET_PAYLOAD_COLUMNS = {
    "T_HR_AVG",
    "T_MAX",
    "T_MIN",
    "P_CALC",
    "SOLARAD",
    "SUR_TEMP",
    "RH_HR_AVG",
    "SOIL_MOISTURE_5",
    "SOIL_MOISTURE_10",
    "SOIL_MOISTURE_20",
    "SOIL_MOISTURE_50",
    "SOIL_MOISTURE_100",
    "SOIL_TEMP_5",
    "SOIL_TEMP_10",
    "SOIL_TEMP_20",
    "SOIL_TEMP_50",
    "SOIL_TEMP_100",
}
_ISO_UTC_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _canonical_packet_bytes(value):
    """Return contract-style canonical JSON bytes for packets and metadata."""
    def clean(item):
        if isinstance(item, float) and math.isnan(item):
            return None
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("canonical JSON object keys must be strings")
            return {key: clean(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [clean(child) for child in item]
        return item

    try:
        return json.dumps(
            clean(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("packets and params must be canonical JSON values") from exc


def _validate_signed_packet(packet, position):
    if not isinstance(packet, dict) or set(packet) != PACKET_FIELDS:
        raise ValueError(
            f"packet at position {position} must have exactly the contracted packet fields"
        )
    for field in ("v", "key_id", "station", "ts", "sent_at", "nonce", "payload_sha256", "sig"):
        if not isinstance(packet[field], str):
            raise ValueError(f"packet at position {position}: {field} must be a string")
    if not packet["station"]:
        raise ValueError(f"packet at position {position}: station must not be empty")
    seq = packet["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError(f"packet at position {position}: seq must be a non-negative integer")
    for field in ("ts", "sent_at"):
        value = packet[field]
        if not _ISO_UTC_Z.fullmatch(value):
            raise ValueError(f"packet at position {position}: {field} must be ISO 8601 UTC with Z")
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError(f"packet at position {position}: {field} is not a valid timestamp") from exc
    if not re.fullmatch(r"[0-9a-f]{32}", packet["nonce"]):
        raise ValueError(f"packet at position {position}: nonce must be 32 lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{64}", packet["payload_sha256"]):
        raise ValueError(f"packet at position {position}: payload_sha256 must be 64 lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{128}", packet["sig"]):
        raise ValueError(f"packet at position {position}: sig must be 128 lowercase hex characters")
    payload = packet["payload"]
    if not isinstance(payload, dict) or set(payload) != PACKET_PAYLOAD_COLUMNS:
        raise ValueError(
            f"packet at position {position}: payload must contain exactly the contract measurement fields"
        )
    _canonical_packet_bytes(packet)
    return pd.Timestamp(packet["ts"])


def _registered_station_keys():
    """Read station/key bindings from the repository's unchanged contract schema."""
    schema_path = Path(__file__).with_name("data_contract.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return {item["station"]: item["key_id"] for item in schema["station_registry"]}


def _tamper_packet(signed_packets, params):
    mode = params.get("mode")
    supported_modes = {
        "payload_only",
        "recompute_hash_keep_signature",
        "signed_header_change",
        "signature_flip",
        "station_swap",
        "drop_field",
    }
    if mode not in supported_modes:
        raise ValueError(f"unsupported Tamper mode: {mode!r}")

    seed = params.get("seed")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    count = params.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer")
    station = params.get("station")
    if not isinstance(station, str) or not station:
        raise ValueError("station must be a non-empty string for Tamper")

    timestamps = [
        _validate_signed_packet(packet, position)
        for position, packet in enumerate(signed_packets)
    ]
    station_keys = _registered_station_keys()
    if station not in station_keys:
        raise ValueError(f"station {station!r} is not registered in the contract")
    station_positions = [
        position
        for position, packet in enumerate(signed_packets)
        if packet["station"] == station
    ]
    if not station_positions:
        raise ValueError(f"station {station!r} is not present in signed_packets")

    rng = random.Random(seed)
    payload_offset = None
    header_field = None
    dropped_field = None
    target_station = None

    if mode in {"payload_only", "recompute_hash_keep_signature"}:
        try:
            payload_offset = Decimal(str(params["payload_offset"]))
        except (KeyError, ArithmeticError, ValueError) as exc:
            raise ValueError("payload_offset is required and must be a finite number") from exc
        if not payload_offset.is_finite() or payload_offset == 0:
            raise ValueError("payload_offset must be finite and non-zero")
        offset_ticks = payload_offset / RESOLUTION
        if offset_ticks != offset_ticks.to_integral_value():
            raise ValueError("payload_offset must be a multiple of the 0.001 resolution")

    if mode == "signed_header_change":
        header_field = params.get("header_field", "seq")
        if header_field not in {"seq", "ts", "sent_at", "nonce"}:
            raise ValueError("header_field must be one of seq, ts, sent_at, or nonce")
    if mode == "drop_field":
        dropped_field = params.get("drop_field")
        if dropped_field is not None and dropped_field not in PACKET_FIELDS:
            raise ValueError("drop_field must name a required top-level packet field")

    if mode == "station_swap":
        original_key_ids = {signed_packets[pos]["key_id"] for pos in station_positions}
        replacement_stations = [
            candidate
            for candidate, candidate_key in station_keys.items()
            if candidate != station and candidate_key not in original_key_ids
        ]
        if not replacement_stations:
            raise ValueError(
                "no different registered station has a key_id binding distinct from the original packet"
            )
        target_station = rng.choice(sorted(replacement_stations))

    eligible_positions = []
    for position in station_positions:
        packet = signed_packets[position]
        if mode in {"payload_only", "recompute_hash_keep_signature"}:
            raw_value = packet["payload"].get(TARGET_COLUMN)
            if isinstance(raw_value, bool) or raw_value is None:
                continue
            try:
                original = Decimal(str(raw_value))
            except Exception:
                continue
            if not original.is_finite():
                continue
            if original < LOWER_BOUND or original > UPPER_BOUND:
                continue
            if (original / RESOLUTION) != (original / RESOLUTION).to_integral_value():
                continue
            modified = (original + payload_offset).quantize(
                RESOLUTION, rounding=ROUND_HALF_UP
            )
            if LOWER_BOUND <= modified <= UPPER_BOUND and modified != original:
                eligible_positions.append(position)
        else:
            eligible_positions.append(position)

    if len(eligible_positions) < count:
        raise ValueError(
            f"requested count={count}, but only {len(eligible_positions)} eligible packet(s) exist for station {station!r}"
        )
    selected_positions = sorted(rng.sample(eligible_positions, count))
    if mode == "drop_field" and dropped_field is None:
        dropped_field = rng.choice(sorted(PACKET_FIELDS))

    attacked_packets = deepcopy(list(signed_packets))
    changes = []
    for position in selected_positions:
        original_packet = signed_packets[position]
        attacked_packet = attacked_packets[position]
        record = {
            "index": position,
            "seq": original_packet["seq"],
            "original_ts": original_packet["ts"],
            "modified_ts": original_packet["ts"],
            "original_sent_at": original_packet["sent_at"],
            "modified_sent_at": original_packet["sent_at"],
        }

        if mode in {"payload_only", "recompute_hash_keep_signature"}:
            original_value = Decimal(str(original_packet["payload"][TARGET_COLUMN]))
            modified_value = (original_value + payload_offset).quantize(
                RESOLUTION, rounding=ROUND_HALF_UP
            )
            attacked_packet["payload"][TARGET_COLUMN] = float(modified_value)
            if mode == "recompute_hash_keep_signature":
                attacked_packet["payload_sha256"] = hashlib.sha256(
                    _canonical_packet_bytes(attacked_packet["payload"])
                ).hexdigest()
            record.update(
                {
                    "changed_field": f"payload.{TARGET_COLUMN}",
                    "original_value": float(original_value),
                    "modified_value": float(modified_value),
                    "payload_offset": float(payload_offset),
                }
            )
        elif mode == "signed_header_change":
            original_value = original_packet[header_field]
            if header_field == "seq":
                modified_value = original_value + 1
            elif header_field in {"ts", "sent_at"}:
                modified_value = (
                    datetime.strptime(original_value, "%Y-%m-%dT%H:%M:%SZ")
                    + timedelta(seconds=1)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
            else:  # nonce: flip a hex nibble while preserving the contracted format.
                first = "1" if original_value[0] != "1" else "0"
                modified_value = first + original_value[1:]
            attacked_packet[header_field] = modified_value
            if header_field == "ts":
                record["modified_ts"] = modified_value
            if header_field == "sent_at":
                record["modified_sent_at"] = modified_value
            record.update(
                {
                    "changed_field": header_field,
                    "original_value": original_value,
                    "modified_value": modified_value,
                }
            )
        elif mode == "signature_flip":
            signature = bytearray.fromhex(original_packet["sig"])
            byte_index = rng.randrange(len(signature))
            bit_index = rng.randrange(8)
            signature[byte_index] ^= 1 << bit_index
            modified_value = signature.hex()
            attacked_packet["sig"] = modified_value
            record.update(
                {
                    "changed_field": "sig",
                    "original_value": original_packet["sig"],
                    "modified_value": modified_value,
                    "flipped_byte_index": byte_index,
                    "flipped_bit_index": bit_index,
                }
            )
        elif mode == "station_swap":
            modified_value = target_station
            attacked_packet["station"] = modified_value
            record.update(
                {
                    "changed_field": "station",
                    "original_value": original_packet["station"],
                    "modified_value": modified_value,
                    "key_id_unchanged": original_packet["key_id"],
                }
            )
        else:  # drop_field
            original_value = attacked_packet.pop(dropped_field)
            record.update(
                {
                    "changed_field": dropped_field,
                    "original_value": original_value,
                    "modified_value": None,
                    "field_removed": True,
                }
            )
        changes.append(record)

    event_params = {
        "attack_type": "tamper",
        "mode": mode,
        "delivery": "replace",
        "configuration": params,
        "seed": seed,
        "count": count,
        "selected_packets": changes,
        "target_station": target_station,
    }
    run_hash = hashlib.sha256(_canonical_packet_bytes(event_params)).hexdigest()[:24]
    run_id = f"tamper-{station}-{run_hash}"

    attacked_flags = [False] * len(signed_packets)
    attack_types = [""] * len(signed_packets)
    run_ids = [""] * len(signed_packets)
    for position in selected_positions:
        attacked_flags[position] = True
        attack_types[position] = "tamper"
        run_ids[position] = run_id
    labels = pd.DataFrame(
        {
            "is_attacked": attacked_flags,
            "attack_type": attack_types,
            "attack_run_id": run_ids,
        },
        index=range(len(signed_packets)),
        columns=LABEL_COLUMNS,
    )

    first_time = min(timestamps[position] for position in selected_positions)
    last_time = max(timestamps[position] for position in selected_positions)
    event = {
        "attack_run_id": run_id,
        "station": station,
        "attack_type": "tamper",
        # Working convention: events target the protected observation field;
        # params_json records the exact packet field changed in each packet.
        "target_columns": TARGET_COLUMN,
        "start": first_time.strftime("%Y-%m-%d %H:%M:%S"),
        "end": last_time.strftime("%Y-%m-%d %H:%M:%S"),
        "params_json": _canonical_packet_bytes(event_params).decode("utf-8"),
        "seed": seed,
        "engine_version": ENGINE_VERSION,
    }
    return attacked_packets, labels, event


def attack_packet(signed_packets, params):
    """Replay a contiguous window of signed packet dictionaries without editing it.

    ``signed_packets`` is an ordered list/tuple of exact contract packet objects.
    ``params`` requires ``attack_type='replay'``, an integer ``seed``, positive
    ``window_len``, and non-negative ``delay_packets``; an optional ``station``
    restricts selection. A window is eligible only when it belongs to one
    station and every adjacent observation timestamp is exactly one hour apart.
    Its copies are inserted after the requested number of subsequent original
    deliveries. Copies retain every field name and value. Labels are returned
    separately, with a zero-based index for output delivery positions.

    The event's ``target_columns`` lists every measurement in the replayed
    payload as a working convention: Replay duplicates the complete payload,
    even though ``SOIL_MOISTURE_5`` is the project's particularly protected
    measurement. No raw byte identity is implied for dictionary inputs.
    """
    if not isinstance(signed_packets, (list, tuple)) or not signed_packets:
        raise ValueError("signed_packets must be a non-empty ordered list or tuple")
    if not isinstance(params, dict):
        raise TypeError("params must be a dictionary")
    if params.get("attack_type") == "tamper":
        return _tamper_packet(signed_packets, params)
    if params.get("attack_type") != "replay":
        raise ValueError("supported packet attack_type values are 'replay' and 'tamper'")

    seed = params.get("seed")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    window_len = params.get("window_len")
    if isinstance(window_len, bool) or not isinstance(window_len, int) or window_len < 1:
        raise ValueError("window_len must be a positive integer")
    delay_packets = params.get("delay_packets")
    if isinstance(delay_packets, bool) or not isinstance(delay_packets, int) or delay_packets < 0:
        raise ValueError("delay_packets must be a non-negative integer")
    requested_station = params.get("station")
    if requested_station is not None and (not isinstance(requested_station, str) or not requested_station):
        raise ValueError("station, when provided, must be a non-empty string")

    timestamps = [
        _validate_signed_packet(packet, position)
        for position, packet in enumerate(signed_packets)
    ]
    possible_starts = []
    for start in range(len(signed_packets) - window_len + 1):
        end = start + window_len - 1
        window = signed_packets[start : end + 1]
        if requested_station is not None and window[0]["station"] != requested_station:
            continue
        if any(packet["station"] != window[0]["station"] for packet in window[1:]):
            continue
        if any(
            timestamps[index + 1] - timestamps[index] != _ONE_HOUR
            for index in range(start, end)
        ):
            continue
        possible_starts.append(start)
    if not possible_starts:
        raise ValueError(
            "no one-hour-spaced contiguous packet window matches window_len and station"
        )

    eligible_starts = [
        start
        for start in possible_starts
        if start + window_len - 1 + delay_packets < len(signed_packets)
    ]
    if not eligible_starts:
        raise ValueError(
            "packet stream is too short for delay_packets after every eligible window"
        )

    rng = random.Random(seed)
    window_start = rng.choice(eligible_starts)
    window_end = window_start + window_len - 1
    insertion_index = window_end + delay_packets + 1
    replayed_packets = deepcopy(list(signed_packets[window_start : window_end + 1]))

    fingerprint = hashlib.sha256(_canonical_packet_bytes(replayed_packets)).hexdigest()
    identity = {
        "configuration": params,
        "selected_window_start_index": window_start,
        "selected_window_end_index": window_end,
        "selected_packets": replayed_packets,
    }
    run_hash = hashlib.sha256(_canonical_packet_bytes(identity)).hexdigest()[:24]
    station = signed_packets[window_start]["station"]
    run_id = f"replay-{station}-{run_hash}"

    original_copies = deepcopy(list(signed_packets))
    attacked_packets = (
        original_copies[:insertion_index]
        + replayed_packets
        + original_copies[insertion_index:]
    )
    attacked_flags = [False] * len(attacked_packets)
    attack_types = [""] * len(attacked_packets)
    run_ids = [""] * len(attacked_packets)
    for delivery_index in range(insertion_index, insertion_index + window_len):
        attacked_flags[delivery_index] = True
        attack_types[delivery_index] = "replay"
        run_ids[delivery_index] = run_id
    labels = pd.DataFrame(
        {
            "is_attacked": attacked_flags,
            "attack_type": attack_types,
            "attack_run_id": run_ids,
        },
        index=range(len(attacked_packets)),
        columns=LABEL_COLUMNS,
    )

    selected_packets = signed_packets[window_start : window_end + 1]
    # Working convention: Replay repeats the packet, but the event schema only
    # accepts observation columns. SOIL_MOISTURE_5 is the evaluation target.
    target_columns = TARGET_COLUMN
    event_params = {
        "attack_type": "replay",
        "mode": "replay",
        "configuration": params,
        "seed": seed,
        "window_len": window_len,
        "delay_packets": delay_packets,
        "selected_window_start_index": window_start,
        "selected_window_end_index": window_end,
        "selected_window_ts": [packet["ts"] for packet in selected_packets],
        "selected_window_seq": [packet["seq"] for packet in selected_packets],
        "insertion_index": insertion_index,
        "replayed_packets_sha256": fingerprint,
    }
    event = {
        "attack_run_id": run_id,
        "station": station,
        "attack_type": "replay",
        "target_columns": target_columns,
        "start": datetime.strptime(
            selected_packets[0]["ts"], "%Y-%m-%dT%H:%M:%SZ"
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "end": datetime.strptime(
            selected_packets[-1]["ts"], "%Y-%m-%dT%H:%M:%SZ"
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "params_json": _canonical_packet_bytes(event_params).decode("utf-8"),
        "seed": seed,
        "engine_version": ENGINE_VERSION,
    }
    return attacked_packets, labels, event


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
