import json
import hashlib
import random
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import pandas as pd

from attack_engine import (
    EVENT_COLUMNS,
    LABEL_COLUMNS,
    PACKET_PAYLOAD_COLUMNS,
    attack_data,
    attack_packet,
)


def make_clean_data():
    times = pd.date_range("2024-06-01 00:00:00", periods=6, freq="h")
    return pd.DataFrame(
        {
            "time": list(times) + list(times),
            "station": ["CA_Fallbrook_5_NE"] * 6 + ["OK_Goodwell_2_E"] * 6,
            "annee": [2024] * 12,
            "SOIL_MOISTURE_5": [0.100, 0.101, 0.102, None, 0.104, 0.105]
            + [0.200, 0.201, 0.202, 0.203, 0.204, 0.205],
            "P_CALC": [0.0] * 12,
        }
    )


def fixed_params():
    return {
        "attack_type": "bias",
        "mode": "constant_offset",
        "station": "CA_Fallbrook_5_NE",
        "seed": 17,
        "years": [2024],
        "duration_hours_range": [2, 2],
        "offset_range": [0.010, 0.010],
    }


def fixed_spike_params():
    return {
        "attack_type": "bias",
        "mode": "spike",
        "station": "CA_Fallbrook_5_NE",
        "seed": 2024,
        "years": [2024],
        "duration_hours_range": [6, 6],
        "spike_count_range": [3, 3],
        "spike_magnitude_range": [-0.010, 0.010],
    }


def make_signed_packets(count=8, gap_at=None):
    """Build synthetic contract-shaped packets with disposable test values."""
    packets = []
    start = pd.Timestamp("2024-06-01T00:00:00Z")
    for index in range(count):
        extra_gap = pd.Timedelta(hours=1) if gap_at is not None and index >= gap_at else pd.Timedelta(0)
        timestamp = start + pd.Timedelta(hours=index) + extra_gap
        ts = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {name: None for name in PACKET_PAYLOAD_COLUMNS}
        payload["SOIL_MOISTURE_5"] = round(0.100 + index / 1000, 3)
        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        packets.append(
            {
                "v": "1.0.0",
                "key_id": "CA_Fallbrook_5_NE-k1",
                "station": "CA_Fallbrook_5_NE",
                "seq": index,
                "ts": ts,
                "sent_at": ts,
                "nonce": f"{index:032x}",
                "payload": payload,
                "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
                # A disposable, correctly shaped placeholder. This unit suite
                # does not claim Ed25519 verification or Stage-1 gate results.
                "sig": f"{index:0128x}",
            }
        )
    return packets


def fixed_replay_params(**overrides):
    params = {
        "attack_type": "replay",
        "seed": 41,
        "window_len": 2,
        "delay_packets": 0,
        "station": "CA_Fallbrook_5_NE",
    }
    params.update(overrides)
    return params


DEMO_PUBLIC_KEY = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
DEMO_PACKET = {
    "v": "1.0.0",
    "key_id": "OK_Goodwell_2_E-k1",
    "station": "OK_Goodwell_2_E",
    "seq": 29269,
    "ts": "2025-05-04T14:00:00Z",
    "sent_at": "2025-05-04T14:00:04Z",
    "nonce": "9f2c4e0a7b1d3c5e8f6a2b4d0c1e3f57",
    "payload_sha256": "a41465971874a9c98e901bbd94d528dda75f34e5f6c95d495cac96d25c4f283d",
    "payload": {
        "T_HR_AVG": 12.8,
        "T_MAX": 14.3,
        "T_MIN": 10.2,
        "P_CALC": 0.0,
        "SOLARAD": 224.0,
        "SUR_TEMP": 12.6,
        "RH_HR_AVG": 65.0,
        "SOIL_MOISTURE_5": 0.164,
        "SOIL_MOISTURE_10": 0.211,
        "SOIL_MOISTURE_20": 0.223,
        "SOIL_MOISTURE_50": 0.388,
        "SOIL_MOISTURE_100": 0.251,
        "SOIL_TEMP_5": 14.4,
        "SOIL_TEMP_10": 15.0,
        "SOIL_TEMP_20": 15.4,
        "SOIL_TEMP_50": 15.3,
        "SOIL_TEMP_100": 15.0,
    },
    "sig": "fe78b842be0d1e179028ab2ff0c099e67e4b928e9cb7b1008eaa87c9293ed75e2fecdaeaa8455789c691a7b04852dc299c0b79a3bafef8167503122a2321a90f",
}


def run_packet_validator(packet):
    """Run validate.py with temporary packet and public-key files only."""
    repo_root = Path(__file__).resolve().parent
    temporary_paths = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".jsonl", prefix="tamper-packet-",
            dir=repo_root, delete=False,
        ) as packet_file:
            packet_path = Path(packet_file.name)
            temporary_paths.append(packet_path)
            packet_file.write(json.dumps(packet, separators=(",", ":")) + "\n")
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", prefix="tamper-pubkeys-",
            dir=repo_root, delete=False,
        ) as pubkeys_file:
            pubkeys_path = Path(pubkeys_file.name)
            temporary_paths.append(pubkeys_path)
            pubkeys_file.write(
                json.dumps({DEMO_PACKET["key_id"]: DEMO_PUBLIC_KEY})
            )
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(repo_root / "validate.py"),
                "packets",
                str(packet_path),
                "--pubkeys",
                str(pubkeys_path),
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        for temporary_path in temporary_paths:
            temporary_path.unlink(missing_ok=True)


class TestBias(unittest.TestCase):
    def test_constant_offset(self):
        clean = make_clean_data()
        original = clean.copy(deep=True)
        attacked, labels, event = attack_data(clean, fixed_params())
        attacked_again, labels_again, event_again = attack_data(clean, fixed_params())

        pd.testing.assert_frame_equal(clean, original)
        pd.testing.assert_frame_equal(attacked, attacked_again)
        pd.testing.assert_frame_equal(labels, labels_again)
        self.assertEqual(event, event_again)
        self.assertEqual(list(attacked.columns), list(clean.columns))
        self.assertEqual(list(labels.columns), LABEL_COLUMNS)
        self.assertEqual(list(event), EVENT_COLUMNS)

        changed = labels["is_attacked"]
        self.assertTrue(changed.any())
        self.assertTrue((labels.loc[changed, "attack_type"] == "bias").all())
        self.assertTrue((labels.loc[changed, "attack_run_id"] == event["attack_run_id"]).all())
        self.assertTrue((labels.loc[~changed, "attack_type"] == "").all())
        self.assertTrue((labels.loc[~changed, "attack_run_id"] == "").all())

        both_valid = attacked["SOIL_MOISTURE_5"].notna() & clean["SOIL_MOISTURE_5"].notna()
        moisture_changed = pd.Series(False, index=clean.index)
        moisture_changed.loc[both_valid] = attacked.loc[
            both_valid, "SOIL_MOISTURE_5"
        ].ne(clean.loc[both_valid, "SOIL_MOISTURE_5"])
        self.assertTrue(moisture_changed.equals(changed))
        other_columns = [column for column in clean.columns if column != "SOIL_MOISTURE_5"]
        pd.testing.assert_frame_equal(attacked[other_columns], clean[other_columns])
        self.assertTrue((attacked.loc[changed, "SOIL_MOISTURE_5"] <= 0.65).all())
        self.assertTrue((attacked.loc[changed, "SOIL_MOISTURE_5"] >= 0.0).all())
        self.assertTrue(
            (((attacked.loc[changed, "SOIL_MOISTURE_5"] * 1000).round() % 1) == 0).all()
        )
        event_params = json.loads(event["params_json"])
        self.assertEqual(event_params["years"], [2024])
        self.assertEqual(event_params["duration_hours_range"], [2, 2])
        self.assertEqual(event_params["offset_range"], [0.01, 0.01])
        self.assertEqual(event_params["selected_duration_hours"], 2)
        self.assertEqual(event_params["mode"], "constant_offset")
        self.assertEqual(event_params["seed"], 17)
        recorded_offset = Decimal(str(event_params["selected_offset"]))
        for pos in range(len(clean)):
            if changed.iloc[pos]:
                original_value = Decimal(str(clean.iloc[pos]["SOIL_MOISTURE_5"]))
                expected_value = (original_value + recorded_offset).quantize(
                    Decimal("0.001"), rounding=ROUND_HALF_UP
                )
                self.assertEqual(
                    Decimal(str(attacked.iloc[pos]["SOIL_MOISTURE_5"])),
                    expected_value,
                )

        # Other stations and all observations outside the selected interval stay unchanged.
        other_station = clean["station"].eq("OK_Goodwell_2_E")
        pd.testing.assert_series_equal(
            attacked.loc[other_station, "SOIL_MOISTURE_5"],
            clean.loc[other_station, "SOIL_MOISTURE_5"],
        )
        changed_times = set(attacked.loc[changed, "time"])
        outside_window = ~clean["time"].isin(changed_times)
        pd.testing.assert_frame_equal(attacked.loc[outside_window], clean.loc[outside_window])
        self.assertTrue(attacked.loc[clean["SOIL_MOISTURE_5"].isna(), "SOIL_MOISTURE_5"].isna().all())
        self.assertEqual(event["target_columns"], "SOIL_MOISTURE_5")
        self.assertEqual(event["seed"], 17)
        self.assertEqual(
            pd.Timestamp(event["end"]) - pd.Timestamp(event["start"]),
            pd.Timedelta(hours=1),
        )

    def test_no_valid_contiguous_window_raises(self):
        clean = make_clean_data()
        params = fixed_params()
        params["station"] = "NO_SUCH_STATION"
        with self.assertRaisesRegex(ValueError, "not present"):
            attack_data(clean, params)

        params["station"] = "CA_Fallbrook_5_NE"
        params["duration_hours_range"] = [3, 3]
        # Missing 02:00 and 03:00 leave valid runs that are each shorter than 3 hours.
        clean.loc[
            clean["station"].eq("CA_Fallbrook_5_NE")
            & clean["time"].eq(pd.Timestamp("2024-06-01 02:00:00")),
            "SOIL_MOISTURE_5",
        ] = None
        with self.assertRaisesRegex(ValueError, "no feasible contiguous window"):
            attack_data(clean, params)

    def test_skips_bounds_invalid_window_when_feasible_window_exists(self):
        clean = make_clean_data()
        fallbrook_rows = clean.index[clean["station"].eq("CA_Fallbrook_5_NE")]
        clean.loc[fallbrook_rows, "SOIL_MOISTURE_5"] = pd.Series(
            [0.645, 0.646, float("nan"), 0.100, 0.101, 0.102],
            index=fallbrook_rows,
            dtype="float64",
        )
        params = fixed_params()
        params["seed"] = 0

        # With the old unfiltered selector, this seed selected the first,
        # out-of-bounds window. A later valid window is available.
        old_selector = random.Random(params["seed"])
        old_selector.randrange(1)  # fixed one-tick offset range
        old_selector.randint(2, 2)  # fixed duration
        self.assertEqual(old_selector.randrange(3), 0)

        attacked, labels, event = attack_data(clean, params)
        self.assertGreaterEqual(event["start"], "2024-06-01 03:00:00")
        self.assertEqual(
            pd.Timestamp(event["end"]) - pd.Timestamp(event["start"]),
            pd.Timedelta(hours=1),
        )
        changed = labels["is_attacked"]
        self.assertEqual(int(changed.sum()), 2)
        self.assertTrue((attacked.loc[changed, "SOIL_MOISTURE_5"] <= 0.65).all())
        self.assertTrue((attacked.loc[changed, "SOIL_MOISTURE_5"] >= 0.0).all())

    def test_distinct_configurations_have_distinct_run_ids(self):
        clean = make_clean_data()
        first_params = fixed_params()
        second_params = fixed_params()
        second_params["experiment_name"] = "second-configuration"

        _, _, first_event = attack_data(clean, first_params)
        _, _, second_event = attack_data(clean, second_params)

        self.assertNotEqual(first_event["attack_run_id"], second_event["attack_run_id"])
        self.assertEqual(
            json.loads(second_event["params_json"])["configuration"]["experiment_name"],
            "second-configuration",
        )

    def test_out_of_bounds_configuration_raises(self):
        clean = make_clean_data()
        fallbrook_rows = clean.index[clean["station"].eq("CA_Fallbrook_5_NE")]
        clean.loc[fallbrook_rows, "SOIL_MOISTURE_5"] = pd.Series(
            [0.645, 0.646, 0.647, float("nan"), 0.648, 0.649],
            index=fallbrook_rows,
            dtype="float64",
        )
        params = fixed_params()
        with self.assertRaisesRegex(ValueError, "no feasible contiguous window"):
            attack_data(clean, params)

    def test_lower_bound_violation_raises(self):
        clean = make_clean_data()
        fallbrook_rows = clean.index[clean["station"].eq("CA_Fallbrook_5_NE")]
        clean.loc[fallbrook_rows, "SOIL_MOISTURE_5"] = pd.Series(
            [0.005, 0.006, 0.007, float("nan"), 0.008, 0.009],
            index=fallbrook_rows,
            dtype="float64",
        )
        params = fixed_params()
        params["offset_range"] = [-0.010, -0.010]
        with self.assertRaisesRegex(ValueError, "no feasible contiguous window"):
            attack_data(clean, params)

    def test_2025_is_configurable_but_first_fixture_is_2024(self):
        clean = make_clean_data()
        params = fixed_params()
        params["years"] = [2025]
        with self.assertRaisesRegex(ValueError, "no feasible contiguous window"):
            attack_data(clean, params)


class TestSpike(unittest.TestCase):
    def test_spike_count_spacing_bounds_labels_and_event(self):
        clean = make_clean_data()
        original = clean.copy(deep=True)
        params = fixed_spike_params()
        attacked, labels, event = attack_data(clean, params)

        pd.testing.assert_frame_equal(clean, original)
        self.assertEqual(list(attacked.columns), list(clean.columns))
        self.assertEqual(list(labels.columns), LABEL_COLUMNS)
        self.assertEqual(list(event), EVENT_COLUMNS)

        changed = labels["is_attacked"]
        self.assertEqual(int(changed.sum()), 3)
        self.assertTrue((labels.loc[changed, "attack_type"] == "bias").all())
        self.assertTrue((labels.loc[changed, "attack_run_id"] == event["attack_run_id"]).all())
        self.assertTrue((labels.loc[~changed, "attack_type"] == "").all())
        self.assertTrue((labels.loc[~changed, "attack_run_id"] == "").all())
        self.assertTrue(attacked.loc[clean["SOIL_MOISTURE_5"].isna(), "SOIL_MOISTURE_5"].isna().all())

        changed_positions = [i for i, value in enumerate(changed.tolist()) if value]
        changed_times = [pd.Timestamp(clean.iloc[i]["time"]) for i in changed_positions]
        self.assertTrue(all((b - a) >= pd.Timedelta(hours=2) for a, b in zip(changed_times, changed_times[1:])))
        self.assertEqual(event["start"], changed_times[0].strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEqual(event["end"], changed_times[-1].strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEqual(event["target_columns"], "SOIL_MOISTURE_5")
        self.assertEqual(event["attack_type"], "bias")
        self.assertEqual(event["seed"], params["seed"])

        event_params = json.loads(event["params_json"])
        self.assertEqual(event_params["mode"], "spike")
        self.assertEqual(event_params["selected_duration_hours"], 6)
        self.assertEqual(event_params["selected_spike_count"], 3)
        self.assertEqual(event_params["selected_window_start"], "2024-06-01 00:00:00")
        self.assertEqual(event_params["selected_window_end"], "2024-06-01 05:00:00")
        self.assertEqual(len(event_params["spikes"]), 3)
        self.assertEqual(
            [spike["timestamp"] for spike in event_params["spikes"]],
            [value.strftime("%Y-%m-%d %H:%M:%S") for value in changed_times],
        )
        for pos, spike in zip(changed_positions, event_params["spikes"]):
            old_value = Decimal(str(clean.iloc[pos]["SOIL_MOISTURE_5"]))
            new_value = Decimal(str(attacked.iloc[pos]["SOIL_MOISTURE_5"]))
            magnitude = Decimal(str(spike["magnitude"]))
            self.assertNotEqual(magnitude, Decimal("0"))
            self.assertEqual(new_value, (old_value + magnitude).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP))
            self.assertGreaterEqual(new_value, Decimal("0"))
            self.assertLessEqual(new_value, Decimal("0.65"))
            self.assertEqual(new_value * 1000 % 1, 0)

        unaffected = [column for column in clean.columns if column != "SOIL_MOISTURE_5"]
        pd.testing.assert_frame_equal(attacked[unaffected], clean[unaffected])
        pd.testing.assert_series_equal(
            attacked.loc[~changed, "SOIL_MOISTURE_5"],
            clean.loc[~changed, "SOIL_MOISTURE_5"],
        )

    def test_spike_seed_is_reproducible(self):
        clean = make_clean_data()
        params = fixed_spike_params()
        first = attack_data(clean, params)
        second = attack_data(clean, params)
        pd.testing.assert_frame_equal(first[0], second[0])
        pd.testing.assert_frame_equal(first[1], second[1])
        self.assertEqual(first[2], second[2])

    def test_spike_count_must_fit_spacing_and_duration(self):
        params = fixed_spike_params()
        params["spike_count_range"] = [4, 4]
        with self.assertRaisesRegex(ValueError, "cannot fit"):
            attack_data(make_clean_data(), params)


class TestReplay(unittest.TestCase):
    def test_replay_duplicates_complete_window_at_zero_delay(self):
        packets = make_signed_packets()
        original = json.loads(json.dumps(packets))
        attacked, labels, event = attack_packet(packets, fixed_replay_params())
        event_params = json.loads(event["params_json"])
        start = event_params["selected_window_start_index"]
        end = event_params["selected_window_end_index"]
        insertion = end + 1
        expected = packets[:insertion] + packets[start : end + 1] + packets[insertion:]

        self.assertEqual(attacked, expected)
        self.assertEqual(attacked[insertion : insertion + 2], packets[start : end + 1])
        self.assertEqual(packets, original)
        self.assertTrue(all(attacked[i] is not packets[i] for i in range(len(packets))))
        self.assertEqual(list(labels.columns), ["is_attacked", "attack_type", "attack_run_id"])
        self.assertEqual(list(labels.index), list(range(len(attacked))))
        self.assertEqual(labels["is_attacked"].sum(), 2)
        self.assertEqual(labels.index[labels["is_attacked"]].tolist(), [insertion, insertion + 1])
        self.assertTrue((labels.loc[labels["is_attacked"], "attack_type"] == "replay").all())
        self.assertTrue((labels.loc[labels["is_attacked"], "attack_run_id"] == event["attack_run_id"]).all())
        self.assertTrue((labels.loc[~labels["is_attacked"], "attack_type"] == "").all())
        self.assertTrue((labels.loc[~labels["is_attacked"], "attack_run_id"] == "").all())
        self.assertEqual(list(event), EVENT_COLUMNS)
        self.assertEqual(event["attack_type"], "replay")
        self.assertEqual(event["station"], "CA_Fallbrook_5_NE")
        self.assertEqual(
            event["start"],
            pd.Timestamp(packets[start]["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.assertEqual(
            event["end"],
            pd.Timestamp(packets[end]["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.assertEqual(
            event["target_columns"], "SOIL_MOISTURE_5"
        )
        self.assertEqual(event["seed"], 41)

    def test_delay_inserts_after_d_subsequent_original_packets(self):
        packets = make_signed_packets(count=10)
        delay = 2
        attacked, labels, event = attack_packet(
            packets, fixed_replay_params(delay_packets=delay)
        )
        event_params = json.loads(event["params_json"])
        end = event_params["selected_window_end_index"]
        insertion = end + delay + 1

        self.assertEqual(event_params["insertion_index"], insertion)
        self.assertEqual(attacked[:insertion], packets[:insertion])
        start = event_params["selected_window_start_index"]
        window_len = event_params["window_len"]
        self.assertEqual(
            attacked[insertion : insertion + window_len], packets[start : end + 1]
        )
        self.assertEqual(attacked[insertion + window_len :], packets[insertion:])
        self.assertEqual(
            labels.index[labels["is_attacked"]].tolist(),
            list(range(insertion, insertion + window_len)),
        )

    def test_replay_selection_and_run_id_are_reproducible(self):
        packets = make_signed_packets()
        params = fixed_replay_params(seed=2026)
        first = attack_packet(packets, params)
        second = attack_packet(packets, params)

        self.assertEqual(first[0], second[0])
        pd.testing.assert_frame_equal(first[1], second[1])
        self.assertEqual(first[2], second[2])
        digest_part = first[2]["attack_run_id"].rsplit("-", 1)[1]
        self.assertEqual(len(digest_part), 24)
        self.assertTrue(all(char in "0123456789abcdef" for char in digest_part))

    def test_fingerprint_hashes_complete_canonicalized_packets(self):
        packets = make_signed_packets()
        attacked, _, event = attack_packet(packets, fixed_replay_params())
        event_params = json.loads(event["params_json"])
        insertion = event_params["insertion_index"]
        length = event_params["window_len"]
        replayed = attacked[insertion : insertion + length]
        canonical = json.dumps(
            replayed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        expected = hashlib.sha256(canonical).hexdigest()
        signatures_only = json.dumps(
            [packet["sig"] for packet in replayed], separators=(",", ":")
        ).encode("utf-8")

        self.assertEqual(event_params["replayed_packets_sha256"], expected)
        self.assertNotEqual(expected, hashlib.sha256(signatures_only).hexdigest())

    def test_replay_event_passes_events_validator(self):
        _, _, event = attack_packet(make_signed_packets(), fixed_replay_params())
        selected_ts = json.loads(event["params_json"])["selected_window_ts"]
        self.assertEqual(
            event["start"],
            pd.Timestamp(selected_ts[0]).strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.assertEqual(
            event["end"],
            pd.Timestamp(selected_ts[-1]).strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.assertRegex(event["start"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        with tempfile.NamedTemporaryFile(suffix=".csv", dir=Path(__file__).parent, delete=False) as temporary:
            events_path = Path(temporary.name)
        try:
            pd.DataFrame([event], columns=EVENT_COLUMNS).to_csv(events_path, index=False)
            result = subprocess.run(
                [sys.executable, "validate.py", "events", str(events_path)],
                cwd=Path(__file__).parent,
                capture_output=True,
                text=True,
                check=False,
            )
        finally:
            events_path.unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_window_requires_exact_one_hour_timestamp_spacing(self):
        packets = make_signed_packets(count=24, gap_at=12)
        with self.assertRaisesRegex(ValueError, "one-hour-spaced"):
            attack_packet(
                packets,
                fixed_replay_params(window_len=24, delay_packets=0),
            )

        hourly = make_signed_packets(count=24)
        attacked, _, event = attack_packet(
            hourly, fixed_replay_params(window_len=24, delay_packets=0)
        )
        self.assertEqual(len(attacked), 48)
        self.assertEqual(
            pd.Timestamp(event["end"]) - pd.Timestamp(event["start"]),
            pd.Timedelta(hours=23),
        )

    def test_too_short_stream_for_delay_raises(self):
        packets = make_signed_packets(count=4)
        with self.assertRaisesRegex(ValueError, "too short"):
            attack_packet(
                packets,
                fixed_replay_params(window_len=2, delay_packets=4),
            )

    def test_packet_structure_must_match_contract_exactly(self):
        packets = make_signed_packets()
        packets[0]["extra"] = "not contracted"
        with self.assertRaisesRegex(ValueError, "exactly the contracted packet fields"):
            attack_packet(packets, fixed_replay_params())


class TestTamper(unittest.TestCase):
    def params(self, mode, **overrides):
        params = {
            "attack_type": "tamper",
            "mode": mode,
            "seed": 91,
            "count": 1,
            "station": "CA_Fallbrook_5_NE",
        }
        params.update(overrides)
        return params

    def assert_only_selected_packet_changes(self, original, attacked, labels):
        self.assertEqual(len(attacked), len(original))
        selected = set(labels.index[labels["is_attacked"]].tolist())
        for position, (before, after) in enumerate(zip(original, attacked)):
            if position not in selected:
                self.assertEqual(after, before, f"unselected packet {position} changed")
        self.assertEqual(len(selected), int(labels["is_attacked"].sum()))

    def test_payload_modes_apply_explicit_plus_001_and_keep_signature(self):
        packets = make_signed_packets(count=8)
        for mode in ("payload_only", "recompute_hash_keep_signature"):
            with self.subTest(mode=mode):
                original = json.loads(json.dumps(packets))
                attacked, labels, event = attack_packet(
                    packets,
                    self.params(mode, count=2, payload_offset=0.001),
                )
                selected = labels.index[labels["is_attacked"]].tolist()
                self.assertEqual(len(selected), 2)
                self.assert_only_selected_packet_changes(packets, attacked, labels)
                self.assertEqual(list(labels.columns), LABEL_COLUMNS)
                self.assertEqual(list(labels.index), list(range(len(packets))))
                for position in selected:
                    old = Decimal(str(packets[position]["payload"]["SOIL_MOISTURE_5"]))
                    new = Decimal(str(attacked[position]["payload"]["SOIL_MOISTURE_5"]))
                    self.assertEqual(new - old, Decimal("0.001"))
                    self.assertEqual(new * 1000 % 1, 0)
                    self.assertGreaterEqual(new, Decimal("0"))
                    self.assertLessEqual(new, Decimal("0.65"))
                    self.assertEqual(attacked[position]["sig"], packets[position]["sig"])
                    for field in packets[position]:
                        if field not in {"payload", "payload_sha256"}:
                            self.assertEqual(
                                attacked[position][field], packets[position][field]
                            )
                    for column in packets[position]["payload"]:
                        if column != "SOIL_MOISTURE_5":
                            self.assertEqual(
                                attacked[position]["payload"][column],
                                packets[position]["payload"][column],
                            )
                    if mode == "payload_only":
                        self.assertEqual(
                            attacked[position]["payload_sha256"],
                            packets[position]["payload_sha256"],
                        )
                    else:
                        canonical_payload = json.dumps(
                            attacked[position]["payload"],
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ).encode("utf-8")
                        self.assertEqual(
                            attacked[position]["payload_sha256"],
                            hashlib.sha256(canonical_payload).hexdigest(),
                        )
                metadata = json.loads(event["params_json"])
                self.assertEqual(metadata["delivery"], "replace")
                self.assertEqual(len(metadata["selected_packets"]), 2)
                self.assertEqual(list(event), EVENT_COLUMNS)
                self.assertEqual(
                    [item["index"] for item in metadata["selected_packets"]],
                    selected,
                )
                self.assertTrue(
                    all(item["changed_field"] == "payload.SOIL_MOISTURE_5" for item in metadata["selected_packets"])
                )
                original_times = [packets[position]["ts"] for position in selected]
                self.assertEqual(event["start"], min(original_times).replace("T", " ").removesuffix("Z"))
                self.assertEqual(event["end"], max(original_times).replace("T", " ").removesuffix("Z"))
                self.assertEqual(packets, original)

    def test_payload_change_with_no_feasible_bound_raises(self):
        packets = make_signed_packets(count=3)
        for packet in packets:
            packet["payload"]["SOIL_MOISTURE_5"] = 0.650
        with self.assertRaisesRegex(ValueError, "only 0 eligible"):
            attack_packet(
                packets,
                self.params("payload_only", payload_offset=0.001),
            )

    def test_signed_header_modes_keep_signature_and_valid_field_format(self):
        packets = make_signed_packets(count=4)
        for field in ("seq", "ts", "sent_at", "nonce"):
            with self.subTest(field=field):
                attacked, labels, event = attack_packet(
                    packets,
                    self.params("signed_header_change", header_field=field),
                )
                position = labels.index[labels["is_attacked"]][0]
                before, after = packets[position], attacked[position]
                self.assertEqual(after["sig"], before["sig"])
                self.assertEqual(set(after), set(before))
                self.assertNotEqual(after[field], before[field])
                for name in before:
                    if name != field:
                        self.assertEqual(after[name], before[name])
                if field == "seq":
                    self.assertIsInstance(after[field], int)
                    self.assertGreaterEqual(after[field], 0)
                elif field in {"ts", "sent_at"}:
                    self.assertRegex(after[field], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
                    self.assertEqual(
                        pd.Timestamp(after[field]) - pd.Timestamp(before[field]),
                        pd.Timedelta(seconds=1),
                    )
                else:
                    self.assertRegex(after[field], r"^[0-9a-f]{32}$")
                self.assert_only_selected_packet_changes(packets, attacked, labels)
                record = json.loads(event["params_json"])["selected_packets"][0]
                self.assertEqual(record["changed_field"], field)
                self.assertEqual(record["original_value"], before[field])
                self.assertEqual(record["modified_value"], after[field])

    def test_signature_flip_changes_exactly_one_signature_bit(self):
        packets = make_signed_packets(count=5)
        attacked, labels, event = attack_packet(
            packets, self.params("signature_flip")
        )
        position = labels.index[labels["is_attacked"]][0]
        before, after = packets[position], attacked[position]
        xor = int(before["sig"], 16) ^ int(after["sig"], 16)
        self.assertEqual(xor.bit_count(), 1)
        self.assertEqual(len(after["sig"]), 128)
        self.assertRegex(after["sig"], r"^[0-9a-f]{128}$")
        for field in before:
            if field != "sig":
                self.assertEqual(after[field], before[field])
        self.assert_only_selected_packet_changes(packets, attacked, labels)
        change = json.loads(event["params_json"])["selected_packets"][0]
        self.assertEqual(change["changed_field"], "sig")
        self.assertEqual(change["original_value"], before["sig"])
        self.assertEqual(change["modified_value"], after["sig"])

    def test_station_swap_uses_another_registered_key_binding(self):
        packets = make_signed_packets(count=5)
        packets = [
            {**packet, "station": "OK_Goodwell_2_E", "key_id": "OK_Goodwell_2_E-k1"}
            for packet in packets
        ]
        attacked, labels, event = attack_packet(
            packets,
            self.params("station_swap", station="OK_Goodwell_2_E"),
        )
        position = labels.index[labels["is_attacked"]][0]
        before, after = packets[position], attacked[position]
        self.assertNotEqual(after["station"], before["station"])
        self.assertEqual(after["key_id"], before["key_id"])
        self.assertNotEqual(after["station"], "OK_Goodwell_2_E")
        for field in before:
            if field != "station":
                self.assertEqual(after[field], before[field])
        self.assert_only_selected_packet_changes(packets, attacked, labels)
        record = json.loads(event["params_json"])["selected_packets"][0]
        self.assertEqual(record["changed_field"], "station")
        self.assertEqual(record["original_value"], before["station"])
        self.assertEqual(record["modified_value"], after["station"])

    def test_drop_field_removes_required_top_level_field(self):
        packets = make_signed_packets(count=5)
        attacked, labels, event = attack_packet(
            packets, self.params("drop_field", drop_field="sent_at")
        )
        position = labels.index[labels["is_attacked"]][0]
        self.assertNotIn("sent_at", attacked[position])
        self.assertEqual(set(attacked[position]), set(packets[position]) - {"sent_at"})
        self.assert_only_selected_packet_changes(packets, attacked, labels)
        record = json.loads(event["params_json"])["selected_packets"][0]
        self.assertEqual(record["changed_field"], "sent_at")
        self.assertEqual(record["original_value"], packets[position]["sent_at"])
        self.assertIsNone(record["modified_value"])
        self.assertTrue(record["field_removed"])

    def test_default_count_is_one_and_insufficient_eligible_packets_raises(self):
        packets = make_signed_packets(count=3)
        params = self.params("signature_flip")
        params.pop("count")
        attacked, labels, _ = attack_packet(packets, params)
        self.assertEqual(int(labels["is_attacked"].sum()), 1)
        self.assertEqual(len(attacked), len(packets))
        with self.assertRaisesRegex(ValueError, "requested count=4"):
            attack_packet(
                packets,
                self.params("signature_flip", count=4),
            )

    def test_packet_after_replaced_delivery_remains_unchanged(self):
        packets = make_signed_packets(count=8)
        for seed in range(100):
            attacked, labels, _ = attack_packet(
                packets,
                self.params("signature_flip", seed=seed),
            )
            position = labels.index[labels["is_attacked"]][0]
            if position + 1 < len(packets):
                break
        self.assertEqual(attacked[position + 1], packets[position + 1])

    def test_tamper_selection_labels_and_event_are_reproducible(self):
        packets = make_signed_packets(count=8)
        params = self.params("signature_flip", seed=810)
        first = attack_packet(packets, params)
        second = attack_packet(packets, params)
        self.assertEqual(first[0], second[0])
        pd.testing.assert_frame_equal(first[1], second[1])
        self.assertEqual(first[2], second[2])


class TestTamperValidatorIntegration(unittest.TestCase):
    def test_contract_demo_packet_validates_untouched(self):
        result = run_packet_validator(DEMO_PACKET)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VALID against contract", result.stdout)

    def test_payload_only_reports_hash_mismatch(self):
        attacked, _, _ = attack_packet(
            [DEMO_PACKET],
            {
                "attack_type": "tamper",
                "mode": "payload_only",
                "station": DEMO_PACKET["station"],
                "payload_offset": 0.001,
                "seed": 5,
            },
        )
        result = run_packet_validator(attacked[0])
        self.assertEqual(result.returncode, 1)
        self.assertIn("payload_sha256 does not match payload", result.stdout)
        self.assertNotIn("signature invalid", result.stdout)

    def test_recompute_hash_keep_signature_reports_bad_signature(self):
        attacked, _, _ = attack_packet(
            [DEMO_PACKET],
            {
                "attack_type": "tamper",
                "mode": "recompute_hash_keep_signature",
                "station": DEMO_PACKET["station"],
                "payload_offset": 0.001,
                "seed": 6,
            },
        )
        result = run_packet_validator(attacked[0])
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("payload_sha256 does not match payload", result.stdout)
        self.assertIn("signature invalid", result.stdout)

    def test_signed_header_change_reports_bad_signature(self):
        attacked, _, _ = attack_packet(
            [DEMO_PACKET],
            {
                "attack_type": "tamper",
                "mode": "signed_header_change",
                "header_field": "seq",
                "station": DEMO_PACKET["station"],
                "seed": 7,
            },
        )
        result = run_packet_validator(attacked[0])
        self.assertEqual(result.returncode, 1)
        self.assertIn("signature invalid", result.stdout)

    def test_signature_flip_reports_bad_signature(self):
        attacked, _, _ = attack_packet(
            [DEMO_PACKET],
            {
                "attack_type": "tamper",
                "mode": "signature_flip",
                "station": DEMO_PACKET["station"],
                "seed": 8,
            },
        )
        result = run_packet_validator(attacked[0])
        self.assertEqual(result.returncode, 1)
        self.assertIn("signature invalid", result.stdout)

    def test_station_swap_reports_key_binding_mismatch(self):
        attacked, _, _ = attack_packet(
            [DEMO_PACKET],
            {
                "attack_type": "tamper",
                "mode": "station_swap",
                "station": DEMO_PACKET["station"],
                "seed": 9,
            },
        )
        result = run_packet_validator(attacked[0])
        self.assertEqual(result.returncode, 1)
        self.assertIn("key_id not bound to station", result.stdout)
        self.assertIn("signature invalid", result.stdout)

    def test_drop_field_reports_incorrect_required_fields(self):
        attacked, _, _ = attack_packet(
            [DEMO_PACKET],
            {
                "attack_type": "tamper",
                "mode": "drop_field",
                "drop_field": "sent_at",
                "station": DEMO_PACKET["station"],
                "seed": 10,
            },
        )
        result = run_packet_validator(attacked[0])
        self.assertEqual(result.returncode, 1)
        self.assertIn("fields must be exactly", result.stdout)
        self.assertNotIn("signature invalid", result.stdout)


if __name__ == "__main__":
    unittest.main()
