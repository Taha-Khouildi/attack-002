import json
import random
import unittest
from decimal import Decimal, ROUND_HALF_UP

import pandas as pd

from attack_engine import EVENT_COLUMNS, LABEL_COLUMNS, attack_data


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


if __name__ == "__main__":
    unittest.main()
