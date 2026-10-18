import unittest
from pathlib import Path

import pandas as pd

from attack_engine import LABEL_COLUMNS
from make_attacks import load_config, run_config, validate_config


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "provisional_v2.json"
OUTPUT_DIR = ROOT / "data" / "attacked"


def synthetic_observations(count=30, gap=False):
    times = pd.date_range(
        "2024-06-01 00:00:00", periods=count, freq="2h" if gap else "h"
    )
    return pd.DataFrame(
        {
            "time": times,
            "station": ["CA_Fallbrook_5_NE"] * count,
            "annee": [2024] * count,
            "SOIL_MOISTURE_5": [round(0.100 + (i % 10) / 1000, 3) for i in range(count)],
            "P_CALC": [0.0] * count,
        }
    )


def configured_run(output_dir, *, profile="bias", seed=81, run_id="bias01"):
    config = load_config(CONFIG_PATH)
    config["output_dir"] = str(output_dir)
    config["runs"] = [
        {
            "id": run_id,
            "profile": profile,
            "station": "CA_Fallbrook_5_NE",
            "seed": seed,
        }
    ]
    return config


def remove_run_outputs(output_dir, run_id, mode="constant_offset"):
    stem = f"{mode}_provisional_v2_CA_Fallbrook_5_NE_{run_id}"
    for suffix in (".csv", "_events.csv"):
        path = Path(output_dir) / f"{stem}{suffix}"
        path.unlink(missing_ok=True)


class TestMakeAttacks(unittest.TestCase):
    def test_loads_json_profile_and_keeps_spike_deferred(self):
        config = load_config(CONFIG_PATH)
        self.assertEqual(config["profiles"]["bias"]["offset_range"], [0.02, 0.08])
        self.assertEqual(config["profiles"]["bias"]["duration_hours_range"], [6, 72])
        self.assertEqual(config["profiles"]["bias"]["years"], [2024])
        self.assertFalse(config["profiles"]["spike"]["enabled"])
        self.assertEqual(config["profiles"]["spike"]["spike_magnitude_range"], [0.03, 0.10])
        self.assertEqual(config["runs"], [])

    def test_empty_run_list_writes_no_attack_files(self):
        config = load_config(CONFIG_PATH)
        config["output_dir"] = str(ROOT / "data" / "attacked" / "unused-no-run-output")
        report = run_config(config)
        self.assertEqual(report["configured_runs"], 0)
        self.assertEqual(report["applied_runs"], 0)
        self.assertFalse(Path(config["output_dir"]).exists())

    def test_bias_run_is_reproducible_and_preserves_columns_and_labels(self):
        clean = synthetic_observations()
        clean_before = clean.copy(deep=True)
        config = configured_run(OUTPUT_DIR, run_id="runner-repro-test")
        config["profiles"]["bias"]["duration_hours_range"] = [6, 6]
        try:
            first_report = run_config(config, clean_data=clean)
            first_csv = OUTPUT_DIR / "constant_offset_provisional_v2_CA_Fallbrook_5_NE_runner-repro-test.csv"
            first_event = OUTPUT_DIR / "constant_offset_provisional_v2_CA_Fallbrook_5_NE_runner-repro-test_events.csv"
            first_bytes = first_csv.read_bytes()
            first_event_bytes = first_event.read_bytes()
            self.assertEqual(first_report["applied_runs"], 1)
            first_csv.unlink()
            first_event.unlink()
            second_report = run_config(config, clean_data=clean)
            self.assertEqual(second_report["applied_runs"], 1)
            self.assertEqual(first_bytes, first_csv.read_bytes())
            self.assertEqual(first_event_bytes, first_event.read_bytes())
            pd.testing.assert_frame_equal(clean, clean_before)
            attacked = pd.read_csv(first_csv)
            self.assertEqual(list(attacked.columns), list(clean.columns) + LABEL_COLUMNS)
            self.assertEqual(int(attacked["is_attacked"].sum()), 6)
            self.assertTrue((attacked.loc[attacked.is_attacked, "attack_type"] == "bias").all())
            self.assertEqual(
                first_report["stations"]["CA_Fallbrook_5_NE"]["bias_runs_configured"], 1
            )
        finally:
            remove_run_outputs(OUTPUT_DIR, "runner-repro-test")

    def test_existing_outputs_are_not_overwritten(self):
        config = configured_run(OUTPUT_DIR, run_id="runner-no-overwrite-test")
        try:
            run_config(config, clean_data=synthetic_observations())
            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                run_config(config, clean_data=synthetic_observations())
        finally:
            remove_run_outputs(OUTPUT_DIR, "runner-no-overwrite-test")

    def test_spike_runs_when_all_required_parameters_are_explicit(self):
        config = load_config(CONFIG_PATH)
        spike = config["profiles"]["spike"]
        spike.update(
            {
                "enabled": True,
                "duration_hours_range": [6, 6],
                "spike_count_range": [2, 2],
            }
        )
        config["output_dir"] = str(OUTPUT_DIR)
        config["runs"] = [
            {
                "id": "runner-spike-explicit-test",
                "profile": "spike",
                "station": "CA_Fallbrook_5_NE",
                "seed": 91,
            }
        ]
        try:
            report = run_config(config, clean_data=synthetic_observations())
            self.assertEqual(report["applied_runs"], 1)
            output_path = OUTPUT_DIR / "spike_provisional_v2_CA_Fallbrook_5_NE_runner-spike-explicit-test.csv"
            attacked = pd.read_csv(output_path)
            self.assertEqual(int(attacked["is_attacked"].sum()), 2)
            self.assertTrue((attacked.loc[attacked.is_attacked, "attack_type"] == "bias").all())
        finally:
            remove_run_outputs(OUTPUT_DIR, "runner-spike-explicit-test", mode="spike")

    def test_disabled_spike_cannot_be_scheduled(self):
        config = load_config(CONFIG_PATH)
        config["runs"] = [
            {"id": "spike01", "profile": "spike", "station": "CA_Fallbrook_5_NE", "seed": 2}
        ]
        with self.assertRaisesRegex(ValueError, "disabled profile"):
            validate_config(config)

    def test_enabled_spike_requires_duration_and_count_ranges(self):
        config = load_config(CONFIG_PATH)
        config["profiles"]["spike"]["enabled"] = True
        config["profiles"]["spike"]["duration_hours_range"] = [6, 72]
        config["runs"] = [
            {"id": "spike01", "profile": "spike", "station": "CA_Fallbrook_5_NE", "seed": 2}
        ]
        with self.assertRaisesRegex(ValueError, "spike_count_range"):
            validate_config(config)

    def test_failed_run_reports_engine_reason_and_data_diagnostics(self):
        config = load_config(CONFIG_PATH)
        config["profiles"]["bias"]["duration_hours_range"] = [6, 6]
        config["runs"] = [
            {"id": "gap01", "profile": "bias", "station": "CA_Fallbrook_5_NE", "seed": 4}
        ]
        config["output_dir"] = str(ROOT / "data" / "attacked" / "unused-gap-test-output")
        report = run_config(config, clean_data=synthetic_observations(24, gap=True))
        result = report["stations"]["CA_Fallbrook_5_NE"]["runs"][0]
        self.assertEqual(result["status"], "not_applied")
        self.assertIn("no feasible contiguous window", result["reason"])
        self.assertGreater(result["diagnostics"]["hourly_gaps"], 0)
        self.assertFalse(Path(config["output_dir"]).exists())

    def test_failed_run_reports_missing_and_bounds_diagnostics(self):
        config = load_config(CONFIG_PATH)
        config["profiles"]["bias"]["duration_hours_range"] = [6, 6]
        config["runs"] = [
            {"id": "bounds01", "profile": "bias", "station": "CA_Fallbrook_5_NE", "seed": 7}
        ]
        clean = synthetic_observations()
        clean["SOIL_MOISTURE_5"] = 0.64
        clean.loc[0, "SOIL_MOISTURE_5"] = None
        report = run_config(config, clean_data=clean)
        result = report["stations"]["CA_Fallbrook_5_NE"]["runs"][0]
        self.assertEqual(result["status"], "not_applied")
        self.assertEqual(result["diagnostics"]["missing_target_rows"], 1)
        self.assertGreater(result["diagnostics"]["bound_blocked_rows_at_range_endpoints"], 0)


if __name__ == "__main__":
    unittest.main()
