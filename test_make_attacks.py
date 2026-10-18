"""Focused checks for the configured station-year CSV runner."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

import pandas as pd

from attack_engine import EVENT_COLUMNS, LABEL_COLUMNS, TARGET_COLUMN
from make_attacks import load_config, run_config, validate_config


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "provisional_v2.json"
STATION = "CA_Fallbrook_5_NE"
OTHER_STATION = "AZ_Tucson_11_W"
OUTPUT_DIR = ROOT / "data" / "attacked" / "runner_unit_test_output"


def observations(hours=30, *, year=2024, station=STATION, start=None):
    start = start or f"{year}-06-01 00:00:00"
    return pd.DataFrame({
        "time": pd.date_range(start, periods=hours, freq="h"),
        "station": [station] * hours,
        "annee": [year] * hours,
        TARGET_COLUMN: [round(0.100 + (i % 10) / 1000, 3) for i in range(hours)],
        "P_CALC": [0.0] * hours,
    })


def configured(*runs):
    config = load_config(CONFIG_PATH)
    config["output_dir"] = str(OUTPUT_DIR)
    config["profiles"]["bias"]["duration_hours_range"] = [6, 6]
    config["profiles"]["bias"]["offset_range"] = [0.02, 0.02]
    config["runs"] = list(runs)
    return config


def run_entry(run_id, *, station=STATION, year=2024, profile="bias", seed=81):
    return {"id": run_id, "profile": profile, "station": station, "year": year, "seed": seed}


class TestMakeAttacks(unittest.TestCase):
    def tearDown(self):
        if OUTPUT_DIR.exists():
            for path in OUTPUT_DIR.iterdir():
                if path.is_file():
                    path.unlink()
            OUTPUT_DIR.rmdir()

    def test_config_profiles_and_empty_run_list(self):
        config = load_config(CONFIG_PATH)
        self.assertEqual(config["profiles"]["bias"]["years"], [2024, 2025])
        self.assertEqual(config["profiles"]["bias"]["offset_range"], [0.02, 0.08])
        self.assertEqual(config["profiles"]["bias"]["duration_hours_range"], [6, 72])
        self.assertFalse(config["profiles"]["spike"]["enabled"])
        self.assertEqual(config["runs"], [])
        config["output_dir"] = str(OUTPUT_DIR)
        report = run_config(config)
        self.assertEqual(report["configured_runs"], 0)
        self.assertFalse(OUTPUT_DIR.exists())

    def test_bias_is_reproducible_and_preserves_source(self):
        clean = observations()
        before = clean.copy(deep=True)
        config = configured(run_entry("first"))
        first = run_config(config, clean)
        csv = OUTPUT_DIR / f"{STATION}_2024.csv"
        events = OUTPUT_DIR / "attack_events.csv"
        first_bytes = (csv.read_bytes(), events.read_bytes())
        csv.unlink()
        events.unlink()
        second = run_config(config, clean)
        self.assertEqual(first["output_files"], second["output_files"])
        self.assertEqual(first_bytes, (csv.read_bytes(), events.read_bytes()))
        json.dumps(first)
        pd.testing.assert_frame_equal(clean, before)
        output = pd.read_csv(csv, keep_default_na=False)
        self.assertEqual(list(output.columns), list(clean.columns) + LABEL_COLUMNS)
        self.assertEqual(int(output["is_attacked"].sum()), 6)
        self.assertEqual(set(output.loc[output.is_attacked, "attack_type"]), {"bias"})
        self.assertEqual(set(output.loc[~output.is_attacked, "attack_type"]), {""})
        self.assertEqual(set(output.loc[~output.is_attacked, "attack_run_id"]), {""})
        self.assertEqual(list(pd.read_csv(events).columns), EVENT_COLUMNS)

    def test_multiple_events_share_one_station_year_file_without_overlap(self):
        config = configured(run_entry("one", seed=1), run_entry("two", seed=2))
        clean = observations(hours=30)
        report = run_config(config, clean)
        self.assertEqual(report["applied_runs"], 2)
        self.assertEqual(len(report["output_files"]), 2)
        output = pd.read_csv(OUTPUT_DIR / f"{STATION}_2024.csv", keep_default_na=False)
        events = pd.read_csv(OUTPUT_DIR / "attack_events.csv")
        self.assertEqual(int(output["is_attacked"].sum()), 12)
        self.assertEqual(len(events), 2)
        attacked_rows = output.loc[output["is_attacked"]]
        self.assertEqual(attacked_rows["attack_run_id"].nunique(), 2)
        self.assertEqual(set(attacked_rows["attack_type"]), {"bias"})
        self.assertEqual(set(events["attack_run_id"]), set(attacked_rows["attack_run_id"]))

    def test_reserved_window_causes_later_run_to_be_unapplied(self):
        config = configured(run_entry("one", seed=1), run_entry("two", seed=2))
        report = run_config(config, observations(hours=6))
        self.assertEqual(report["applied_runs"], 1)
        self.assertEqual(report["not_applied_runs"], 1)
        second = report["stations"][STATION]["runs"][1]
        self.assertIn("not present in clean_data", second["reason"])
        self.assertEqual(len(pd.read_csv(OUTPUT_DIR / "attack_events.csv")), 1)

    def test_spike_reserves_full_window_including_unchanged_hours(self):
        config = configured(
            run_entry("spike", profile="spike", seed=1),
            run_entry("bias", seed=2),
        )
        config["profiles"]["spike"].update({
            "enabled": True,
            "duration_hours_range": [6, 6],
            "spike_count_range": [2, 2],
            "spike_magnitude_range": [0.03, 0.03],
        })
        report = run_config(config, observations(hours=6))
        self.assertEqual(report["applied_runs"], 1)
        self.assertEqual(report["not_applied_runs"], 1)
        output = pd.read_csv(OUTPUT_DIR / f"{STATION}_2024.csv")
        self.assertEqual(int(output["is_attacked"].sum()), 2)
        self.assertEqual(len(pd.read_csv(OUTPUT_DIR / "attack_events.csv")), 1)

    def test_separate_station_year_outputs_and_interval_start_year(self):
        config = configured(
            run_entry("a", year=2024),
            run_entry("b", year=2025, seed=42),
            run_entry("c", station=OTHER_STATION, year=2024, seed=43),
        )
        year_end = observations(hours=8, year=2025, start="2025-12-31 17:00:00")
        # Last row is 2025's closing interval at midnight on 2026-01-01.
        clean = pd.concat([observations(hours=8), year_end, observations(hours=8, station=OTHER_STATION)], ignore_index=True)
        report = run_config(config, clean)
        self.assertEqual(report["applied_runs"], 3)
        self.assertEqual(len(report["output_files"]), 4)
        output = pd.read_csv(OUTPUT_DIR / f"{STATION}_2025.csv")
        self.assertEqual(len(output), 8)
        self.assertEqual(int(output["is_attacked"].sum()), 6)
        self.assertFalse(bool(output.iloc[-1]["is_attacked"]))
        self.assertEqual(len(pd.read_csv(OUTPUT_DIR / "attack_events.csv")), 3)

    def test_existing_destination_preflight_prevents_all_writes(self):
        config = configured(run_entry("a"), run_entry("b", station=OTHER_STATION))
        clean = pd.concat([observations(hours=8), observations(hours=8, station=OTHER_STATION)], ignore_index=True)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        existing = OUTPUT_DIR / f"{OTHER_STATION}_2024.csv"
        existing.write_text("do not overwrite", encoding="utf-8")
        with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
            run_config(config, clean)
        self.assertEqual(existing.read_text(encoding="utf-8"), "do not overwrite")
        self.assertEqual(list(OUTPUT_DIR.iterdir()), [existing])

    def test_invalid_year_and_disabled_spike_are_rejected(self):
        config = configured(run_entry("a", year=2023))
        with self.assertRaisesRegex(ValueError, "year must be one of"):
            validate_config(config)
        config = configured(run_entry("a", profile="spike"))
        with self.assertRaisesRegex(ValueError, "disabled profile"):
            validate_config(config)
        config["profiles"]["spike"]["enabled"] = True
        with self.assertRaisesRegex(ValueError, "duration_hours_range"):
            validate_config(config)

    def test_failed_run_reports_gaps_missing_and_bounds(self):
        config = configured(run_entry("a"))
        clean = observations(hours=20)
        clean["time"] = pd.date_range("2024-06-01", periods=20, freq="2h")
        report = run_config(config, clean)
        result = report["stations"][STATION]["runs"][0]
        self.assertEqual(result["status"], "not_applied")
        self.assertGreater(result["diagnostics"]["hourly_gaps"], 0)
        self.assertFalse(OUTPUT_DIR.exists())
        clean = observations(hours=8)
        clean[TARGET_COLUMN] = 0.64
        clean.loc[0, TARGET_COLUMN] = None
        report = run_config(config, clean)
        result = report["stations"][STATION]["runs"][0]
        self.assertEqual(result["diagnostics"]["missing_target_rows"], 1)
        self.assertGreater(result["diagnostics"]["bound_blocked_rows_at_range_endpoints"], 0)

    def test_representative_station_year_and_event_outputs_validate(self):
        # Use a small 2024 slice solely as a contract-shaped fixture. The
        # temporary runner outputs are removed by tearDown.
        source = pd.read_parquet(ROOT / "data" / "processed" / "uscrn_clean.parquet")
        sample = source.loc[
            source["station"].eq(STATION) & source["annee"].eq(2024)
        ].head(100).copy()
        config = configured(run_entry("validator", seed=9))
        report = run_config(config, sample)
        self.assertEqual(report["applied_runs"], 1)
        for command, path in (
            ("attacked", OUTPUT_DIR / f"{STATION}_2024.csv"),
            ("events", OUTPUT_DIR / "attack_events.csv"),
        ):
            result = subprocess.run(
                [sys.executable, "-B", "validate.py", command, str(path)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
