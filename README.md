# TSYP14 attack engine

This repository contains a deterministic attack engine for USCRN soil-moisture
observations. It implements pre-sign Bias attacks (constant offset and Spike
mode) and post-sign Replay and Tamper packet attacks. The engine returns
attacked data, separate ground-truth labels, and contract-shaped event records.

## Install and test

```powershell
pip install -r requirements.txt
python -m unittest discover -v
```

## Run the configured batch

The JSON configuration is [config/provisional_v2.json](config/provisional_v2.json).
It accepts the 2024 and 2025 observation years. Run:

```powershell
python make_attacks.py --config config/provisional_v2.json
```

Each configured run specifies one `year` allowed by its profile. The runner
reserves the selected attack window before choosing the next event, then writes
one labeled CSV per station and interval-start year (`annee`), plus one event
ledger:

```text
data/attacked/provisional_v2/<station>_<year>.csv
data/attacked/provisional_v2/attack_events.csv
```

Attack events in the same station-year file are non-overlapping. Labels are
written as the contract strings `attack_type` and `attack_run_id`; clean rows
have empty strings.
The supplied configuration has `runs: []`, so the command currently reports
that no runs are configured and writes no new dataset files. The Spike profile
is disabled until its duration and count ranges are supplied.

## Validate outputs

```powershell
python validate.py attacked <file>
python validate.py events <file>
```

Illustrative validator output after runs have been configured and generated:

```text
data/attacked/provisional_v2/CA_Fallbrook_5_NE_2024.csv: VALID against contract v1.0.0
data/attacked/provisional_v2/attack_events.csv: VALID against contract v1.0.0
```

The clean input is `data/processed/uscrn_clean.parquet`. Contract definitions
are in [data_contract.md](data_contract.md) and
[data_contract.schema.json](data_contract.schema.json).

`data/packets/replay_test_valid.jsonl` is a signed five-packet fixture. Its
observation timestamps are one second apart at packet generation time, so it
does not represent consecutive hourly USCRN observations. The repository
history identifies who committed the file, not who signed it. An hourly
replacement needs fresh signatures from the packet owner. Salma's Stage-1
gate has not been run in this repository.
