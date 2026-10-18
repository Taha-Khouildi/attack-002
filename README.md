# TSYP14 — False-Data Injection Attack Toolkit

**Track 2: Ground Truth Under Attack — False-Data Injection**

A Python toolkit for creating controlled false-data injection scenarios against a simulated environmental sensor data pipeline. The project focuses on attacks on **soil-moisture measurements** and **signed sensor packets**, with separate ground-truth labels for evaluation.

> **Project status:** Work in progress. Some runner configuration, event-validation fixes, and end-to-end Stage-1 integration checks are pending. This README describes the project's intended workflow and the attack behavior developed so far; verify file locations and commands against the current branch.

## Project goals

- Create reproducible attack scenarios for cybersecurity and anomaly-detection testing.
- Test whether packet-level security controls reject altered, duplicated, or malformed signed messages.
- Study attacks that can contain plausible, correctly signed but physically false sensor readings.
- Keep attack ground truth **separate** from the sensor packets so detectors cannot read the answers directly.

The main sensor feature used in the examples is `SOIL_MOISTURE_5`, based on processed USCRN observations.

## Attack types

### 1. Bias injection — before signing

Changes a sensor measurement over a selected time window while leaving the rest of the record unchanged.

- **Constant offset:** Adds a configured offset to eligible values within a contiguous window.
- **Spike:** Adds short, isolated changes at selected observations.

Because these modifications can occur **before** packet signing, the resulting packet can still have a valid hash and signature. Cryptographic validation by itself cannot prove that a reading is physically true.

**Provisional parameter guidance (not the final scenario specification):**

| Scenario | Proposed magnitude | Other settings |
| --- | --- | --- |
| Constant Bias | Positive offset of `+0.02` to `+0.08` | Duration of `6–72` hours |
| Spike | Positive magnitude of `+0.03` to `+0.10` | Duration, count, and per-station allocation **not finalized** |

Values are expressed in the dataset's measurement units, not percentages. An interim `0–0.65` soil-moisture value guard has been used while a contract/schema bound discrepancy is resolved. The final parameters and allowed signs must be confirmed with the team.

### 2. Replay — after signing

Takes an already signed packet and inserts a byte-for-byte equivalent packet later in the delivery stream. Its signature can remain valid, but it should be detected as a replay through sequence-number, nonce, or freshness checks, depending on the receiving gate's behavior.

### 3. Tamper — after signing

Applies controlled changes to a signed packet to test validation and rejection behavior.

| Tamper mode | What changes | Predicted rejection |
| --- | --- | --- |
| `payload_only` | Payload changes; old hash and signature remain | `E_PAYLOAD_HASH` |
| `recompute_hash_keep_signature` | Payload and hash change; old signature remains | `E_BAD_SIG` |
| `signed_header_change` | A signed header field changes without resigning | `E_BAD_SIG` |
| `signature_flip` | Signature bytes change | `E_BAD_SIG` |
| `station_swap` | Station changes while the original key ID remains | `E_UNKNOWN_KEY` |
| `drop_field` | A required packet field is removed | `E_SCHEMA` |

**Important:** These are **predicted** Stage-1 results, not confirmed outcomes from the receiving team's Stage-1 gate. Validation diagnostics and actual gate results must be distinguished.

## Data and packet conventions

The project uses a shared data contract. Refer to the contract files in the repository for authoritative field definitions, ranges, and timestamp requirements:

- `data_contract.md`
- `data_contract.schema.json`
- `validate.py`

The signed packet format uses these fields:

```text
v, key_id, station, seq, ts, sent_at, nonce,
payload, payload_sha256, sig
```

The packet hash and signature cover specific canonical data defined by the contract. **Do not edit a signed packet just to correct a label or an event description.**

For observation-based attack exports, ground-truth labels use:

```text
is_attacked, attack_type, attack_run_id
```

An attack function keeps labels separate from the observation data; labels may be joined for a designated attacked-data export. **Signed packet streams must not contain ground-truth labels.**

Event records describe each attack and use fields such as:

```text
attack_run_id, station, attack_type, target_columns,
start, end, params_json, seed, engine_version
```

The `start` and `end` timestamp format for Replay/Tamper events is under review because an event-validation error was reported. Confirm the exact validator requirement before changing any timestamps; do not alter signed packet `ts` or `sent_at` as a workaround.

## Main project files

The following names are associated with the project; availability may vary by branch:

| File or directory | Purpose |
| --- | --- |
| `attack_engine.py` | Implements Bias/Spike data attacks and Replay/Tamper packet attacks. |
| `test_attack_engine.py` | Automated tests for the attack engine. |
| `make_attacks.py` | Planned/configuration-based runner for generating attack batches; check whether it has been added. |
| `data_contract.md` | Human-readable shared data contract. |
| `data_contract.schema.json` | Machine-readable contract/schema rules. |
| `validate.py` | Data and event validation utility. |
| `data/processed/` | Processed clean observations, when available locally. |
| `data/attacked/` | Generated attacked observations, packet streams, and sidecar metadata, when available. |

## Getting started

### Prerequisites

- Python 3 and `pip`.
- Access to the clean or signed input data needed for the scenario you want to run.
- Any Python dependencies required by your checked-out version of the code.

Clone the repository:

```bash
git clone https://github.com/Taha-Khouildi/attack-002.git
cd attack-002
```

Create a virtual environment:

**Windows PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies **once `requirements.txt` is present and verified**:

```bash
python -m pip install -r requirements.txt
```

> Dependency versions and the exact minimum Python version have not been verified against the remote repository. Do not assume that the requirements file already exists.

## Running tests

If the repository includes `test_attack_engine.py` using Python's `unittest`, run:

```bash
python -m unittest test_attack_engine -v
```

For test discovery across the repository:

```bash
python -m unittest discover -v
```

Run contract and event validation using the commands supported by the current `validate.py`; check its help or documented CLI before supplying arguments:

```bash
python validate.py --help
```

A passing local validator does **not** establish that the Stage-1 gate produced the predicted rejection codes. Test those packets against the gate separately.

## Generating attacks

The attack engine provides two main interfaces:

- `attack_data(clean_data, params)` — create Bias or Spike modifications to observations.
- `attack_packet(signed_packets, params)` — create Replay or Tamper packet streams.

The exact parameter structures are defined in `attack_engine.py` and its tests. They should be treated as authoritative.

A separate **configuration-driven runner** (`make_attacks.py`) is planned or under development so scenario magnitudes and allocations can be updated without modifying `attack_engine.py`. Its configuration format should match the format agreed with the other attacker; do not assume JSON or YAML until that is confirmed.

**Until the final scenario specification is available:**

- Do not invent Spike duration, Spike count, event frequency, or per-station allocation.
- Keep provisional runs distinctly named (for example, `provisional_v2`).
- Keep held-out scenarios separate from training and calibration exports.
- Report unapplied attacks caused by missing observations, invalid windows, or value bounds rather than silently changing the requested parameters.

## Testing flow

1. Prepare clean observation records or a valid signed-packet input stream.
2. Select the scenario and a reproducible random seed.
3. Generate the attacked observations or packet stream.
4. Write attack labels and event information separately from the signed packets.
5. Validate output structure and event metadata using the shared contract.
6. For Replay and Tamper, submit packets to the Stage-1 gate and compare its **actual** per-packet results with the predicted ones.
7. For anomaly-detection experiments, share the appropriate attacked dataset and a change note describing how its parameters differ from the previous batch.

### Expected Stage-1 checks

The shared contract describes the following rejection/status categories:

```text
E_SCHEMA
E_UNKNOWN_KEY
E_PAYLOAD_HASH
E_BAD_SIG
E_REPLAY_SEQ
E_REPLAY_NONCE
E_STALE
OK
```

An example Replay stream generated from five valid packets inserted a duplicate at delivery index `4`. The duplicate was predicted to produce `E_REPLAY_SEQ`; subsequent decisions can depend on how the gate handles state after a rejected packet. This remains an integration test case, not a verified Stage-1 outcome.

## Reproducibility and safety

- Use explicit seeds and record the scenario parameters for each run.
- Keep packet files and their accompanying ground-truth/expected-result sidecars separate.
- Preserve original input files and generate outputs under distinct names.
- Verify signed packet content is unchanged when only event metadata needs fixing.
- Avoid committing private keys, sensitive local paths, or private datasets to a public repository.
- Use these attack scenarios only in authorized test and research environments.

## Current limitations

- Final attack magnitudes, event counts per station, and held-out allocations are pending team agreement.
- Spike duration and count for the provisional profile are unspecified.
- The Replay/Tamper event timestamp-validation issue still requires confirmation and correction.
- Predicted Stage-1 error codes need verification against the real receiving gate.
- The configuration runner and its command-line usage should be documented more precisely once finalized in code.

---

**Repository:** [Taha-Khouildi/attack-002](https://github.com/Taha-Khouildi/attack-002)
