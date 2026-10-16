# Data Contract — USCRN Soil-Moisture Pipeline

**Version 1.0.0 — DRAFT, not yet frozen.** See Appendix A for versioning rules. **Track:** 2 — False-Data Injection · **Owner:** Team lead **Machine-readable form:** `data_contract.schema.json` · **Checker:** `validate.py`

---

## 0\. Read this first

**What this document is.** This contract fixes the format of every file that moves between team members: the clean observations, the signed packets, the attacked datasets and the detector outputs. If your file passes `validate.py`, anyone downstream can use it without asking you how you made it. If it fails, fix your file, not theirs.

**Who should read it.**

| Role | Read first | Skim |
| :---- | :---- | :---- |
| Crypto owner | §3 (pipeline), §4 (example), §8 (packets) | §6–7 |
| Attack owner A (replay, tamper, bias) | §3, §4, §5 (attacks), §6–7, §9 | §8 |
| Attack owner B (drift, mimicry) | §3, §4, §5, §6–7, §9 | §8 |
| AI lead | §3, §4, §5, §7.3–7.4, §9–12 | §8 |
| Team lead / integration | Everything | — |

**How the pipeline fits together.** We replay real hourly USCRN soil-moisture data through an emulated sensor node. The node signs each hourly reading with its Ed25519 key and sends it as a packet. **Stage 1** (the crypto gate) rejects packets that are forged, altered in transit or replayed. **Stage 2** (the AI detector) scores the packets that pass, because a compromised node holds a valid key and can sign false values. The attack engine attacks both points: before signing (a lying sensor) and after signing (an attacker on the network). Every attack is labelled, so the evaluation can measure what each stage caught.

**If something is unclear,** do not guess and do not work around the contract. Ask the team lead, or open a repository issue labelled `contract`. If the contract is wrong, it gets fixed and re-versioned (Appendix A), so everyone moves together.

**Quick check, run before every handoff:**

python validate.py observations data/processed/uscrn\_clean.parquet

python validate.py attacked     data/attacked/bias\_run01.csv

python validate.py events       data/attacked/attack\_events.csv

python validate.py packets      data/packets/OK\_Goodwell\_2\_E.jsonl \--pubkeys keys/pubkeys.json

Exit code `0` \= valid, `1` \= contract violation (the output lists each problem).

---

## 1\. Open questions

All four data questions are resolved (answers from the AI lead, 14 Oct 2026).

| \# | Question | Answer | Effect on the contract |
| :---- | :---- | :---- | :---- |
| Q1 | Are timestamps UTC, marking the end of each hour? | **Yes.** Also confirmed from the data: peak solar radiation falls at a later UTC hour the further west a station is | None. §7.1 stands |
| Q2 | What does `flag_incoherence_verticale` mean, and why is it always `false`? | The vertical-consistency check ran; no row met its anomaly conditions | Column kept as a record of the check. Always `false` in v1 |
| Q3 | What happened to the USCRN quality flags? | Readings flagged invalid by NOAA were set to `NaN`; the flag columns were then removed | A `NaN` means either a sensor outage or a NOAA-invalid reading (§6). Neither is ever an attack |
| Q4 | Why these 6 stations? | 5 stations in different climates, plus a second Goodwell station close to the first, for spatial-consistency checks | Report sentence. §7.3 stands |

---

## 2\. Who does what

Roles only, because this file goes into the anonymous Phase 1 repository.

| Role | Owns | Uses the contract for |
| :---- | :---- | :---- |
| Crypto owner | Trust anchor, sensor emulator, Stage 1 gate | Packet format, canonical bytes, gate codes (§8). Writes `data/packets/*.jsonl` |
| Attack owner A | `replay`, `tamper`, `bias` | Label columns and events file (§9), bounds and resolution (§7.2), gaps to avoid (§7.4). Sends replay/tamper output to the crypto owner and bias output to the AI lead |
| Attack owner B | `drift`, `mimicry` | Same as attack owner A; also the context columns that make mimicry plausible (§7.2) |
| AI lead | Clean dataset, Stage 2 detector, future context source | Observation schema (§7), evaluation split (§12), detector output (§10), planned columns and context slot (§11, §11b) |
| Team lead | This contract, threat model, trust-score definition, final report | Approves every change (Appendix A). Owns integration and metrics until that role is assigned |

---

## 3\. How data flows

 data/raw/                      Raw USCRN hourly files (NOAA)

     │

     │  cleaning (AI lead)

     ▼

 data/processed/uscrn\_clean.parquet Clean observations (§7) ──────────────────┐

     │                                                                        │

     │                      ┌───────────────────────────────┐                 │

     ├─────────────────────►│ ATTACK ENGINE — PRE-SIGN      │                 │

     │                      │ bias · drift · mimicry        │                 │

     │                      │ (the sensor itself lies)      │                 │

     │                      └──────────────┬────────────────┘                 │

     │                                     │ data/attacked/\<run\>.csv          │

     │                                     │ data/attacked/attack\_events.csv  │

     ▼                                     ▼  (labels removed before signing) │

 ┌─────────────────────────────────────────────────┐                          │

 │ SENSOR EMULATOR (crypto owner)                  │                          │

 │ one packet per station-hour, Ed25519-signed     │                          │

 └──────────────────────┬──────────────────────────┘                          │

                        │ data/packets/\<station\>.jsonl (§8)                   │

                        ▼                                                     │

              ┌───────────────────────────────┐                               │

              │ ATTACK ENGINE — POST-SIGN     │                               │

              │ replay · tamper               │                               │

              │ (attacker on the network)     │                               │

              └──────────────┬────────────────┘                               │

                             ▼                                                │

 ┌─────────────────────────────────────────────────┐                          │

 │ STAGE 1 — CRYPTO GATE                           │                          │

 │ schema · key · hash · signature · seq · nonce · │──► rejected: gate\_status │

 │ staleness                                       │    E\_\* (logged)          │

 └──────────────────────┬──────────────────────────┘                          │

                        │ gate\_status \= OK                                    │

                        ▼                                                     │

 ┌─────────────────────────────────────────────────┐                          │

 │ STAGE 2 — AI DETECTOR (AI lead)                 │                          │

 │ trust\_score 0–1 → decision accept/flag/reject   │                          │

 └──────────────────────┬──────────────────────────┘                          │

                        ▼                                                     │

 outputs/detector\_output.csv (§10)                                            │

                        │                                                     │

                        ▼                                                     │

 ┌─────────────────────────────────────────────────┐   labels and events      │

 │ EVALUATION HARNESS                              │◄─────────────────────────┘

 │ detection rate · false alarms · latency ·       │   (only the harness

 │ memory · crypto overhead                        │    reads labels)

 └─────────────────────────────────────────────────┘

**Two attack points, two catchers.**

- **Pre-sign attacks** (`bias`, `drift`, `mimicry`) alter values *before* the node signs them. The signature is valid, so Stage 1 lets them through. Stage 2 must catch them.  
- **Post-sign attacks** (`replay`, `tamper`) alter or resend packets *after* signing. Stage 1 must catch them.

The folder paths above are the agreed repository layout. Private signing keys are never committed: only `keys/pubkeys.json` (public keys) goes into the repo.

---

## 4\. One record, end to end

Real values: station `OK_Goodwell_2_E`, hour ending **2025-05-04 14:00 UTC**, a dry spring afternoon with no rain.

### Step 1 — Clean record (`data/processed/uscrn_clean.parquet`)

Selected columns:

| time | station | SOIL\_MOISTURE\_5 | SOIL\_MOISTURE\_10 | SOIL\_TEMP\_5 | T\_HR\_AVG | P\_CALC |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| 2025-05-04 14:00:00 | OK\_Goodwell\_2\_E | 0.164 | 0.211 | 14.4 | 12.8 | 0.0 |

Around this hour, 5 cm moisture stays between 0.164 and 0.166, and there is no rain.

### Step 2 — Signed packet (`data/packets/OK_Goodwell_2_E.jsonl`, one line)

This is a real, verifiable packet. It was signed with a **demonstration key** whose public key is `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`. That key is published here, so it must never be used in the real pipeline. In this run the emulator numbered packets from `seq = 0` at the station's first hour.

{

  "v": "1.0.0",

  "key\_id": "OK\_Goodwell\_2\_E-k1",

  "station": "OK\_Goodwell\_2\_E",

  "seq": 29269,

  "ts": "2025-05-04T14:00:00Z",

  "sent\_at": "2025-05-04T14:00:04Z",

  "nonce": "9f2c4e0a7b1d3c5e8f6a2b4d0c1e3f57",

  "payload\_sha256": "a41465971874a9c98e901bbd94d528dda75f34e5f6c95d495cac96d25c4f283d",

  "payload": {

    "T\_HR\_AVG": 12.8, "T\_MAX": 14.3, "T\_MIN": 10.2, "P\_CALC": 0.0,

    "SOLARAD": 224.0, "SUR\_TEMP": 12.6, "RH\_HR\_AVG": 65.0,

    "SOIL\_MOISTURE\_5": 0.164, "SOIL\_MOISTURE\_10": 0.211, "SOIL\_MOISTURE\_20": 0.223,

    "SOIL\_MOISTURE\_50": 0.388, "SOIL\_MOISTURE\_100": 0.251,

    "SOIL\_TEMP\_5": 14.4, "SOIL\_TEMP\_10": 15.0, "SOIL\_TEMP\_20": 15.4,

    "SOIL\_TEMP\_50": 15.3, "SOIL\_TEMP\_100": 15.0

  },

  "sig": "fe78b842be0d1e179028ab2ff0c099e67e4b928e9cb7b1008eaa87c9293ed75e2fecdaeaa8455789c691a7b04852dc299c0b79a3bafef8167503122a2321a90f"

}

The gate returns `OK`.

### Step 3 — Attacked record

**Case A — `bias` (pre-sign).** The compromised node adds \+0.060 m³/m³ to 5 cm moisture for 24 hours, starting at 12:00. Row in `data/attacked/bias_run01.csv` (selected columns):

| time | station | SOIL\_MOISTURE\_5 | P\_CALC | is\_attacked | attack\_type | attack\_run\_id |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| 2025-05-04 14:00:00 | OK\_Goodwell\_2\_E | **0.224** (was 0.164) | 0.0 | true | bias | bias-r01 |

Matching line in `data/attacked/attack_events.csv`:

attack\_run\_id,station,attack\_type,target\_columns,start,end,params\_json,seed,engine\_version

bias-r01,OK\_Goodwell\_2\_E,bias,SOIL\_MOISTURE\_5,2025-05-04 12:00:00,2025-05-05 11:00:00,"{""offset"": 0.06}",7,0.1.0

The node signs the false value 0.224, so the new packet has a new `payload_sha256` (`0bd21cae…7a31e0`) and a valid signature. **The gate returns `OK`.** Only Stage 2 can catch this.

**Case B — `tamper` (post-sign).** An attacker edits the Step 2 packet in transit, changing `SOIL_MOISTURE_5` to 0.224 without re-signing. The payload no longer matches `payload_sha256`, so **the gate returns `E_PAYLOAD_HASH`** and the packet never reaches Stage 2\.

### Step 4 — Detector output (`outputs/detector_output.csv`)

The `trust_score` and `latency_ms` values below are illustrative, since no detector exists yet. The format is binding.

| station | time | gate\_status | trust\_score | decision | latency\_ms | detector\_version |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| OK\_Goodwell\_2\_E | 2025-05-04 14:00:00 | OK | 0.12 | flag | 3.4 | det-0.1.0 |
| OK\_Goodwell\_2\_E | 2025-05-04 14:00:00 | E\_PAYLOAD\_HASH |  | reject | 0.2 | det-0.1.0 |

Row 1 is Case A. The physics gives it away: 5 cm moisture jumped 0.06 with no rain, and the 5 cm layer is now wetter than 10 cm (0.211). Row 2 is Case B, and `trust_score` is empty because Stage 2 never saw it.

The evaluation harness joins these rows with the labels from Step 3 and counts Case A as a true detection by Stage 2 and Case B as a true detection by Stage 1\.

---

## 5\. Attacks

| Code | What it does | Injected | Caught by | Example |
| :---- | :---- | :---- | :---- | :---- |
| `replay` | Resends an old packet that was validly signed, so old data looks current | Post-sign, on the network | Stage 1: `E_REPLAY_SEQ`, `E_REPLAY_NONCE` or `E_STALE` | The 2025-05-04 14:00 packet is sent again on 2025-05-06 |
| `tamper` | Alters a packet's content after signing, without re-signing | Post-sign, on the network | Stage 1: `E_PAYLOAD_HASH` (payload altered) or `E_BAD_SIG` (header altered) | `SOIL_MOISTURE_5` 0.164 → 0.224 in transit (§4, Case B) |
| `bias` | Adds a constant offset or spikes to the protected value | Pre-sign, compromised node with a valid key | Stage 2 | \+0.060 m³/m³ for 24 h (§4, Case A) |
| `drift` | Adds a slow ramp, too gradual for simple thresholds | Pre-sign, compromised node | Stage 2 | \+0.002 m³/m³ per hour over 3 days |
| `mimicry` | Fakes a plausible event using real context, to look natural | Pre-sign, compromised node | Stage 2 | A realistic wetting-then-drying curve inserted on a day with `P_CALC = 0` |
| `heldout` | Hidden variants that the detector never sees in training | Either point | Either stage | Not disclosed. Only the SHA-256 of the held-out code and data is committed, before tuning starts |

Example parameters are illustrative; each attack's real parameters are recorded in `params_json` (§9.2).

**Rules for every attack:**

- Never inject inside a known data gap (§7.4). A missing reading is a *missing-data* event, never an attack.  
- Round injected values to the column's resolution (§7.2). Extra decimals give the attack away trivially.  
- Keep injected values inside the hard bounds (§7.2). Otherwise the schema check rejects them, which proves nothing about the detector.

---

## 6\. Source dataset

| Property | Value |
| :---- | :---- |
| Source | NOAA U.S. Climate Reference Network (USCRN), Hourly02 product: 24 raw text files (6 stations × 4 years) |
| File | `data/processed/uscrn_clean.parquet` (a `.csv` export with the same columns is also accepted) |
| Provenance | Built by `clean_uscrn.py` from the raw files in `USCRN_final/`; every correction is logged in `uscrn_rapport_qualite.csv` (by station, year and column). See the AI lead's cleaning report |
| Stations | 6 (§7.3) |
| Period | 2022-01-01 01:00 to 2026-01-01 00:00 (UTC) |
| Rows | 210,384 \= 6 stations × 35,064 hours |
| Grid | Complete hourly grid: one row per station per hour, no duplicates, no missing rows |
| Missing values | Empty cell or `NaN` only. The USCRN sentinel `-9999` must never appear. A `NaN` is a sensor outage (including frozen soil, §7.4), a NOAA missing code (`-99`, `-9999`, `-99999`), a reading with a NOAA quality flag ≠ 0, or a value outside the hard bounds. Rows are never deleted, only values |
| Gap filling | None. Missing readings stay `NaN`; nothing is interpolated |

**Protected asset:** `SOIL_MOISTURE_5` (volumetric soil moisture at 5 cm). Every other column is context the detector may use.

---

## 7\. Observation record (one row \= one station, one hour)

### 7.1 Keys and time

| Column | Type | Rule |
| :---- | :---- | :---- |
| `time` | timestamp | `YYYY-MM-DD HH:MM:SS`, **UTC**, marks the **end** of the hourly interval (USCRN convention). `2022-01-01 01:00:00` covers 00:00–01:00 UTC. Minutes and seconds are always `00` |
| `station` | string | Must exist in the station registry (§7.3) |
| `annee` | integer | Year of the **start** of the interval, so the row at `2026-01-01 00:00:00` has `annee = 2025`. Derived; never used as a feature |

`(station, time)` is the primary key and must be unique.

### 7.2 Measurements

**Hard bounds** are physical limits, the same ones the cleaning step applied. A value outside them is impossible, so the record is malformed and fails schema validation (`E_SCHEMA` at the gate). A value inside the bounds but unusual is **not** rejected here; judging plausibility is Stage 2's job.

| Column | Unit | Hard bounds | Resolution | Observed range (2022–2025) | Notes |
| :---- | :---- | :---- | :---- | :---- | :---- |
| `LATITUDE` | degrees | \= registry value | — | 32.24 – 42.44 | Constant per station |
| `LONGITUDE` | degrees | \= registry value | — | −117.19 – −76.25 | Constant per station |
| `T_HR_AVG` | °C | −60 – 70 | 0.1 | −28.9 – 43.9 | Mean air temperature over the hour |
| `T_MAX` | °C | −60 – 70 | 0.1 | −27.9 – 44.9 | Hourly max air temperature |
| `T_MIN` | °C | −60 – 70 | 0.1 | −30.3 – 43.4 | Hourly min air temperature |
| `P_CALC` | mm | 0 – 200 | 0.1 | 0 – 76.1 | Precipitation over the hour |
| `SOLARAD` | W/m² | 0 – 1600 | 1 | 0 – 1075 | Mean global solar radiation |
| `SUR_TEMP` | °C | −60 – 70 | 0.1 | −33.3 – 69.1 | Ground surface (infrared) temperature |
| `RH_HR_AVG` | % | 0 – 100 | 1 | 0 – 100 | Mean relative humidity |
| **`SOIL_MOISTURE_5`** | m³/m³ | 0 – 0.70 | 0.001 | 0.009 – 0.523 | **Protected asset** |
| `SOIL_MOISTURE_10` | m³/m³ | 0 – 0.70 | 0.001 | 0.021 – 0.544 |  |
| `SOIL_MOISTURE_20` | m³/m³ | 0 – 0.70 | 0.001 | 0.085 – 0.518 | Absent at 2 stations (§7.3) |
| `SOIL_MOISTURE_50` | m³/m³ | 0 – 0.70 | 0.001 | 0.102 – 0.568 | Absent at 2 stations |
| `SOIL_MOISTURE_100` | m³/m³ | 0 – 0.70 | 0.001 | 0.005 – 0.547 | Absent at 2 stations |
| `SOIL_TEMP_5` | °C | −60 – 70 | 0.1 | −2.9 – 57.8 |  |
| `SOIL_TEMP_10` | °C | −60 – 70 | 0.1 | −1.4 – 52.5 |  |
| `SOIL_TEMP_20` | °C | −60 – 70 | 0.1 | 0.3 – 31.2 | Absent at 2 stations |
| `SOIL_TEMP_50` | °C | −60 – 70 | 0.1 | 0.8 – 29.6 | Absent at 2 stations |
| `SOIL_TEMP_100` | °C | −60 – 70 | 0.1 | 1.7 – 28.7 | Absent at 2 stations |
| `flag_incoherence_verticale` | boolean | `true` / `false` | — | always `false` | Cleaning check: a 5 cm rise \> 0.10 m³/m³ with a 10 cm response \< 0.01 and no rain over 3 h. No case found (Q2). **Not a detector feature**: attack files keep the clean value and never recompute it |

**Consistency rules (hard):**

- `T_MIN ≤ T_HR_AVG ≤ T_MAX` whenever all three are present (tolerance 0.1 °C).  
- If the registry lists no sensor at a depth for a station, that depth is `NaN` on every row for that station.

### 7.3 Station registry

The same data is stored machine-readably in `data_contract.schema.json` → `station_registry`.

| Station | Climate | Lat | Lon | Rain/yr | Soil depths (cm) | Key ID |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| AZ\_Tucson\_11\_W | Arid | 32.24 | −111.17 | 223 mm | 5, 10 | `AZ_Tucson_11_W-k1` |
| CA\_Fallbrook\_5\_NE | Mediterranean | 33.44 | −117.19 | 428 mm | 5, 10 | `CA_Fallbrook_5_NE-k1` |
| MS\_Newton\_5\_ENE | Humid subtropical | 32.34 | −89.07 | 1,439 mm | 5, 10, 20, 50, 100 | `MS_Newton_5_ENE-k1` |
| NY\_Ithaca\_13\_E | Cold continental | 42.44 | −76.25 | 1,047 mm | 5, 10, 20, 50, 100 | `NY_Ithaca_13_E-k1` |
| OK\_Goodwell\_2\_SE | Semi-arid plains | 36.57 | −101.61 | 443 mm | 5, 10, 20, 50, 100 | `OK_Goodwell_2_SE-k1` |
| OK\_Goodwell\_2\_E | Twin of 2\_SE | 36.60 | −101.59 | 454 mm | 5, 10, 20, 50, 100 | `OK_Goodwell_2_E-k1` |

At Tucson and Fallbrook, vertical consistency can only compare 5 cm with 10 cm.

**The Goodwell pair** (3.8 km apart) supports a spatial-consistency check. Figures from the cleaning report:

| Fact | Value | Why it matters |
| :---- | :---- | :---- |
| Systematic offset | 2\_SE reads **0.056 m³/m³** higher than 2\_E (95.3 % of hours) | Remove it before comparing the two stations |
| Correlation of levels | 0.907 | Compare levels, which track each other well |
| Correlation of hourly changes | 0.415 | Do not compare hour-to-hour changes |
| Spatial-check threshold | **0.095 m³/m³** on offset-corrected levels | 99th percentile of the normal difference. A detector should flag above it. An attack that stays below it evades this check, so the attacks must test both cases |

### 7.4 Known data gaps (real sensor outages, not attacks)

| Station | `SOIL_MOISTURE_5` missing | Longest gap |
| :---- | :---- | :---- |
| OK\_Goodwell\_2\_E | 9.8 % | 2,687 h (\~112 days) |
| AZ\_Tucson\_11\_W | 2.4 % | 60 h |
| NY\_Ithaca\_13\_E | 2.1 % | 536 h |
| OK\_Goodwell\_2\_SE | 1.1 % | 108 h |
| CA\_Fallbrook\_5\_NE, MS\_Newton\_5\_ENE | \< 0.1 % | 5 h |

**Frozen soil.** In cold stations, the soil sensor stops measuring when the ground freezes. At Ithaca, 701 of the 727 missing hours have soil below 1 °C. These gaps are never filled. They are a winter blind spot of the detector, to be stated in the report as a limitation.

Attacks must not be injected inside these gaps, and evaluation windows skip them.

---

## 8\. Signed packet (Stage 1 input)

One packet \= one observation record (one station, one hour). Written as JSON Lines (`.jsonl`), one packet per line. A complete example is in §4, Step 2\.

| Field | Type | Rule |
| :---- | :---- | :---- |
| `v` | string | Contract version the packet follows |
| `key_id` | string | Must match the station's `key_id` in the registry |
| `station` | string | Registry station |
| `seq` | integer ≥ 0 | Per-station counter, **strictly increasing** by 1 per packet |
| `ts` | ISO 8601 UTC | Observation time \= the record's `time`, with `Z` |
| `sent_at` | ISO 8601 UTC | Emulated emission time, on the replay clock |
| `nonce` | 32 hex chars | 16 random bytes, never reused for the same key |
| `payload` | object | The measurement columns of §7.2, without `LATITUDE`, `LONGITUDE`, `annee` and `flag_incoherence_verticale`. Missing values are `null` |
| `payload_sha256` | 64 hex chars | SHA-256 of the canonical payload bytes |
| `sig` | 128 hex chars | Ed25519 signature over the canonical header bytes |

**Canonical bytes**, so every component produces exactly the same bytes for the same data:

- JSON with keys sorted, no whitespace (`separators=(",", ":")`), UTF-8, floats written exactly as stored, `NaN` → `null`.  
- Payload bytes \= canonical(`payload`).  
- Header bytes \= canonical of `{v, key_id, station, seq, ts, sent_at, nonce, payload_sha256}`, which excludes `sig` and `payload`.

Because the signature covers `payload_sha256`, it covers the payload too. Keeping the hash separate lets the gate report *which* part was altered. The reference implementation of `canonical()` is in `validate.py`; use it rather than writing your own.

### Gate checks and codes

The gate runs the checks in this order and stops at the first failure.

| Order | Code | Check | Meaning |
| :---- | :---- | :---- | :---- |
| 1 | `E_SCHEMA` | Packet structure, types, hard bounds (§7.2) | Malformed packet |
| 2 | `E_UNKNOWN_KEY` | `key_id` is in the registry and bound to `station` | Unknown or mismatched key |
| 3 | `E_PAYLOAD_HASH` | `sha256(canonical(payload)) == payload_sha256` | Payload altered after signing |
| 4 | `E_BAD_SIG` | Ed25519 verification over the header bytes | Forged or altered header |
| 5 | `E_REPLAY_SEQ` | `seq` \= last accepted `seq` \+ 1 for this station | Replayed, duplicated or reordered |
| 6 | `E_REPLAY_NONCE` | `nonce` not seen before for this key | Replayed packet |
| 7 | `E_STALE` | `0 ≤ sent_at − ts ≤ 2 h` | Old data presented as fresh |
| — | `OK` | All checks passed | Forwarded to Stage 2 |

A sequence jump (`seq` skips ahead) is accepted, but the gate logs it as warning `W_SEQ_GAP`, which signals packet loss.

**Known limit (document it in the report):** a compromised node holds a valid key, so its false data passes every gate check. Catching it is Stage 2's job.

---

## 9\. Attacked datasets (attack-engine output)

### 9.1 Attacked observation file (`data/attacked/<run>.csv`)

Exactly the columns of §7, in the same order, plus three label columns:

| Column | Type | Rule |
| :---- | :---- | :---- |
| `is_attacked` | boolean | `true` on every row whose values were altered |
| `attack_type` | string | An attack code from §5, or empty when `is_attacked = false` |
| `attack_run_id` | string | Links the row to its event in the events file, or empty |

Attack codes (v1): `replay`, `tamper`, `bias`, `drift`, `mimicry`, `heldout`. `heldout` data is never shared outside its owner before final evaluation.

Rules:

- Rows not under attack keep their original values exactly, bit for bit.  
- Injected values respect the hard bounds and resolution of §7.2 and avoid the gaps of §7.4.  
- **Label columns never enter the detector.** The pipeline strips them before signing; only the evaluation harness reads them.

### 9.2 Events file (`data/attacked/attack_events.csv`)

One row per attack event, enough to regenerate it exactly. An example is in §4, Step 3\.

| Column | Type | Rule |
| :---- | :---- | :---- |
| `attack_run_id` | string | Unique |
| `station` | string | Registry station |
| `attack_type` | string | Attack code |
| `target_columns` | string | Altered columns, separated by `;` (e.g. `SOIL_MOISTURE_5`) |
| `start` | timestamp UTC | First attacked hour (inclusive) |
| `end` | timestamp UTC | Last attacked hour (inclusive) |
| `params_json` | JSON string | Attack parameters (magnitude, slope, shape…) |
| `seed` | integer | Random seed used |
| `engine_version` | string | Attack-engine version or commit hash |

---

## 10\. Detector output (`outputs/detector_output.csv`)

One row per packet that reaches the pipeline. The evaluation harness computes every metric from this file plus the labels. An example is in §4, Step 4\.

| Column | Type | Rule |
| :---- | :---- | :---- |
| `station`, `time` | as §7.1 | Key of the evaluated record |
| `gate_status` | string | A code from §8 |
| `trust_score` | float 0–1 | Stage 2 score (1 \= fully trusted, lower \= less trusted). Empty when the gate rejected the packet. How each model's anomaly score is converted to this range is a detector design choice, documented with the detector; it does not change this format |
| `decision` | string | `accept`, `flag` or `reject` |
| `latency_ms` | float ≥ 0 | Processing time for this record |
| `detector_version` | string | Model version or commit hash |

---

## 11\. Planned additions (v1.1)

The cleaning report lists two columns the AI lead plans to add. Each one is a **minor** version change (1.1.0), and no existing column changes:

- `flag_sol_gele`: `true` when 5 cm moisture is missing and soil temperature is below 1 °C (frozen soil).  
- An offset-corrected 5 cm moisture column for OK\_Goodwell\_2\_E. The AI lead sets the name when it is added.

Until then, compute both on the fly from the rules above.

## 11b. External context sources (reserved)

External context (ERA5, SMAP or another source) is not part of v1.0.0 and never blocks the simulation. When a source is added:

- Its columns use the prefix `CTX_` plus the source name (for example `CTX_ERA5_SWVL1`, `CTX_SMAP_SM`) and join on `(station, time)`.  
- Values are **not interpolated**, since the organizers do not want generated data. Each hour takes the latest available value of the source, and a companion column `CTX_<SOURCE>_AGE_H` gives its age in hours. This matters for SMAP, which passes over a site only every few days.  
- `NaN` is allowed wherever the source has no value.  
- Adding `CTX_` columns is a **minor** version change (1.1.0, 1.2.0…). No existing column changes.

Until then, context comes from the station itself (precipitation, soil temperature, deeper moisture) and from the paired Goodwell station.

---

## 12\. Evaluation split (confirmed with the AI lead)

Split by time, never row by row. A random row split leaks neighbouring hours between train and test, which inflates the scores.

The detectors are **one-class models** (Isolation Forest, One-Class SVM, autoencoder…). They learn what normal data looks like and are trained on **clean data only**.

| Split | Period | Data | Use |
| :---- | :---- | :---- | :---- |
| Train | 2022-01-01 → 2023-12-31 | Clean only, no attacks | Fit the one-class models |
| Validation | 2024-01-01 → 2024-12-31 | Clean \+ the 4 standard attacks | Calibrate the trust score, choose the model, set thresholds |
| Test | 2025-01-01 → 2026-01-01 | Clean \+ standard attacks \+ held-out attacks | Final metrics, reported once |

Consequences:

- **Attacks are injected only into 2024 and 2025\.** No attacked file covers 2022–2023.  
- **Held-out attacks appear only in 2025\.** They are never used for calibration or model choice.  
- The §4 example falls in the test year, so it is the kind of record the final metrics are computed on.

---

## 13\. Glossary

| Term | Meaning |
| :---- | :---- |
| **Stage 1** | The crypto gate. Checks that a packet is well-formed, signed by the right key, unaltered and not replayed. Cannot judge whether the values are true |
| **Stage 2** | The AI detector. Scores whether the values of a packet that passed Stage 1 are physically plausible |
| **gate** | Short for the Stage 1 crypto gate |
| **gate\_status** | The gate's verdict for a packet: `OK` or one of the `E_*` codes (§8) |
| **trust\_score** | Stage 2's confidence that a record is genuine, from 0 (certainly false) to 1 (fully trusted) |
| **decision** | Final action for a record: `accept` (use it), `flag` (use with a warning, alert the analyst) or `reject` (discard) |
| **payload** | The measurement values inside a packet (§8): what the sensor reports |
| **payload\_sha256** | A SHA-256 fingerprint of the payload. Any change to any value changes it |
| **key\_id** | Identifier of the signing key a packet claims to use. Each station has exactly one (§7.3) |
| **seq** | Per-station packet counter that increases by 1 each hour. A repeated or backwards `seq` means replay |
| **nonce** | 16 random bytes, unique per packet. A repeated nonce means the packet was seen before |
| **ts** | When the measurement was taken (end of the hour, UTC) |
| **sent\_at** | When the packet was emitted, on the replay clock. If it is far after `ts`, old data is being passed off as new |
| **replay** | Resending a genuine old packet so stale data looks current |
| **tamper** | Changing a packet after it was signed, without the key |
| **bias** | A compromised sensor adding a constant offset to its readings |
| **drift** | A compromised sensor adding a slowly growing error |
| **mimicry** | A compromised sensor faking a natural-looking event, using real context to avoid detection |
| **held-out** | Attack variants kept secret from the detector's training, used only for final testing. They prove the detector generalizes rather than memorizes |
| **pre-sign / post-sign** | Whether an attack alters data before the sensor signs it (only Stage 2 can catch it) or after (Stage 1 catches it) |
| **hard bounds** | Physical limits outside which a value is impossible (§7.2) |
| **canonical bytes** | The single agreed way to turn a JSON object into bytes before hashing or signing (§8) |

---

## Appendix A — Versioning

- Semantic versioning: **major** \= a column renamed or removed, or a unit or meaning changed; **minor** \= a column or attack code added; **patch** \= a wording fix.  
- Every change goes through the team lead and gets a changelog line.  
- Every packet and file carries the version it follows (`v` in packets, `engine_version` and `detector_version` elsewhere).

### Changelog

| Version | Date | Change |
| :---- | :---- | :---- |
| 1.0.0-draft | 2026-10-13 | First draft, profiled from `uscrn_clean.csv` |
| 1.0.0-draft | 2026-10-13 | Restructured for readability: read-first section, data flow, end-to-end example, attack table, roles, glossary. No rule changed |
| 1.0.0-draft | 2026-10-14 | Aligned with the AI lead's cleaning report: hard bounds now equal the cleaning bounds, Parquet as primary format, exact vertical-check rule, Goodwell pair figures, frozen-soil blind spot, climates in the registry |
| 1.0.0-draft | 2026-10-14 | Q1–Q4 answered by the AI lead. Split confirmed, with one-class training on clean data only and attacks in 2024–2025 only. External context: no interpolation, latest value \+ age column |

