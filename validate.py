#!/usr/bin/env python3
"""Check a file against the data contract (data_contract.schema.json).

Usage:
    python validate.py observations uscrn_clean.parquet   (or .csv)
    python validate.py attacked     attacked_bias.csv
    python validate.py events       attack_events.csv
    python validate.py packets      packets.jsonl [--pubkeys pubkeys.json]

Exit code 0 = valid, 1 = contract violations found, 2 = usage error.
`--pubkeys` maps key_id -> Ed25519 public key (hex); signatures are then
verified too (needs the `cryptography` package).
"""
import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path

import pandas as pd

SCHEMA = json.loads((Path(__file__).parent / "data_contract.schema.json").read_text())
OBS = SCHEMA["observation"]
REGISTRY = {s["station"]: s for s in SCHEMA["station_registry"]}
HEX = lambda n: re.compile(rf"^[0-9a-f]{{{n}}}$")
ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class Report:
    def __init__(self):
        self.errors, self.warnings = [], []

    def err(self, msg, n=None):
        self.errors.append(f"{msg}" + (f" ({n} rows)" if n else ""))

    def warn(self, msg):
        self.warnings.append(msg)

    def done(self, what):
        for w in self.warnings:
            print(f"  WARN  {w}")
        for e in self.errors:
            print(f"  FAIL  {e}")
        status = "VALID" if not self.errors else f"INVALID ({len(self.errors)} problems)"
        print(f"{what}: {status} against contract v{SCHEMA['version']}")
        return 0 if not self.errors else 1


def read_table(path):
    """Read the observation table from CSV or Parquet (the cleaning step outputs Parquet)."""
    if str(path).endswith(".parquet"):
        df = pd.read_parquet(path)
        if pd.api.types.is_datetime64_any_dtype(df["time"]):
            df["time"] = df["time"].dt.strftime("%Y-%m-%d %H:%M:%S")
        return df
    return pd.read_csv(path, dtype={"station": str})


def canonical(obj) -> bytes:
    def clean(v):
        if isinstance(v, float) and math.isnan(v):
            return None
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items()}
        return v
    return json.dumps(clean(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------- observations / attacked ----------

def check_observations(path, attacked=False):
    r = Report()
    df = read_table(path)
    expected = list(OBS["column_order"])
    labels = list(SCHEMA["attacked"]["label_columns"]) if attacked else []
    if list(df.columns) != expected + labels:
        missing = [c for c in expected + labels if c not in df.columns]
        extra = [c for c in df.columns if c not in expected + labels]
        r.err(f"column set/order mismatch; missing={missing} extra={extra}")
        if missing:
            return r.done(path)

    # time + key
    t = pd.to_datetime(df["time"], format=OBS["columns"]["time"]["format"], errors="coerce")
    if t.isna().any():
        r.err("unparseable or wrongly formatted `time`", int(t.isna().sum()))
    if ((t.dt.minute != 0) | (t.dt.second != 0)).any():
        r.err("`time` not on the hour", int(((t.dt.minute != 0) | (t.dt.second != 0)).sum()))
    dup = df.duplicated(["station", "time"]).sum()
    if dup:
        r.err("duplicate (station, time)", int(dup))
    bad_station = ~df["station"].isin(REGISTRY)
    if bad_station.any():
        r.err(f"unknown stations {sorted(df.loc[bad_station, 'station'].unique())}", int(bad_station.sum()))
    exp_year = (t - pd.Timedelta(hours=1)).dt.year
    if (df["annee"] != exp_year).any():
        r.err("`annee` is not the year of the interval start", int((df["annee"] != exp_year).sum()))

    # registry-bound columns
    for col, key in (("LATITUDE", "latitude"), ("LONGITUDE", "longitude")):
        ref = df["station"].map(lambda s: REGISTRY.get(s, {}).get(key))
        bad = (df[col] - ref).abs() > 1e-6
        if bad.any():
            r.err(f"`{col}` differs from registry", int(bad.sum()))

    # numeric bounds, sentinel, resolution
    for col, spec in OBS["columns"].items():
        if spec["type"] != "float" or "min" not in spec:
            continue
        v = df[col]
        if (v <= -9990).any():
            r.err(f"`{col}` contains the -9999 sentinel", int((v <= -9990).sum()))
        out = v.notna() & ((v < spec["min"]) | (v > spec["max"]))
        if out.any():
            r.err(f"`{col}` outside hard bounds [{spec['min']}, {spec['max']}]", int(out.sum()))
        res = spec.get("resolution")
        if res:
            off = v.notna() & ((v / res).round() * res - v).abs().gt(res * 1e-3)
            if off.any():
                r.err(f"`{col}` finer than resolution {res} (injected values must be rounded)", int(off.sum()))

    # absent depths must be null
    for st, info in REGISTRY.items():
        rows = df["station"] == st
        for d in (5, 10, 20, 50, 100):
            if d in info["soil_depths_cm"]:
                continue
            for c in (f"SOIL_MOISTURE_{d}", f"SOIL_TEMP_{d}"):
                n = df.loc[rows, c].notna().sum()
                if n:
                    r.err(f"`{c}` has values at {st}, which has no {d} cm sensor", int(n))

    # temperature order
    tr = OBS["rules"]["temperature_order"]
    tol = tr["tolerance"]
    have = df[[tr["min"], tr["avg"], tr["max"]]].notna().all(axis=1)
    bad = have & ((df[tr["min"]] > df[tr["avg"]] + tol) | (df[tr["avg"]] > df[tr["max"]] + tol))
    if bad.any():
        r.err("T_MIN <= T_HR_AVG <= T_MAX violated", int(bad.sum()))

    # boolean flag
    if not df["flag_incoherence_verticale"].astype(str).str.lower().isin(["true", "false"]).all():
        r.err("`flag_incoherence_verticale` must be true/false")

    # grid completeness (warning: real outages are allowed as NaN rows, not missing rows)
    for st, g in df.assign(_t=t).groupby("station"):
        steps = g["_t"].sort_values().diff().dropna()
        if (steps != pd.Timedelta(hours=1)).any():
            r.warn(f"{st}: hourly grid has holes or irregular steps ({int((steps != pd.Timedelta(hours=1)).sum())})")

    if attacked:
        codes = set(SCHEMA["attacked"]["attack_codes"])
        att = df["is_attacked"].astype(str).str.lower()
        if not att.isin(["true", "false"]).all():
            r.err("`is_attacked` must be true/false")
        is_att = att == "true"
        typ = df["attack_type"].fillna("")
        rid = df["attack_run_id"].fillna("")
        if (is_att & ~typ.isin(codes)).any():
            r.err("attacked rows with missing/unknown `attack_type`", int((is_att & ~typ.isin(codes)).sum()))
        if (is_att & (rid == "")).any():
            r.err("attacked rows without `attack_run_id`", int((is_att & (rid == "")).sum()))
        if (~is_att & ((typ != "") | (rid != ""))).any():
            r.err("clean rows must have empty `attack_type` and `attack_run_id`")
        yrs = SCHEMA["split"]
        tt = pd.to_datetime(df["time"], errors="coerce")
        lo = pd.Timestamp(yrs["validation"][0])
        early = is_att & (tt < lo)
        if early.any():
            r.err("attacks inside the training period (one-class models train on clean data only)", int(early.sum()))
        test_lo = pd.Timestamp(yrs["test"][0])
        ho = is_att & (typ == "heldout") & (tt < test_lo)
        if ho.any():
            r.err("held-out attacks outside the test period", int(ho.sum()))
        if is_att.mean() > 0.5:
            r.warn(f"{is_att.mean():.0%} of rows are attacked; check the class balance")
    return r.done(path)


# ---------- events ----------

def check_events(path):
    r = Report()
    df = pd.read_csv(path, dtype=str)
    cols = SCHEMA["attacked"]["events_columns"]
    if list(df.columns) != cols:
        r.err(f"columns must be exactly {cols}")
        return r.done(path)
    if df["attack_run_id"].duplicated().any():
        r.err("duplicate attack_run_id", int(df["attack_run_id"].duplicated().sum()))
    if (~df["station"].isin(REGISTRY)).any():
        r.err("unknown station")
    if (~df["attack_type"].isin(SCHEMA["attacked"]["attack_codes"])).any():
        r.err("unknown attack_type")
    s, e = pd.to_datetime(df["start"], errors="coerce"), pd.to_datetime(df["end"], errors="coerce")
    if s.isna().any() or e.isna().any() or (e < s).any():
        r.err("bad start/end (unparseable or end < start)")
    for i, p in df["params_json"].items():
        try:
            json.loads(p)
        except Exception:
            r.err(f"row {i}: params_json is not valid JSON")
    if pd.to_numeric(df["seed"], errors="coerce").isna().any():
        r.err("seed must be an integer")
    allowed = set(OBS["column_order"])
    for i, tc in df["target_columns"].items():
        bad = [c for c in str(tc).split(";") if c not in allowed]
        if bad:
            r.err(f"row {i}: unknown target columns {bad}")
    return r.done(path)


# ---------- packets ----------

def check_packets(path, pubkeys_path=None):
    r = Report()
    spec = SCHEMA["packet"]
    payload_cols = [c for c in OBS["column_order"] if c not in spec["payload_excludes"]]
    verify = None
    if pubkeys_path:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        keys = {k: Ed25519PublicKey.from_public_bytes(bytes.fromhex(v))
                for k, v in json.loads(Path(pubkeys_path).read_text()).items()}

        def verify(p):
            hdr = {f: p[f] for f in spec["signed_header_fields"]}
            try:
                keys[p["key_id"]].verify(bytes.fromhex(p["sig"]), canonical(hdr))
                return True
            except Exception:
                return False

    last_seq, nonces = {}, set()
    with open(path) as fh:
        for ln, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                p = json.loads(line)
            except json.JSONDecodeError:
                r.err(f"line {ln}: not JSON")
                continue
            if set(p) != set(spec["fields"]):
                r.err(f"line {ln}: fields must be exactly {sorted(spec['fields'])}")
                continue
            st = REGISTRY.get(p["station"])
            if not st:
                r.err(f"line {ln}: unknown station")
                continue
            if p["key_id"] != st["key_id"]:
                r.err(f"line {ln}: key_id not bound to station")
            if not (isinstance(p["seq"], int) and p["seq"] >= 0):
                r.err(f"line {ln}: seq must be a non-negative integer")
            if not (ISO_Z.match(str(p["ts"])) and ISO_Z.match(str(p["sent_at"]))):
                r.err(f"line {ln}: ts/sent_at must be ISO 8601 UTC with Z")
            if not HEX(32).match(str(p["nonce"])):
                r.err(f"line {ln}: nonce must be 32 lowercase hex chars")
            if not HEX(64).match(str(p["payload_sha256"])):
                r.err(f"line {ln}: payload_sha256 must be 64 hex chars")
            if not HEX(128).match(str(p["sig"])):
                r.err(f"line {ln}: sig must be 128 hex chars")
            if sorted(p["payload"]) != sorted(payload_cols):
                r.err(f"line {ln}: payload keys must be exactly the contract measurement columns")
            elif hashlib.sha256(canonical(p["payload"])).hexdigest() != p["payload_sha256"]:
                r.err(f"line {ln}: payload_sha256 does not match payload")
            if verify and not verify(p):
                r.err(f"line {ln}: signature invalid")
            # stream properties of a clean file (an attacked stream is expected to break these)
            prev = last_seq.get(p["station"])
            if prev is not None and p["seq"] != prev + 1:
                r.warn(f"line {ln}: seq {p['seq']} after {prev} for {p['station']}")
            last_seq[p["station"]] = p["seq"]
            key = (p["key_id"], p["nonce"])
            if key in nonces:
                r.err(f"line {ln}: nonce reused for {p['key_id']}")
            nonces.add(key)
    return r.done(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind", choices=["observations", "attacked", "events", "packets"])
    ap.add_argument("path")
    ap.add_argument("--pubkeys")
    a = ap.parse_args()
    if a.kind == "observations":
        return check_observations(a.path)
    if a.kind == "attacked":
        return check_observations(a.path, attacked=True)
    if a.kind == "events":
        return check_events(a.path)
    return check_packets(a.path, a.pubkeys)


if __name__ == "__main__":
    sys.exit(main())
