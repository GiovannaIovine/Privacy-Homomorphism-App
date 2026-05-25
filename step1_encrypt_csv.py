"""
STEP 1 — CSV Encryption
==========================
It reads a csv file and encrypt each cell with Privacy Homomorphism
di Domingo-Ferrer (2002).

Output
------
encrypted_data.csv   — a csv file where each cell contains the ciphertext json serialized.
key.json             — secret key (m, d, r, m_prime, r_inv, r_pows, r_inv_pows)
metadata.json        — public patrams (m, d) + decimal_places for each column.

Cell format in csv
-----------------------------------------
  [["1","<big_int_str>"],["2","<big_int_str>"],["3","<big_int_str>"]]
where each couple ["r", "value_mod_m"] is a component of the cipher vector.
Values are serialized as bug inter (~200 digits)

Run
--------
  python step1_encrypt_csv.py data.csv
  python step1_encrypt_csv.py data.csv --digits 200 --d 3
"""

import csv
import json
import sys
import argparse
from pathlib import Path
from domingo_ferrer_2002 import keygen, encrypt


# ── serialize / deserialize ciphertext ────────────────────────────

def ct_to_str(ct: dict) -> str:
    return json.dumps([[str(j), str(cj)] for j, cj in sorted(ct.items())],
                      separators=(',', ':'))


def str_to_ct(s: str) -> dict:
    return {int(j): int(cj) for j, cj in json.loads(s)}


# ── auto detect decimal places ───────────────────────────────

def detect_decimal_places(values: list[str]) -> int:
    max_dp = 0
    for v in values:
        v = v.strip()
        if '.' in v:
            decimal_part = v.split('.')[1].rstrip('0')
            max_dp = max(max_dp, len(decimal_part))
    return max_dp


# ── key serialization ─────────────────────────────────────────────────────────

def key_to_dict(key: dict) -> dict:
    return {
        "m":          str(key["m"]),
        "d":          key["d"],
        "r":          str(key["r"]),
        "m_prime":    str(key["m_prime"]),
        "r_inv":      str(key["r_inv"]),
        "r_pows":     [str(x) for x in key["r_pows"]],
        "r_inv_pows": [str(x) for x in key["r_inv_pows"]],
        "s":          key["s"],
    }


def dict_to_key(d: dict) -> dict:
    return {
        "m":          int(d["m"]),
        "d":          int(d["d"]),
        "r":          int(d["r"]),
        "m_prime":    int(d["m_prime"]),
        "r_inv":      int(d["r_inv"]),
        "r_pows":     [int(x) for x in d["r_pows"]],
        "r_inv_pows": [int(x) for x in d["r_inv_pows"]],
        "s":          float(d["s"]),
    }


# ── main ──────────────────────────────────────────────────────────────────────

def encrypt_csv(
    input_path: str,
    digits: int = 200,
    d: int = 3,
    out_enc:  str = "encrypted_data.csv",
    out_key:  str = "key.json",
    out_meta: str = "metadata.json",
) -> None:

    # ── read CSV ───────────────────────────────────────────────────────────
    with open(input_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames
        rows    = list(reader)

    if not columns:
        raise ValueError("CSV privo di intestazioni.")
    n_rows = len(rows)
    print(f"[step1] CSV: {n_rows} righe × {len(columns)} colonne")

    # ── key generation ────────────────────────────────────────────────────
    key = keygen(num_decimal_digits=digits, d=d, verbose=True)
    m   = key["m"]

    # ── detect decimal places in each column ────────────────────────────────
    decimal_places = {}
    for col in columns:
        col_values = [row[col] for row in rows]
        decimal_places[col] = detect_decimal_places(col_values)

    print(f"[step1] n of decimal places detected:")
    for col, dp in decimal_places.items():
        print(f"         {col}: {dp}")

    # ── ENCRYPTION ─────────────────────────────────────────────────────────────
    print(f"[step1] Encryption of {n_rows * len(columns)} values …")

    enc_rows = []
    for i, row in enumerate(rows):
        enc_row = {}
        for col in columns:
            dp      = decimal_places[col]
            scale   = 10 ** dp
            int_val = round(float(row[col]) * scale)
            ct      = encrypt(int_val, key)
            enc_row[col] = ct_to_str(ct)
        enc_rows.append(enc_row)
        if (i + 1) % 50 == 0:
            print(f"  … {i+1}/{n_rows} encrypted rows")

    # ── save encrypted_data.csv ───────────────────────────────────────
    with open(out_enc, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(enc_rows)
    print(f"[step1] Saved: {out_enc}")

    # ── save key.json ──────────────────────────────────────────────────
    with open(out_key, 'w', encoding='utf-8') as f:
        json.dump(key_to_dict(key), f, indent=2)
    print(f"[step1] Saved: {out_key}  ← KEEP SECRET")

    # ── save metadata.json ─────────────────────────────────────────────
    metadata = {
        "m":             str(m),          
        "d":             d,
        "n_rows":        n_rows,
        "columns":       columns,
        "decimal_places": decimal_places, 
    }
    with open(out_meta, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    print(f"[step1] Saved: {out_meta}")


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":

    encrypt_csv(
        input_path=r"C:\Users\riovi\Privacy-Homomorphism-App\diabetes.csv",
        digits=200,
        d=3,
        out_enc="diabetes_encrypted.csv",
        out_key="diabetes_key.json",
        out_meta="metadata.json",
    )
