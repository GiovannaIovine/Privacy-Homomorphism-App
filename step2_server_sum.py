"""
STEP 2 — Homomorphic sum on remote server
=====================================
Gets encrypted_data.csv e metadata.json as input.

On each column:
    C_sum[col] = C(x_1) ⊕ C(x_2) ⊕ … ⊕ C(x_n)

Output
------
encrypted_sums.csv   — A csv with only one row, each cell contains the computed sum

Run
--------
  python step2_server_sum.py
  python step2_server_sum.py --enc encrypted_data.csv --meta metadata.json
"""

import csv
import json
import argparse


# ── sserialize ──

def str_to_ct(s: str) -> dict:
    return {int(j): int(cj) for j, cj in json.loads(s)}

def ct_to_str(ct: dict) -> str:
    return json.dumps([[str(j), str(cj)] for j, cj in sorted(ct.items())],
                      separators=(',', ':'))


# ── SUM ───────────────────────────────

def homo_add(c1: dict, c2: dict, m: int) -> dict:
    degrees = set(c1) | set(c2)
    return {j: (c1.get(j, 0) + c2.get(j, 0)) % m for j in degrees}


# ── main ──────────────────────────────────────────────────────────────────────

def server_sum(
    enc_path:  str = "encrypted_data.csv",
    meta_path: str = "metadata.json",
    out_path:  str = "encrypted_sums.csv",
) -> None:

    # ── read metadata to get m──────
    with open(meta_path, encoding='utf-8') as f:
        meta = json.load(f)

    m       = int(meta["m"])
    columns = meta["columns"]
    n_rows  = meta["n_rows"]
    print(f"[step2] Params: n={n_rows} rows, {len(columns)} columns, "
          f"|m|={len(str(m))} digits")

    # ── Read encrypted csv ───────────────────────────────────────────────────
    with open(enc_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows   = list(reader)

    if len(rows) != n_rows:
        raise ValueError(f"Expected {n_rows} rows, found {len(rows)}")

    # ── columnwise sum ──────────────────────────────────────────
    print(f"[step2] computing sums …")
    sums = {}
    for col in columns:
        C_sum = str_to_ct(rows[0][col])
        for row in rows[1:]:
            C_next = str_to_ct(row[col])
            C_sum  = homo_add(C_sum, C_next, m)
        sums[col] = ct_to_str(C_sum)
        print(f"  {col}: result (max r-degree = "
              f"{max(int(j) for j,_ in json.loads(sums[col]))})")

    # ── save encrypted_sums.csv ────────────────────────────────────────
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerow(sums)           # una sola riga: i ciphertext delle somme
    print(f"[step2] Salvato: {out_path}")
    print(f"[step2] Invia {out_path} + metadata.json al possessore della chiave")