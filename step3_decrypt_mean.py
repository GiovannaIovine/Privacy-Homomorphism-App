"""
STEP 3 — Decryption and mean calculus
==========================================
Read encrypted_sums.csv, key.json e metadata.json.

Output
------
means.csv   — CSV with cleartext means

Run
--------
  python step3_decrypt_mean.py
  python step3_decrypt_mean.py --sums encrypted_sums.csv --key key.json --meta metadata.json
"""

import csv
import json
import argparse


# ── Key ───────────────────────────────────────────────────
from domingo_ferrer_2002 import decrypt


# ── deserialize ─────────────────────────────────────────────────────────

def str_to_ct(s: str) -> dict:
    return {int(j): int(cj) for j, cj in json.loads(s)}

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

def decrypt_means(
    sums_path: str = "encrypted_sums.csv",
    key_path:  str = "key.json",
    meta_path: str = "metadata.json",
    out_path:  str = "means.csv",
) -> dict:


    # ── read key ────────────────────────────────────────────────────────
    with open(key_path, encoding='utf-8') as f:
        key = dict_to_key(json.load(f))

    # ── read metadata ──────────────────────────────────────────────────────
    with open(meta_path, encoding='utf-8') as f:
        meta = json.load(f)

    columns        = meta["columns"]
    n_rows         = meta["n_rows"]
    decimal_places = meta["decimal_places"]       # {col: int}

    print(f"[step3] n={n_rows} righe, {len(columns)} colonne")

    # ── read encrypted sums ─────────────────────────────────────────────────
    with open(sums_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        sum_rows = list(reader)

    if len(sum_rows) != 1:
        raise ValueError(
            f"{sums_path} only 1 row expected "
            f"found {len(sum_rows)}"
        )
    sum_row = sum_rows[0]

    # ── decryption + computing ───────────────────────────────────────────
    print(f"\n{'row':<18} {'decrypted sum':>25} {'n × scale':>12} {'mean':>14}")
    print("─" * 72)

    means = {}
    for col in columns:
        dp     = int(decimal_places[col])
        scale  = 10 ** dp

        C_sum    = str_to_ct(sum_row[col])
        dec_sum  = decrypt(C_sum, key)          # integer in Z_m

        mean_val = dec_sum / (n_rows * scale)
        means[col] = mean_val

        print(f"{col:<18} {str(dec_sum):>25} {n_rows * scale:>12} {mean_val:>14.4f}")

    print()

    # ── save means.csv ─────────────────────────────────────────────────
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        # Scrivi i valori float con precisione sufficiente
        writer.writerow({col: f"{v:.10g}" for col, v in means.items()})
    print(f"[step3] Salvato: {out_path}")

    return means


if __name__ == "__main__":

    decrypt_means(
        sums_path=r"C:\Users\riovi\Privacy-Homomorphism-App\outputs\encrypted_sums.csv",
        key_path=r"C:\Users\riovi\Privacy-Homomorphism-App\diabetes_key.json",
        meta_path=r"C:\Users\riovi\Privacy-Homomorphism-App\metadata.json",
        out_path="means.csv",
    )
