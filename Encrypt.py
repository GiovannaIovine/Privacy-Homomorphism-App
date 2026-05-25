import os
import ast
import secrets
import json
import pandas as pd

def encrypt(a: int, key: dict) -> dict[int, int]:
    """
    Encrypt plaintext a ∈ Z_{m'}.

    Algorithm (Section 2 of the paper)
    ------------------------------------
    1. Randomly split a into d parts a_1, …, a_d in Z_m such that
       a_1 + … + a_d ≡ a  (mod m').
       Parts a_1, …, a_{d-1} are chosen uniformly at random; a_d is set to
       satisfy the congruence.
    2. For j = 1, …, d compute  c_j = a_j · r^j  (mod m).
    3. Return  { j: c_j }  — a dict mapping r-degree to ciphertext component.

    The fresh randomness in the split makes encryption *probabilistic*:
    the same plaintext produces a different ciphertext every call.

    Parameters
    ----------
    a   : plaintext integer in [0, m')
    key : dict returned by keygen()

    Returns
    -------
    dict  { r_degree (int) : ciphertext_component (int) }
    """
    m       = key["m"]
    d       = key["d"]
    m_prime = key["m_prime"]
    r_pows  = key["r_pows"]

    a = a % m_prime  # normalise into Z_{m'}

    # ── random split ─────────────────────────────────────────────────────────
    parts = [secrets.randbelow(m) for _ in range(d - 1)]
    last  = (a - sum(parts)) % m_prime          # ensures Σ parts ≡ a (mod m')
    parts.append(last)

    # ── multiply each part by the corresponding power of r ───────────────────
    ciphertext = {}
    for j, (aj, rj) in enumerate(zip(parts, r_pows), start=1):
        ciphertext[j] = (aj * rj) % m           # c_j = a_j · r^j mod m

    return ciphertext

def encrypt_csv_columnwise(file_name: str, key: dict, out_file: str):

    df = pd.read_csv(file_name)

    with open(out_file, "w") as f:

        # header
        f.write(",".join(df.columns) + "\n")

        for _, row in df.iterrows():

            encrypted_row = []

            for col in df.columns:

                x = row[col]

                if pd.isna(x):
                    encrypted_row.append("")
                else:
                    ct = encrypt(int(x), key)

                    encrypted_row.append(json.dumps(ct))

            f.write(",".join(encrypted_row) + "\n")

    return out_file

if __name__ == "__main__":
    keys_db = "keys.json"
    file_name = r"C:\Users\riovi\Privacy-Homomorphism-App\diabetes.csv"

    if os.path.exists(keys_db):
        with open(keys_db, "r") as f:
            data = json.load(f)
    else:
        data = {}

    if file_name not in data:
        print("Key not found")
    else:
        key = data[file_name]
        if isinstance(key, str):
            key = ast.literal_eval(key)

        base, ext = os.path.splitext(file_name)
        out_file = base + "_enc" + ext

        encrypt_csv_columnwise(file_name, key, out_file)
