import os
import ast
import secrets
import json
import pandas as pd

def decrypt(ciphertext: dict[int, int], key: dict) -> int:
    """
    Decrypt a ciphertext vector back to Z_{m'}.

    Algorithm (Section 2 of the paper)
    ------------------------------------
    For each r-degree j present in the ciphertext:
        a_j = c_j · r^{-j}  (mod m)
    Return  (Σ a_j)  mod m'.

    This works for any ciphertext produced by a sequence of homomorphic
    operations, as long as all r-degrees are within the precomputed range
    (up to 4d by default; extend key["r_inv_pows"] if needed).

    Parameters
    ----------
    ciphertext : dict { r_degree: component } — output of encrypt() or any
                 homomorphic operation.
    key        : dict returned by keygen().

    Returns
    -------
    Plaintext integer in [0, m').
    """
    m          = key["m"]
    m_prime    = key["m_prime"]
    r_inv_pows = key["r_inv_pows"]   # index j-1 gives r^{-j}

    # Extend precomputed powers on-the-fly if a very deep multiplication tree
    # has produced a degree higher than 4d.
    r_inv = key["r_inv"]
    max_precomputed = len(r_inv_pows)

    total = 0
    for j, cj in ciphertext.items():
        # Retrieve or compute r^{-j}
        if j <= max_precomputed:
            r_inv_j = r_inv_pows[j - 1]
        else:
            r_inv_j = pow(r_inv, j, m)          # fallback: compute on-the-fly
        aj    = (cj * r_inv_j) % m
        total = (total + aj) % m

    return total % m_prime


def decrypt_csv_columnwise(file_name: str, key: dict, out_file: str):
    """
    Decrypt a CSV where each cell is a JSON-encoded ciphertext dict.
    """

    df = pd.read_csv(file_name, dtype=str)  # 🔥 important: evita conversioni automatiche

    decrypted_df = pd.DataFrame()

    for col in df.columns:

        def decrypt_cell(cell):

            # 🔥 gestisce null/empty in modo robusto
            if cell is None or cell == "" or pd.isna(cell):
                return None

            try:
                ciphertext = json.loads(cell)

                # 🔥 sicurezza: chiavi string → int
                ciphertext = {int(k): v for k, v in ciphertext.items()}

                return decrypt(ciphertext, key)

            except Exception:
                # se qualcosa è corrotto
                return None

        decrypted_df[col] = df[col].apply(decrypt_cell)

    decrypted_df.to_csv(out_file, index=False)

    return out_file

if __name__ == "__main__":
    keys_db = "keys.json"
    file_name = r"Privacy-Homomorphism-App\diabetes_enc.csv"

    if os.path.exists(keys_db):
        with open(keys_db, "r") as f:
            data = json.load(f)
    else:
        data = {}

    if file_name not in data:
        print("Key not found")
    else:
        key=data[file_name]
        with open(file_name, "r", encoding="utf-8") as f:
            content = f.read()
        
        base, ext = os.path.splitext(file_name)
        out_file = base + "_dec" + ext

        decrypt_csv_columnwise(file_name, key, out_file)