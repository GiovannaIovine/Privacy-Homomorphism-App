from flask import Flask, render_template, request
import pandas as pd
import secrets

from crypto.homomorphic import (
    keygen,
    digits_base_b,
    homo_add,
    noise_add,
    decrypt,
)

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():

    # =====================================================
    # Setup
    # =====================================================

    DIGITS = 200
    BASE = 10
    N = 6

    params, sk = keygen(
        num_decimal_digits=DIGITS,
        b=BASE,
        n=N
    )

    p = params.p

    # =====================================================
    # Read CSV
    # =====================================================

    file = request.files["file"]

    df = pd.read_csv(file)

    glucose_values = (
        df["Glucose"]
        .dropna()
        .astype(int)
        .tolist()
    )

    # =====================================================
    # Encrypt all glucose values
    # =====================================================

    encrypted_values = []
    noise_values = []

    for value in glucose_values:

        # Convert to base-b digits
        digits = digits_base_b(value, BASE, N)

        # Random noise vector
        r = [
            secrets.randbelow(p)
            for _ in range(N)
        ]

        # Encrypt
        ciphertext = [
            (sk.a[i] * digits[i] + r[i]) % p
            for i in range(N)
        ]

        encrypted_values.append(ciphertext)
        noise_values.append(r)

    # =====================================================
    # Homomorphic Sum
    # =====================================================

    encrypted_sum = encrypted_values[0]
    noise_sum = noise_values[0]

    for i in range(1, len(encrypted_values)):

        encrypted_sum = homo_add(
            encrypted_sum,
            encrypted_values[i],
            p
        )

        noise_sum = noise_add(
            noise_sum,
            noise_values[i],
            p
        )

    # =====================================================
    # Decrypt
    # =====================================================

    decrypted_sum = decrypt(
        encrypted_sum,
        params,
        sk,
        noise_sum
    )

    # =====================================================
    # Compute average
    # =====================================================

    average = decrypted_sum / len(glucose_values)

    return render_template(
        "results.html",
        average=average,
        total_patients=len(glucose_values),
        encrypted_sum=encrypted_sum
    )


if __name__ == "__main__":
    app.run(debug=True)