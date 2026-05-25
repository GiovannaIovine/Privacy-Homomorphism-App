import json
import os
import secrets
import math

# ═══════════════════════════════════════════════════════════════════════════════
# Internal arithmetic utilities
# ═══════════════════════════════════════════════════════════════════════════════

def _ext_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm.  Returns (gcd, x, y) with a·x + b·y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _ext_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inv(a: int, m: int) -> int:
    """Return a⁻¹ mod m.  Raises ValueError if gcd(a, m) ≠ 1."""
    g, x, _ = _ext_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"mod_inv: gcd({a}, {m}) = {g} ≠ 1 — no inverse exists")
    return x % m


def miller_rabin(n: int, rounds: int = 40) -> bool:
    """
    Probabilistic primality test (Miller-Rabin, 40 rounds).
    Error probability ≤ 4^{-40} ≈ 10^{-24}.
    """
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small:
        return True
    if any(n % p == 0 for p in small):
        return False
    # write n-1 = 2^r · d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(num_decimal_digits: int = 200) -> int:
    """
    Generate a random prime with exactly `num_decimal_digits` decimal digits.
    Uses cryptographically secure randomness (secrets module).
    """
    lo = 10 ** (num_decimal_digits - 1)
    hi = 10 **  num_decimal_digits - 1
    while True:
        c = (secrets.randbelow(hi - lo) + lo) | 1   # force odd
        if miller_rabin(c):
            return c


# ═══════════════════════════════════════════════════════════════════════════════
# Key generation
# ═══════════════════════════════════════════════════════════════════════════════

def keygen(
    num_decimal_digits: int = 200,
    d: int = 3,
    verbose: bool = True,
) -> dict:
    """
    Generate system parameters and secret key.

    Parameters
    ----------
    num_decimal_digits : int
        Desired number of decimal digits for the public modulus m (≥ 200 per paper).
    d : int
        Splitting factor.  d > 2 recommended; d = 2 used only in the paper's example.
    verbose : bool
        Print progress messages.

    Returns
    -------
    dict with keys:
        m        — public modulus (large integer, ~10^{num_decimal_digits})
        d        — splitting factor (public)
        r        — secret multiplier (r^{-1} mod m must exist)
        m_prime  — secret cleartext modulus (divisor of m); cleartext space = Z_{m'}
        s        — security parameter  s = log_{m'}(m)  (informational)
        r_inv    — precomputed r^{-1} mod m (used in decryption)
        r_pows   — precomputed (r^1, r^2, …, r^d) mod m (used in encryption)
        r_inv_pows — precomputed (r^{-1}, r^{-2}, …, r^{-max_degree}) mod m
    """
    if verbose:
        print(f"[keygen] Generating {num_decimal_digits}-digit prime modulus m …")

    # ── m: large prime (simplest compliant choice; composite also valid) ──────
    m = generate_large_prime(num_decimal_digits)

    if verbose:
        print(f"[keygen] m = {str(m)[:48]}… ({m.bit_length()} bits, "
              f"{len(str(m))} decimal digits)")

    # ── r: random invertible element of Z_m ──────────────────────────────────
    # Since m is prime every nonzero element is invertible.
    r = secrets.randbelow(m - 2) + 2
    while math.gcd(r, m) != 1:
        r = secrets.randbelow(m - 2) + 2

    # ── m': secret cleartext modulus, a divisor of m ─────────────────────────
    # When m is prime the only proper divisors are 1 and m itself.
    # We use m' = m so the cleartext space is Z_m  (full residue class ring).
    # In a composite-m deployment one would choose m' as a small secret factor.
    m_prime = m

    # ── precompute powers for efficiency ─────────────────────────────────────
    r_inv = mod_inv(r, m)
    r_pows     = [pow(r,     j, m) for j in range(1, d + 1)]      # r^1 … r^d
    # For decryption after multiplication the r-degree can reach 2d (or more
    # with repeated multiplications).  We precompute up to 4d to be safe.
    max_deg = 4 * d
    r_inv_pows = [pow(r_inv, j, m) for j in range(1, max_deg + 1)]  # r^{-1} … r^{-4d}

    # ── security parameter s = log_{m'}(m) ───────────────────────────────────
    # Since m' = m here, s = 1. In a composite deployment with m' ≪ m, s ≫ 1.
    s = math.log(m) / math.log(m_prime) if m_prime > 1 else float('inf')

    if verbose:
        print(f"[keygen] d = {d},  security parameter s = log_{{m'}}(m) = {s:.4f}")

    return {
        "m":          m,
        "d":          d,
        "r":          r,
        "m_prime":    m_prime,
        "s":          s,
        "r_inv":      r_inv,
        "r_pows":     r_pows,
        "r_inv_pows": r_inv_pows,
    }

if __name__ == "__main__":
    keys_db = "keys.json"
    file_name = r"C:\Users\riovi\Privacy-Homomorphism-App\diabetes.csv"

    if os.path.exists(keys_db):
        with open(keys_db, "r") as f:
            data = json.load(f)
    else:
        data = {}

    if file_name not in data:
        key = str(keygen(200, 3, True))

    with open(keys_db, "w") as f:
        json.dump({file_name: key}, f, indent=4)
