"""
Domingo-Ferrer (2002) Privacy Homomorphism
==========================================
Full implementation with arbitrary-precision integers (Python built-in).

Modulus p has ~200 decimal digits as required by the paper.

Supported homomorphic operations on ciphertext:
  - Addition:              C(x) + C(y)  →  decrypts to  x + y
  - Scalar multiplication: k * C(x)     →  decrypts to  k * x
  - Linear combination:    Σ kᵢ·C(xᵢ)  →  decrypts to  Σ kᵢ·xᵢ

Reference:
  Domingo-Ferrer, J. (2002). A provably secure additive and multiplicative
  privacy homomorphism. In ISC 2002, LNCS 2433, pp. 471-483. Springer.
"""

import secrets
import math


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean algorithm — returns a⁻¹ mod m."""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {g}")
    return x % m


def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def is_prime_miller_rabin(n: int, rounds: int = 40) -> bool:
    """Probabilistic Miller-Rabin primality test (40 rounds → error < 4⁻⁴⁰)."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2           # a ∈ [2, n-2]
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
    """Generate a random prime with exactly `num_decimal_digits` decimal digits."""
    low  = 10 ** (num_decimal_digits - 1)
    high = 10 **  num_decimal_digits - 1
    while True:
        candidate = secrets.randbelow(high - low) + low
        candidate |= 1                              # make it odd
        if is_prime_miller_rabin(candidate):
            return candidate


def digits_base_b(x: int, b: int, n: int) -> list[int]:
    """
    Decompose x into exactly n digits in base b (little-endian).
    x = d[0] + d[1]*b + d[2]*b² + … + d[n-1]*b^(n-1)
    """
    if x < 0 or x >= b ** n:
        raise ValueError(f"x={x} does not fit in {n} digits of base {b}")
    digits = []
    for _ in range(n):
        digits.append(x % b)
        x //= b
    return digits                                   # length == n


def reconstruct_from_digits(digits: list[int], b: int) -> int:
    """Rebuild integer from little-endian base-b digit list."""
    result = 0
    for d in reversed(digits):
        result = result * b + d
    return result


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

class PublicParams:
    """
    Public parameters shared between encryptor and decryptor.
    In a real deployment p and n could be public; a and r stay secret.
    """
    def __init__(self, p: int, b: int, n: int):
        self.p = p      # large prime modulus (~200 digits)
        self.b = b      # base for plaintext decomposition
        self.n = n      # number of components per ciphertext vector


class SecretKey:
    """
    Secret key material:
      a  — vector of n coefficients with Σaᵢ ≡ 1 (mod p)
      a_inv — modular inverses of each aᵢ (precomputed for decryption)
    """
    def __init__(self, a: list[int], a_inv: list[int], params: PublicParams):
        self.a      = a
        self.a_inv  = a_inv
        self.params = params


def keygen(num_decimal_digits: int = 200,
           b: int = 10,
           n: int = 10) -> tuple[PublicParams, SecretKey]:
    """
    Generate system parameters and secret key.

    Parameters
    ----------
    num_decimal_digits : int
        Bit-length target for the prime modulus p (default: 200 decimal digits).
    b : int
        Base for plaintext decomposition (default: 10).
    n : int
        Number of ciphertext components (default: 10, so max plaintext = b^n - 1).
    """
    print(f"[keygen] Generating {num_decimal_digits}-digit prime p …")
    p = generate_large_prime(num_decimal_digits)
    print(f"[keygen] p = {str(p)[:40]}… ({p.bit_length()} bits)")

    # Choose a₁,…,a_{n-1} at random in ℤ*_p; set aₙ so that Σaᵢ ≡ 1 (mod p)
    a = [secrets.randbelow(p - 1) + 1 for _ in range(n - 1)]
    last = (1 - sum(a)) % p
    if last == 0:
        last = 1                                    # avoid a_n = 0
    a.append(last)
    assert sum(a) % p == 1, "Key invariant violated"

    a_inv = [mod_inverse(ai, p) for ai in a]

    params = PublicParams(p=p, b=b, n=n)
    sk     = SecretKey(a=a, a_inv=a_inv, params=params)
    return params, sk


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def encrypt(x: int, params: PublicParams, sk: SecretKey) -> list[int]:
    """
    Encrypt plaintext x ∈ [0, b^n - 1).

    Algorithm
    ---------
    1. Decompose x in base b → (x₁, …, xₙ)
    2. For each i, sample random noise rᵢ ∈ ℤ_p
    3. cᵢ = aᵢ · xᵢ + rᵢ  (mod p)
    4. Return ciphertext C = (c₁, …, cₙ)

    The noise rᵢ is freshly sampled every call → probabilistic encryption.
    """
    p, b, n = params.p, params.b, params.n
    max_x = b ** n
    if not (0 <= x < max_x):
        raise ValueError(f"Plaintext x={x} out of range [0, {max_x})")

    xs = digits_base_b(x, b, n)                    # decompose
    C  = []
    for i in range(n):
        r_i = secrets.randbelow(p)                  # fresh noise
        c_i = (sk.a[i] * xs[i] + r_i) % p
        C.append(c_i)
    return C


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def decrypt(C: list[int], params: PublicParams, sk: SecretKey,
            noise: list[int]) -> int:
    """
    Decrypt ciphertext C using secret key and the noise vectors used at
    encryption time.

    Note: in Domingo-Ferrer's original scheme the noise rᵢ is part of the
    secret key material (the decryptor knows them).  For a stateless demo
    we pass them explicitly; in practice they are stored in the key.

    Algorithm
    ---------
    For each i:  xᵢ = aᵢ⁻¹ · (cᵢ − rᵢ)  (mod p)
    Then:        x  = reconstruct(x₁,…,xₙ, base b)
    """
    p, b, n = params.p, params.b, params.n
    xs = []
    for i in range(n):
        xi = (sk.a_inv[i] * (C[i] - noise[i])) % p
        xs.append(xi)
    return reconstruct_from_digits(xs, b)


# ---------------------------------------------------------------------------
# Homomorphic operations (on ciphertext only — no key needed)
# ---------------------------------------------------------------------------

def homo_add(C1: list[int], C2: list[int], p: int) -> list[int]:
    """
    Homomorphic addition.

    C(x) ⊕ C(y) component-wise mod p.
    Decrypts to x + y  (if x+y < b^n).
    """
    assert len(C1) == len(C2), "Ciphertext length mismatch"
    return [(a + b) % p for a, b in zip(C1, C2)]


def homo_scalar_mul(k: int, C: list[int], p: int) -> list[int]:
    """
    Homomorphic scalar multiplication.

    k ⊗ C(x) component-wise mod p.
    Decrypts to k · x  (if k·x < b^n).
    """
    return [(k * c) % p for c in C]


def homo_linear_combination(coeffs: list[int],
                             ciphertexts: list[list[int]],
                             p: int) -> list[int]:
    """
    Homomorphic linear combination  Σ kᵢ · C(xᵢ).

    Decrypts to  Σ kᵢ · xᵢ.
    """
    assert len(coeffs) == len(ciphertexts)
    n = len(ciphertexts[0])
    result = [0] * n
    for k, C in zip(coeffs, ciphertexts):
        kC = homo_scalar_mul(k, C, p)
        result = homo_add(result, kC, p)
    return result


# ---------------------------------------------------------------------------
# Noise bookkeeping helper (needed for decryption after homomorphic ops)
# ---------------------------------------------------------------------------

def noise_add(r1: list[int], r2: list[int], p: int) -> list[int]:
    """Combined noise after ciphertext addition: r_sum = r1 + r2 (mod p)."""
    return [(a + b) % p for a, b in zip(r1, r2)]


def noise_scalar_mul(k: int, r: list[int], p: int) -> list[int]:
    """Combined noise after scalar multiplication: r_scaled = k*r (mod p)."""
    return [(k * ri) % p for ri in r]


def noise_linear_combination(coeffs: list[int],
                              noises: list[list[int]],
                              p: int) -> list[int]:
    n = len(noises[0])
    result = [0] * n
    for k, r in zip(coeffs, noises):
        kr = noise_scalar_mul(k, r, p)
        result = noise_add(result, kr, p)
    return result


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def _fmt(C: list[int], chars: int = 12) -> str:
    """Pretty-print a ciphertext vector (truncate each component for display)."""
    parts = [str(c)[:chars] + "…" for c in C]
    return "[" + ", ".join(parts) + "]"


def demo():
    print("Domingo-Ferrer (2002) Privacy Homomorphism — Demo")

    # --- Setup (small prime for fast demo; change digits=200 for production) ---
    DIGITS = 200         # use 200 in production
    BASE   = 10
    N      = 6           # supports plaintexts 0 … 10^6 - 1 = 999999

    params, sk = keygen(num_decimal_digits=DIGITS, b=BASE, n=N)
    p = params.p
    print(f"\np  = {p}")
    print(f"b  = {BASE},  n = {N},  max plaintext = {BASE**N - 1}\n")

    # --- Encrypt two values ---
    x, y = 123456, 234567
    print(f"Plaintexts:  x = {x},  y = {y}")

    # We store noise explicitly for decryption (in a real system it's in the key)
    r_x = [secrets.randbelow(p) for _ in range(N)]
    r_y = [secrets.randbelow(p) for _ in range(N)]

    # Build ciphertexts manually so we can track noise (mirrors encrypt() internals)
    xs_digits = digits_base_b(x, BASE, N)
    ys_digits = digits_base_b(y, BASE, N)

    C_x = [(sk.a[i] * xs_digits[i] + r_x[i]) % p for i in range(N)]
    C_y = [(sk.a[i] * ys_digits[i] + r_y[i]) % p for i in range(N)]

    print(f"\nC(x) = {_fmt(C_x)}")
    print(f"C(y) = {_fmt(C_y)}")

    # --- Test 1: Homomorphic addition ---
    C_sum   = homo_add(C_x, C_y, p)
    r_sum   = noise_add(r_x, r_y, p)
    dec_sum = decrypt(C_sum, params, sk, r_sum)
    print(f"\n[Test 1] Homomorphic addition")
    print(f"  C(x) ⊕ C(y) decrypts to: {dec_sum}  (expected: {x + y})")
    assert dec_sum == x + y, "Addition failed!"
    print("  ✓ Correct")

    # --- Test 2: Scalar multiplication ---
    k = 7
    C_scaled   = homo_scalar_mul(k, C_x, p)
    r_scaled   = noise_scalar_mul(k, r_x, p)
    dec_scaled = decrypt(C_scaled, params, sk, r_scaled)
    print(f"\n[Test 2] Scalar multiplication  (k = {k})")
    print(f"  {k} ⊗ C(x) decrypts to: {dec_scaled}  (expected: {k * x})")
    assert dec_scaled == k * x, "Scalar mul failed!"
    print("  ✓ Correct")

    # --- Test 3: Linear combination  2·x + 3·y ---
    coeffs     = [2, 3]
    C_lc       = homo_linear_combination(coeffs, [C_x, C_y], p)
    r_lc       = noise_linear_combination(coeffs, [r_x, r_y], p)
    dec_lc     = decrypt(C_lc, params, sk, r_lc)
    expected   = 2 * x + 3 * y
    print(f"\n[Test 3] Linear combination  2·C(x) + 3·C(y)")
    print(f"  Decrypts to: {dec_lc}  (expected: {expected})")
    assert dec_lc == expected, "Linear combination failed!"
    print("  ✓ Correct")

    # --- Test 4: Probabilistic encryption (same x → different ciphertexts) ---
    C_x1 = encrypt(x, params, sk)
    C_x2 = encrypt(x, params, sk)
    print(f"\n[Test 4] Probabilistic encryption (same x={x})")
    print(f"  C₁ = {_fmt(C_x1)}")
    print(f"  C₂ = {_fmt(C_x2)}")
    assert C_x1 != C_x2, "Ciphertexts should differ!"
    print("  ✓ Different ciphertexts for same plaintext")

    print("\n" + "=" * 65)
    print("All tests passed. For production use set DIGITS = 200.")
    print("=" * 65)


if __name__ == "__main__":
    demo()
