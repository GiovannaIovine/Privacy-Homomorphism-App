"""
Domingo-Ferrer (2002) Privacy Homomorphism
===========================================
Faithful implementation of the scheme described in:

  Josep Domingo-Ferrer, "A provably secure additive and multiplicative
  privacy homomorphism", ISC 2002, LNCS 2433, pp. 471-483, Springer.

SCHEME OVERVIEW
---------------
Public parameters : (m, d)
  m  — large modulus, ≈ 10^200 (arbitrary-precision; trivial in Python).
       Should have many small divisors AND many coprime residues (high φ(m)/m).
       In a minimal deployment m can be prime; in a full deployment m is a
       smooth-ish composite and m' is a proper small divisor.
  d  — splitting factor (recommended d > 2; d = 2 only in the paper's example).

Secret key : (r, m')
  r  — random element of Z*_m (invertible mod m).
  m' — a divisor of m that defines the *cleartext* space Z_{m'}.
       s = log_{m'}(m) is the security parameter (see Corollary 13 of the paper).
       The larger s is relative to n (number of known plaintext-ciphertext pairs),
       the smaller the probability of a successful key-guessing attack.

Encryption  Ek(a):
  1. Randomly split a ∈ Z_{m'} into d parts a_1,…,a_d with Σa_j ≡ a (mod m').
  2. Return the vector  (a_1·r^1 mod m,  a_2·r^2 mod m,  …,  a_d·r^d mod m).
  Each component is labelled by its *r-degree* (1 through d).

Decryption  Dk(C):
  For each r-degree j:  a_j = C[j] · r^{-j}  (mod m).
  Result:  (Σ a_j)  mod m'.

Homomorphic operations (no key required — done on ciphertext only):
  Addition / Subtraction : componentwise  (matching r-degrees).
  Scalar multiplication  : multiply every component by the scalar.
  Full multiplication    : polynomial multiplication over Z_m
                           (doubles max r-degree, like multiplying two polynomials).
  Linear combination     : Σ k_i · Ek(a_i)  ->  Ek(Σ k_i · a_i).

Security (Corollary 13):
  With n known plaintext-ciphertext pairs and security parameter s = log_{m'}(m),
  the probability of random key guessing is at most  π²·(m')^{n-s} / 6  when s > n.
  This can be made arbitrarily small by choosing s large enough.
"""

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


# ═══════════════════════════════════════════════════════════════════════════════
# Encryption
# ═══════════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════════
# Decryption
# ═══════════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════════
# Homomorphic operations  (no key required)
# ═══════════════════════════════════════════════════════════════════════════════

def homo_add(c1: dict, c2: dict, m: int) -> dict:
    """
    Homomorphic addition:  C(a) ⊕ C(b)  →  C(a + b).

    Components with the *same r-degree* are added componentwise mod m.
    Components present in only one operand are copied as-is.
    After decryption the result equals (a + b) mod m'.
    """
    degrees = set(c1) | set(c2)
    return {j: (c1.get(j, 0) + c2.get(j, 0)) % m for j in degrees}


def homo_sub(c1: dict, c2: dict, m: int) -> dict:
    """
    Homomorphic subtraction:  C(a) ⊖ C(b)  →  C(a − b).

    Componentwise subtraction mod m for matching r-degrees.
    After decryption the result equals (a − b) mod m'.
    """
    degrees = set(c1) | set(c2)
    return {j: (c1.get(j, 0) - c2.get(j, 0)) % m for j in degrees}


def homo_scalar_mul(k: int, c: dict, m: int) -> dict:
    """
    Homomorphic scalar multiplication:  k ⊗ C(a)  →  C(k · a).

    Multiply every ciphertext component by the integer constant k mod m.
    After decryption the result equals (k · a) mod m'.
    r-degrees are *unchanged* (unlike full ciphertext multiplication).
    """
    return {j: (k * cj) % m for j, cj in c.items()}


def homo_mul(c1: dict, c2: dict, m: int) -> dict:
    """
    Homomorphic multiplication:  C(a) ⊗ C(b)  →  C(a · b).

    Works exactly like polynomial multiplication over Z_m:
    a term of r-degree i times a term of r-degree j yields a term of
    r-degree i + j (contributions with the same output degree are summed).

    ⚠  This operation *doubles* the maximum r-degree.  After k multiplications
       starting from degree-d ciphertexts, the degree grows to d · 2^k.
       Prefer homo_scalar_mul when one operand is a known constant.

    After decryption the result equals (a · b) mod m'.
    """
    result: dict[int, int] = {}
    for i, ci in c1.items():
        for j, cj in c2.items():
            deg = i + j
            result[deg] = (result.get(deg, 0) + ci * cj) % m
    return result


def homo_linear_combination(
    coeffs: list[int],
    ciphertexts: list[dict],
    m: int,
) -> dict:
    """
    Homomorphic linear combination:  Σ k_i · C(a_i)  →  C(Σ k_i · a_i).

    Uses only scalar multiplications and additions (r-degree stays at d).
    After decryption the result equals (Σ k_i · a_i) mod m'.
    """
    if len(coeffs) != len(ciphertexts):
        raise ValueError("coeffs and ciphertexts must have the same length")
    result: dict[int, int] = {}
    for k, c in zip(coeffs, ciphertexts):
        kc     = homo_scalar_mul(k, c, m)
        result = homo_add(result, kc, m)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Security analysis  (Theorem 7 and Corollary 13)
# ═══════════════════════════════════════════════════════════════════════════════

def security_analysis(m: int, m_prime: int, s: float, n_known: int) -> None:
    """
    Print a security report based on Theorem 7 and Corollary 13 of the paper.

    Parameters
    ----------
    m        : public modulus
    m_prime  : secret cleartext modulus (divisor of m)
    s        : security parameter s = log_{m'}(m)
    n_known  : number of known plaintext-ciphertext pairs available to the adversary
    """
    print("\n" + "─" * 65)
    print("Security Analysis  (Domingo-Ferrer 2002, Theorem 7 / Corollary 13)")
    print("─" * 65)

    digits_m       = len(str(m))
    digits_m_prime = len(str(m_prime))

    print(f"  |m|  = {digits_m} decimal digits   ({m.bit_length()} bits)")
    print(f"  |m'| = {digits_m_prime} decimal digits")
    print(f"  s    = log_{{m'}}(m) = {s:.6f}   (security parameter)")
    print(f"  n    = {n_known}   (number of known plaintext-ciphertext pairs)")
    print()

    if s <= n_known:
        print("  ⚠  WARNING: s ≤ n — security NOT guaranteed.")
        print("     The adversary may have enough information to determine the key.")
        print("     → Increase s by choosing a larger m or a smaller m'.")
        return

    # Expected number of keys consistent with n known pairs (Theorem 7):
    #   E[#consistent keys] ≈ max( (6/π²) · (m')^{s-n}, 1 )
    log10_consistent = (s - n_known) * math.log10(m_prime) + math.log10(6 / math.pi**2)
    print(f"  Expected # of keys consistent with {n_known} known pair(s):")
    if log10_consistent > 300:
        print(f"    ≈ 10^{log10_consistent:.1f}   (astronomically large)")
    else:
        print(f"    ≈ {10**log10_consistent:.3e}")

    # Probability of random key guessing (Corollary 13):
    #   P_guess ≤ π²·(m')^{n-s} / 6
    log10_prob = (n_known - s) * math.log10(m_prime) + math.log10(math.pi**2 / 6)
    print(f"\n  P(random key guess succeeds) ≤ 10^{log10_prob:.2f}")
    if log10_prob < -20:
        print("  → Negligible: far below any practical security threshold.")
    elif log10_prob < -10:
        print("  → Very small, but consider increasing s for long-term security.")
    else:
        print("  → ⚠  Non-negligible — increase s or reduce n.")

    # Table from Section 4 of the paper (a few reference rows):
    print()
    print("  Reference table (from paper, Table 1):")
    print(f"  {'n':>4}  {'s':>4}  {'|m′|':>6}  {'|m|':>6}  {'P_guess':>20}")
    print(f"  {'-'*4}  {'-'*4}  {'-'*6}  {'-'*6}  {'-'*20}")
    for row_n, row_s, row_lm_prime, row_lm in [
        (5,  5, 20, 100), (5,  6, 20, 120),
        (10, 11, 20, 220), (50, 51, 5, 255), (50, 53, 5, 265),
    ]:
        log_p = (row_n - row_s) * row_lm_prime + math.log10(math.pi**2 / 6)
        p_str = f"≈ 10^{log_p:.1f}" if log_p < -2 else "≈ 1"
        print(f"  {row_n:>4}  {row_s:>4}  {row_lm_prime:>6}  {row_lm:>6}  {p_str:>20}")

    print("─" * 65)


# ═══════════════════════════════════════════════════════════════════════════════
# Validation: reproduce the Section 3 numerical example exactly
# ═══════════════════════════════════════════════════════════════════════════════

def _paper_example() -> None:
    """
    Reproduce the numerical example from Section 3 of the paper (d=2, m=28, r=3, m'=7).
    Computes  (x1 + x2 + x3) · x4  with  (x1,x2,x3,x4) = (−0.1, 0.3, 0.1, 2).
    The paper multiplies by 10 to work with integers: (−1, 3, 1, 2), denominator=10.
    Expected result: 6/10 = 0.6.
    """
    m = 28; d = 2; r = 3; m_prime = 7
    key = {
        "m": m, "d": d, "r": r, "m_prime": m_prime,
        "r_inv": mod_inv(r, m),
        "r_pows":     [pow(r,           j, m) for j in range(1, 2*d + 1)],
        "r_inv_pows": [pow(mod_inv(r,m),j, m) for j in range(1, 8*d + 1)],
    }

    # The paper fixes the random splits for illustration:
    def _encrypt_with_fixed_split(a1, a2):
        return {1: (a1 * r) % m, 2: (a2 * r**2) % m}

    C = {
        -1: _encrypt_with_fixed_split(2, 4),   # Ek(-1) = (6, 8)
         3: _encrypt_with_fixed_split(2, 1),   # Ek(3)  = (6, 9)
         1: _encrypt_with_fixed_split(4, 4),   # Ek(1)  = (12,8)
         2: _encrypt_with_fixed_split(3, 6),   # Ek(2)  = (9, 26)
    }

    print("─" * 55)
    print("Section 3 paper example  (x1+x2+x3)·x4 = 0.6")
    print("─" * 55)
    for val, c in C.items():
        print(f"  Ek({val:2d}) = {c}")

    # Unclassified level: additions
    sum3 = homo_add(homo_add(C[-1], C[3], m), C[1], m)
    print(f"\n  Ek(-1)+Ek(3)+Ek(1) = {sum3}   expected {{1:24, 2:25}}")

    # Unclassified level: multiplication
    prod = homo_mul(sum3, C[2], m)
    print(f"  product             = {prod}   expected {{2:20, 3:9, 4:6}}")

    # Classified level: decrypt (denominator = 10·1 = 10)
    numerator = decrypt(prod, key)
    print(f"\n  Decrypted numerator = {numerator}   expected 6")
    print(f"  Final result        = {numerator}/10 = {numerator/10}   expected 0.6")
    assert numerator == 6, "Paper example mismatch!"
    print("  ✓ Exact match with paper")


# ═══════════════════════════════════════════════════════════════════════════════
# Demo / self-test
# ═══════════════════════════════════════════════════════════════════════════════

def demo(digits: int = 200, d: int = 3) -> None:
    """
    Full demo:
      1. Reproduce the paper's Section 3 example.
      2. Keygen with a ~200-digit modulus.
      3. Verify all homomorphic operations.
      4. Run the security analysis.
    """
    print("═" * 65)
    print("Domingo-Ferrer (2002) Privacy Homomorphism — Demo")
    print("═" * 65 + "\n")

    _paper_example()
    print()

    # ── Keygen ────────────────────────────────────────────────────────────────
    print(f"\nKeygen with {digits}-digit modulus, d={d} …")
    key = keygen(num_decimal_digits=digits, d=d, verbose=True)
    m       = key["m"]
    m_prime = key["m_prime"]

    # Use two small plaintexts
    a, b, k = 123456, 234567, 7
    print(f"\nPlaintexts: a = {a},  b = {b},  scalar k = {k}")

    # ── Encrypt ───────────────────────────────────────────────────────────────
    Ca = encrypt(a, key)
    Cb = encrypt(b, key)
    first_comp = str(list(Ca.values())[0])
    print(f"\nC(a) has {len(Ca)} components; first component = {first_comp[:30]}…")

    # ── Test: addition ────────────────────────────────────────────────────────
    C_add   = homo_add(Ca, Cb, m)
    dec_add = decrypt(C_add, key)
    exp_add = (a + b) % m_prime
    print(f"\n[+] a + b     = {exp_add}")
    print(f"    decrypted = {dec_add}   OK={dec_add == exp_add}")
    assert dec_add == exp_add, "Addition failed"

    # ── Test: subtraction ────────────────────────────────────────────────────
    C_sub   = homo_sub(Ca, Cb, m)
    dec_sub = decrypt(C_sub, key)
    exp_sub = (a - b) % m_prime
    print(f"\n[-] a - b     = {exp_sub}")
    print(f"    decrypted = {dec_sub}   OK={dec_sub == exp_sub}")
    assert dec_sub == exp_sub, "Subtraction failed"

    # ── Test: scalar multiplication ───────────────────────────────────────────
    C_scl   = homo_scalar_mul(k, Ca, m)
    dec_scl = decrypt(C_scl, key)
    exp_scl = (k * a) % m_prime
    print(f"\n[×k] k·a     = {exp_scl}")
    print(f"     decrypted = {dec_scl}   OK={dec_scl == exp_scl}")
    assert dec_scl == exp_scl, "Scalar multiplication failed"

    # ── Test: full multiplication ─────────────────────────────────────────────
    C_mul   = homo_mul(Ca, Cb, m)
    dec_mul = decrypt(C_mul, key)
    exp_mul = (a * b) % m_prime
    print(f"\n[×] a · b     = {exp_mul}")
    print(f"    decrypted = {dec_mul}   OK={dec_mul == exp_mul}")
    assert dec_mul == exp_mul, "Multiplication failed"

    # ── Test: linear combination 2a + 3b ─────────────────────────────────────
    C_lc   = homo_linear_combination([2, 3], [Ca, Cb], m)
    dec_lc = decrypt(C_lc, key)
    exp_lc = (2 * a + 3 * b) % m_prime
    print(f"\n[lc] 2a + 3b  = {exp_lc}")
    print(f"     decrypted = {dec_lc}   OK={dec_lc == exp_lc}")
    assert dec_lc == exp_lc, "Linear combination failed"

    # ── Test: probabilistic encryption ───────────────────────────────────────
    Ca2 = encrypt(a, key)
    assert Ca != Ca2, "Same plaintext produced the same ciphertext (not probabilistic)!"
    print(f"\n[P] Same plaintext a={a} → two different ciphertexts ✓")

    # ── Security analysis ─────────────────────────────────────────────────────
    security_analysis(m=m, m_prime=m_prime, s=key["s"], n_known=5)

    print("\n" + "═" * 65)
    print("All tests passed.  ✓")
    print("═" * 65)


# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    demo(digits=200, d=3)
