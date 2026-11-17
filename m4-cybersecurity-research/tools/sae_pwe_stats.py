#!/usr/bin/env python3
"""Measure the iteration-count leakage of the VULNERABLE SAE hunt loop
(sae_derive_pwe_ecc, wpa_supplicant 2.3; extracted verbatim in
report/snippets/sae_derive_pwe_pre_dragonblood.inc) on the REAL
secp256r1 curve: sha256_prf KDF exactly as wpa's crypto wrapper, and the
candidate test reduced to the quadratic-residue decision that
crypto_ec_point_solve_y_coord performs (Legendre symbol, Euler
criterion). The loop pads to k=4 iterations "to protect against
side-channel attacks that attempt to determine the number of iterations
required"; this script shows the padding does not hide it: a large
share of runs stop AFTER the pad, with a geometric tail determined by
the password, i.e. runtime carries password-dependent signal
(CVE-2019-9495/9496, Dragonblood)."""
import hashlib, hmac, secrets, collections

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = p - 3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

def sha256_prf(key, seed, label, nbits):
    out = b""; A = seed
    while len(out) * 8 < nbits:
        A = hmac.new(key, A + label + seed, hashlib.sha256).digest()
        out += A
    return out[:(nbits + 7) // 2 // 4 * 2] if False else out[:(nbits + 7) // 8]

def is_qr(v):
    return v == 0 or pow(v, (p - 1) // 2, p) == 1

def iterations(password, k=4, cap=200):
    """FAITHFUL replica of the loop control in sae_derive_pwe_ecc:
    for (counter = 1; counter < k || !found; counter++) ... found stays
    false until the FIRST passing candidate, then the loop keeps testing
    (real work, result discarded) until counter reaches k."""
    salt = b"\x00" * 12 + b"\x01" * 12   # stand-in MAC pair
    found = False
    counter = 0
    for counter in range(1, cap + 1):
        seed = hmac.new(salt, password + bytes([counter]),
                        hashlib.sha256).digest()
        pv = sha256_prf(seed, b"", b"SAE Hunting and Pecking", 256)
        x = int.from_bytes(pv, "big")
        if x >= p:
            res = 0
        else:
            y2 = (x * x % p * x + a * x + b) % p
            res = 1 if is_qr(y2) else 0
        if res and not found:
            found = True
        if counter >= k and found:
            return counter
    return cap + 1

if __name__ == "__main__":
    N = 1500
    h = collections.Counter(iterations(secrets.token_bytes(8))
                            for _ in range(N))
    tail = sum(v for c, v in h.items() if c > 4) / N
    for c in sorted(h):
        print("real-stops-at-%d: %.3f" % (c, h[c] / N))
    print("P(work beyond the k=4 pad) = %.3f" % tail)
