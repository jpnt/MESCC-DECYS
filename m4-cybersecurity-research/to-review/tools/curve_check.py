#!/usr/bin/env python3
"""Point-count the sae_harness curve (y^2 = x^3 - 3x + 745 over F_1009):
proves #E = 987 = 3*7*47, the ORD the harness reduces scalars mod."""
p, a, b = 1009, 1006, 745          # a = -3 mod p
n = 1                              # point at infinity
for x in range(p):
    y2 = (x * x % p * x + a * x + b) % p
    roots = sum(1 for y in range(p) if y * y % p == y2)
    n += 1 if roots == 1 else (2 if roots >= 2 else 0)
assert n == 987, n
print("#E(F_1009) =", n, "= 3 * 7 * 47")
