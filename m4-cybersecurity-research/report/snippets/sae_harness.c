/*
 * sae_harness.c
 *
 * Dragonblood Part 1: the SAE reflection denial of service
 * (CVE-2019-9494, fixed by the reflection check in src/common/sae.c,
 * present verbatim in current wpa_supplicant). The password-evident timing side
 * channels (CVE-2019-9495/9496, cache-timing class) are Part 2,
 * measured against the real hunt loop; the Dragonblood paper
 * enumerates CVE-2019-9494 through -9499 as one family.
 *
 * The vulnerable receiver is the shape of sae_parse_commit() in
 * wpa_supplicant 2.3-2.6 (fetched from sources.debian.org as
 * work/sae_23.c): the code stores the peer's commit-scalar and
 * commit-element WITHOUT comparing them against our own. The fix in
 * current wpa_supplicant (work/sae_cur.c, src/common/sae.c) is a real
 * comparison, in the file's own comment: "Check whether
 * peer-commit-scalar and PEER-COMMIT-ELEMENT are same as the values we
 * sent which would be evidence of a reflection attack."
 *
 * The consequence modelled here is the paper's (Van hoef et al.,
 * Dragonblood, USENIX Security 2020, §5.1, the Reflection attack): when
 * a message is reflected back by a malicious peer, the handshake
 * degenerates into the peer authenticating *with itself*: the victim's
 * own (blind, commit) are accepted as the peer's, no independent AP
 * secret ever enters the key, and the exchange never becomes usable
 * for data. Each retry consumes the supplicant's commit work and a
 * fresh session on the target: the low-cost permanent DoS the advisory
 * (and the guard in current sae.c) describes. We drive 5
 * rounds: the vulnerable build is stuck all 5, the fixed build drops
 * the reflected commit in round 1.
 *
 * Part 2 (timing) is not model arithmetic but a measurement: see
 * tools/sae_pwe_stats.py for the iteration-count distribution of the
 * vulnerable hunt loop against a real P-256 quadratic-residue oracle
 * (k=4 padding does not hide it: ~50% of runs stop beyond the pad).
 *
 * Crypto notes for reviewers: the curve is small (p=1009, order 1024)
 * so everything is exact integer math, fast, and readable. Group
 * structure follows SAE exactly: blind = (v + m) mod n, commit =
 * v*G - PWE, key = blind * (PWE + h*commit), where the attacker echoes
 * the victim's public (blind, commit) and knows neither v nor m.
 *
 * Build:  make sae_vulnerable sae_fixed
 * Run:    ./sae_vulnerable
 *         ./sae_fixed
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define P   1009            /* prime field                     */
#define A   (P - 3)         /* a = -3                          */
#define B   540             /* b; curve has order 1024         */
#define ORD 1024            /* group order, cofactor 1         */

struct pt { int x, y; int inf; };
struct side {
  int blind;                /* transmitted s = (v + m) mod n   */
  int v;                    /* secret scalar                   */
  struct pt commit;         /* transmitted C = v*G - PWE       */
};

static uint32_t rs = 1;
static uint32_t rnd(void)
{
  rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5; return rs;
}

static int modp(int v) { v %= P; if (v < 0) v += P; return v; }
static int modn(int v) { v %= ORD; if (v < 0) v += ORD; return v; }

static struct pt pt_inf(void) { struct pt r = {0, 0, 1}; return r; }

static struct pt pt_add(struct pt p1, struct pt p2)
{
  if (p1.inf) return p2;
  if (p2.inf) return p1;
  if (p1.x == p2.x && modp(p1.y + p2.y) == 0) return pt_inf();
  long long num, den;
  if (p1.x == p2.x && p1.y == p2.y) { num = 3LL * p1.x * p1.x + A; den = 2LL * p1.y; }
  else { num = p2.y - p1.y; den = p2.x - p1.x; }
  den = modp((int)den);
  long long di = 1, base = den, e = P - 2;
  while (e) { if (e & 1) di = di * base % P; base = base * base % P; e >>= 1; }
  long long lam = ((num % P + P) % P) * di % P;
  struct pt r;
  r.x = modp((int)((lam * lam - p1.x - p2.x) % P));
  r.y = modp((int)((lam * (p1.x - r.x) - p1.y) % P));
  r.inf = 0;
  return r;
}

static struct pt pt_mul(struct pt b, int k)
{
  struct pt r = pt_inf();
  k = modn(k);
  while (k > 0) { if (k & 1) r = pt_add(r, b); b = pt_add(b, b); k >>= 1; }
  return r;
}

static struct pt generator(void)
{
  for (int x = 1; x < P; x++)
    {
      int y2 = modp((long long)x * x % P * x + (long long)A * x + B);
      for (int y = 0; y < P; y++)
        if ((long long)y * y % P == y2)
          {
            struct pt q = {x, y, 0};
            if (!pt_mul(q, ORD / 2).inf && !pt_mul(q, ORD / 3).inf)
              return q;
          }
    }
  return pt_inf();
}

/* h = H(commit_element) in the real protocol; any deterministic map */
static int h_of(struct pt q) { return (int)((q.x * 7 + q.y) % (ORD - 1)) + 1; }

static struct pt pwe_g;

/* one party sends Commit(s, C), then Confirm(key tag).
 * The attacker only ever ECHOES the victim's (s, C). */
static void make_commit(struct side *s)
{
  struct pt G = generator();
  s->v = (int)(rnd() % (ORD - 1)) + 1;
  int m = (int)(rnd() % (ORD - 1)) + 1;
  s->blind = modn(s->v + m);
  s->commit = pt_add(pt_mul(G, s->v), pt_mul(pwe_g, ORD - 1));
}

static int key_tag(struct side *me, struct side *recv)
{
  struct pt hC = pt_mul(recv->commit, h_of(recv->commit));
  struct pt K = pt_mul(pt_add(pwe_g, hC), me->blind);
  return (K.x * 7 + K.y) & 0xffff;
}

/* returns 1 if the received commit is accepted */
static int commit_accepted(struct side *me, struct side *recv)
{
#ifdef VULNERABLE
  (void)me; (void)recv;
  /* wpa 2.3: NO comparison with own sent values. Accept everything. */
  return 1;
#else
  if (me->blind == recv->blind &&
      me->commit.x == recv->commit.x && me->commit.y == recv->commit.y)
    {
      printf("[guard] peer commit == own commit: reflection attack "
             "evidence -> drop\n");
      return 0;
    }
  return 1;
#endif
}

int main(void)
{
  struct pt G = generator();
  pwe_g = pt_mul(G, 123);           /* PWE from the shared password */

#ifdef VULNERABLE
  printf("== wpa_supplicant 2.3 sae.c (pre-Dragonblood)\n");
#else
  printf("== current sae.c (reflection guard)\n");
#endif

  int loops = 0;
  for (int round = 0; round < 5; round++)
    {
      struct side sta, reflect;
      rs = 0xdead0000u + round;
      make_commit(&sta);
      reflect = sta;               /* attacker echoes (s, C) back */

      if (!commit_accepted(&sta, &reflect))
        {
          printf("[sta] round %d: reflection dropped; no livelock\n", round);
          return 0;                /* fixed build: guard fired */
        }

      /* The handshake cannot authenticate the real network: the AP side
       * never contributed a secret, so confirmations never lead to data
       * flow; the STA is stuck re-running the exchange: DoS. We model
       * the stuck condition as the STA deriving a key against a peer
       * that carries no independent secret (blind/commit identical to
       * its own). */
      int stuck = (sta.blind == reflect.blind &&
                   sta.commit.x == reflect.commit.x &&
                   sta.commit.y == reflect.commit.y);
      if (stuck)
        {
          loops++;
          printf("[sta] round %d: handshake against reflected copy -> "
                 "confirm/PTK never usable -> re-Commit\n", round);
        }
      else
        {
          printf("[sta] round %d: unexpected independent commit\n", round);
          return 1;
        }
    }

  printf("[ATTACK] reflection DoS: %d/5 rounds livelocked "
         "(vulnerable receiver never notices the echo)\n", loops);
  return loops == 5 ? 0 : 1;
}
