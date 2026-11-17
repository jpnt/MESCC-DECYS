.PHONY: all run fixed krack sae clean

CC      ?= clang
SANFLAGS = -fsanitize=address,undefined -g -O1

# Checked-in extracts of upstream sources, generated once by
# ../../work/extract_bt_uart.py (see appendix).
VULN_INC   := bt_uart_under_test.inc
FIXED_INC  := bt_uart_under_test_fixed.inc

all: bt_uart_harness bt_uart_harness_fixed

# The vulnerable build: btuart_read() + btuart_rxwork() verbatim from
# the nuttx-12.7.0 tag (before PR #16179 landed).
bt_uart_harness: bt_uart_harness.c $(VULN_INC) Makefile
	$(CC) $(SANFLAGS)  -DBT_UNDER_TEST_FILE='"$(VULN_INC)"' \
	      bt_uart_harness.c -o $@

# The control build: same harness, upstream 12.9.0 function kept intact.
bt_uart_harness_fixed: bt_uart_harness.c $(FIXED_INC) Makefile
	$(CC) $(SANFLAGS)  -DBT_UNDER_TEST_FILE='"$(FIXED_INC)"' \
	      bt_uart_harness.c -o $@

run: bt_uart_harness
	./bt_uart_harness acl || true

fixed: bt_uart_harness_fixed
	./bt_uart_harness_fixed acl

clean:
	rm -f bt_uart_harness bt_uart_harness_fixed inode_unlink_harness krack_vulnerable krack_fixed sae_vulnerable sae_fixed

# ---- KRACK (CVE-2017-13077..87) ----
krack_vulnerable: krack_harness.c
	$(CC) -DVULNERABLE $(SANFLAGS) krack_harness.c -o $@
krack_fixed: krack_harness.c
	$(CC) $(SANFLAGS) krack_harness.c -o $@

krack: krack_vulnerable krack_fixed
	./krack_vulnerable vulnerable
	./krack_fixed fixed

# ---- SAE / Dragonblood (CVE-2019-9494..97) ----
sae_vulnerable: sae_harness.c
	$(CC) -DVULNERABLE $(SANFLAGS) sae_harness.c -o $@
sae_fixed: sae_harness.c
	$(CC) $(SANFLAGS) sae_harness.c -o $@

sae: sae_vulnerable sae_fixed
	./sae_vulnerable
	./sae_fixed

# The .inc extracts are checked in (regenerate via the module-root
# extract_upstream.py / extract_wpa_upstream.py after `make sources`).
$(VULN_INC) $(FIXED_INC): ;
