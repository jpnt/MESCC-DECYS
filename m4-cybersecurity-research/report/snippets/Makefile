.PHONY: all run fixed clean

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
	rm -f bt_uart_harness bt_uart_harness_fixed
