.PHONY: all krack sae clean

CC      ?= clang
SANFLAGS = -fsanitize=address,undefined -g -O1

all: krack sae

krack_vulnerable: krack_harness.c
	$(CC) -DVULNERABLE $(SANFLAGS) krack_harness.c -o $@
krack_fixed: krack_harness.c
	$(CC) $(SANFLAGS) krack_harness.c -o $@

krack: krack_vulnerable krack_fixed
	./krack_vulnerable vulnerable
	./krack_fixed fixed

sae_vulnerable: sae_harness.c
	$(CC) -DVULNERABLE $(SANFLAGS) sae_harness.c -o $@
sae_fixed: sae_harness.c
	$(CC) $(SANFLAGS) sae_harness.c -o $@

sae: sae_vulnerable sae_fixed
	./sae_vulnerable
	./sae_fixed

clean:
	rm -f krack_vulnerable krack_fixed sae_vulnerable sae_fixed
