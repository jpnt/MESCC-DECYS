.PHONY: help sources report krack sae snippets clean progress

help:
	@printf '%s\n' \
		'make sources    fetch the two NuttX release trees the report quotes' \
		'make snippets   rebuild + run the ASan reproduction harnesses' \
		'make report     build report.pdf'
		'make krack sae  build + run the WPA mechanism models'

# Verbatim upstream sources used by the extracts (see report/appendix).
sources: work/nuttx work/bt_uart_nuttx-12.7.0.c report/snippets/upstream

# wpa_supplicant hostap sources are fetched once and checked in under
# report/snippets/upstream/ (Debian sources.debian.org data mirror):
# wpa_23.c, wpa_cur.c, sae_23.c, sae_cur.c -> sources-esp also records ESP-IDF provenance greps.
report/snippets/upstream:
	@echo "checked in under report/snippets/upstream/ (no fetch needed)"

sources-esp:
	mkdir -p work
	curl -sfsL https://raw.githubusercontent.com/espressif/esp-idf/v4.4/components/wpa_supplicant/README.md -o work/esp_v44_wpa_readme.md
	curl -sfsL https://raw.githubusercontent.com/espressif/esp-idf/v5.2/components/wpa_supplicant/README.md -o work/esp_v52_wpa_readme.md
	@echo "tree-level claims (dpp/dragonfly/sae_pk presence) were verified via GitHub browse at these tags;"
	@echo "the two READMEs above are the anchor documents; see Chapter 3 for the dating argument."

work/nuttx:
	git clone --quiet --depth 1 --branch nuttx-12.9.0 \
	  https://github.com/apache/nuttx.git work/nuttx

work/bt_uart_nuttx-12.7.0.c:
	@mkdir -p work
	curl -sfsL \
	  https://raw.githubusercontent.com/apache/nuttx/tags/nuttx-12.7.0/drivers/wireless/bluetooth/bt_uart.c \
	  -o $@

snippets: work/nuttx work/bt_uart_nuttx-12.7.0.c
	python3 report/snippets/extract_upstream.py
	$(MAKE) -C report/snippets
	$(MAKE) -C report/snippets run || true
	$(MAKE) -C report/snippets krack || true
	$(MAKE) -C report/snippets sae || true

krack: report/snippets/upstream
	$(MAKE) -C report/snippets krack

sae: report/snippets/upstream
	$(MAKE) -C report/snippets sae

report:
	typst compile --root . report/main.typ report.pdf

progress: progress_report.typ
	typst compile --root . progress_report.typ progress_report.pdf

clean:
	rm -f report/report.pdf
	$(MAKE) -C report/snippets clean
