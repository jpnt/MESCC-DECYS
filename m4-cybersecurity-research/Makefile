.PHONY: help sources report snippets clean

help:
	@printf '%s\n' \
		'make sources    fetch the two NuttX release trees the report quotes' \
		'make snippets   rebuild + run the ASan reproduction harnesses' \
		'make report     build report.pdf'

# Verbatim upstream sources used by the extracts (see report/appendix).
sources: work/nuttx work/bt_uart_nuttx-12.7.0.c

work/nuttx:
	git clone --quiet --depth 1 --branch nuttx-12.9.0 \
	  https://github.com/apache/nuttx.git work/nuttx

work/bt_uart_nuttx-12.7.0.c:
	@mkdir -p work
	curl -sfsL \
	  https://raw.githubusercontent.com/apache/nuttx/tags/nuttx-12.7.0/drivers/wireless/bluetooth/bt_uart.c \
	  -o $@

snippets: work/nuttx work/bt_uart_nuttx-12.7.0.c
	python3 work/extract_bt_uart.py
	$(MAKE) -C report/snippets
	$(MAKE) -C report/snippets run || true

report:
	typst compile --root . report/main.typ report.pdf

progress: progress_report.typ
	typst compile --root . progress_report.typ progress_report.pdf

clean:
	rm -f report/report.pdf
	$(MAKE) -C report/snippets clean
