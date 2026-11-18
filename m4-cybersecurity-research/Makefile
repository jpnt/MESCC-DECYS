.PHONY: help sources snippets figures report krack sae progress slides clean

help:
	@printf '%s\n' \
		'make snippets   rebuild + run the WPA model harnesses' \
		'make krack sae  run one model pair' \
		'make report     build report.pdf (renders figures/*.dot first)' \
		'make slides     build slides.pdf (presentation)' \
		'make progress   build progress_report.pdf' \
		'make sources-esp refetch the ESP-IDF/lab evidence (needs network)'

# hostap sources are checked in under report/snippets/upstream/ (official
# w1.fi release slices; tarballs under lab/); lab/ holds the ESP-IDF audit
# evidence backing Chapter 3. Nothing to fetch for normal builds.
sources: report/snippets/upstream

report/snippets/upstream:
	@echo "checked in under report/snippets/upstream/ (verify: shasum -a 256 lab/*.tar.gz)"

sources-esp:
	mkdir -p lab
	@for tag in v4.4 v5.2; do \
	  short=$${tag#v}; short=$${short%.*}; \
	  curl -sfsL https://raw.githubusercontent.com/espressif/esp-idf/$${tag}/components/wpa_supplicant/README.md -o lab/wpa_readme_$${short}.md; \
	  curl -sfsL "https://api.github.com/repos/espressif/esp-idf/git/trees/$${tag}?recursive=1" -o lab/$${short}_src.json; \
	  curl -sfsL "https://api.github.com/repos/espressif/esp-idf/commits?sha=$${tag}&path=components/wpa_supplicant&per_page=100" -o lab/$${short}_commits.json; \
	  curl -sfsL https://raw.githubusercontent.com/espressif/esp-idf/$${tag}/components/wpa_supplicant/src/rsn_supp/wpa.c -o lab/$${short}_wpa.c; \
	done
	python3 tools/esp_evidence.py
	python3 tools/esp_timeline.py
	python3 tools/esp_guard_probe.py

figures:
	for f in report/figures/*.dot; do dot -Tpng -Gdpi=180 "$$f" -o "$${f%.dot}.png"; done

snippets:
	python3 report/snippets/extract_wpa_upstream.py
	$(MAKE) -C report/snippets krack
	$(MAKE) -C report/snippets sae

krack:
	$(MAKE) -C report/snippets krack

sae:
	$(MAKE) -C report/snippets sae

report: figures
	typst compile --root . report/main.typ report.pdf

slides: slides.typ
	typst compile --root . slides.typ slides.pdf

progress: progress_report.typ
	typst compile --root . progress_report.typ progress_report.pdf

clean:
	$(MAKE) -C report/snippets clean
	rm -f report.pdf slides.pdf progress_report.pdf
