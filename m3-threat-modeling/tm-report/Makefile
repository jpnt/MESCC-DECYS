.PHONY: help report models check clean $(LEVELS)

# One pytm model per DFD depth: tools/pytm/lv0.py, lv1.py, ...
LEVELS := $(patsubst tools/pytm/%.py,%,$(wildcard tools/pytm/lv*.py))
PYTM := uv run -q --project tools/pytm python

help:
	@printf '%s\n' \
		'make <level>   rebuild one model: build/<level>/{pytm.json,dfd.dot,pytm-dfd.png}' \
		'make models    build every model' \
		'make check     build every model and verify coverage against analysis/lvN/2-stride.md' \
		'make report    run check, then build report.pdf' \
		'make clean     remove build/ and report.pdf' \
		'' \
		'Levels: $(LEVELS)'

report: check
	typst compile --root . report/main.typ report.pdf

models: $(LEVELS:%=build/%/pytm.json)

$(LEVELS): %:
	@$(MAKE) --no-print-directory -B build/$@/pytm.json

# Every pytm threat kept for a level must be triaged in its 2-stride.md.
check: models
	@for l in $(LEVELS); do $(PYTM) tools/pytm/coverage.py build/$$l/pytm.json analysis/$$l/2-stride.md || exit 1; done

build/%/pytm.json: tools/pytm/%.py tools/pytm/export.py
	$(PYTM) tools/pytm/export.py $* build/$*
	dot -Grankdir=LR -Tpng build/$*/dfd.dot -o build/$*/pytm-dfd.png

clean:
	rm -rf build report.pdf
