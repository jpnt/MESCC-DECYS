.PHONY: help report models figures check clean $(LEVELS)

# One pytm model per DFD: tools/pytm/lv0.py, lv0boot.py, lv1.py, ...
LEVELS := $(patsubst tools/pytm/%.py,%,$(wildcard tools/pytm/lv*.py))
PYTM := uv run -q --project tools/pytm python
TRIAGE := report/data/pytm-triage.yaml

help:
	@printf '%s\n' \
		'make <level>   rebuild one model: build/<level>/{pytm.json,dfd.dot,pytm-dfd.png}' \
		'make models    build every model' \
		'make figures   render the figures drawn by hand (attack tree)' \
		'make check     build every model and verify every pytm finding is triaged' \
		'make report    run check and figures, then build report.pdf' \
		'make clean     remove build/ and report.pdf' \
		'' \
		'Levels: $(LEVELS)'

report: check figures
	typst compile --root . report/main.typ report.pdf

models: $(LEVELS:%=build/%/pytm.json)

$(LEVELS): %:
	@$(MAKE) --no-print-directory -B build/$@/pytm.json

# Every pytm threat kept for a level must appear in the triage table.
check: models
	@for l in $(LEVELS); do $(PYTM) tools/pytm/coverage.py build/$$l/pytm.json $(TRIAGE) || exit 1; done

build/%/pytm.json: tools/pytm/%.py tools/pytm/export.py tools/pytm/appshield_common.py
	$(PYTM) tools/pytm/export.py $* build/$*
	dot -Grankdir=LR -Tpng build/$*/dfd.dot -o build/$*/pytm-dfd.png

figures: build/figures/attack-tree.png

build/figures/%.png: report/figures/%.dot
	@mkdir -p build/figures
	dot -Tpng -Gdpi=150 $< -o $@

clean:
	rm -rf build report.pdf
