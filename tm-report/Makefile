.PHONY: report models check clean

# One pytm model per DFD depth: tools/pytm/lv0.py, lv1.py, ...
LEVELS := $(patsubst tools/pytm/%.py,%,$(wildcard tools/pytm/lv*.py))
PYTM := uv run -q --project tools/pytm python

report: check
	typst compile --root . report/main.typ report.pdf

models: $(LEVELS:%=build/%/pytm.json)

# Every pytm threat kept for a level must be triaged in its 2-stride.md.
check: models
	@for l in $(LEVELS); do $(PYTM) tools/pytm/coverage.py build/$$l/pytm.json analysis/$$l/2-stride.md || exit 1; done

build/%/pytm.json: tools/pytm/%.py tools/pytm/export.py
	$(PYTM) tools/pytm/export.py $* build/$*
	dot -Grankdir=LR -Tpng build/$*/dfd.dot -o build/$*/pytm-dfd.png

clean:
	rm -rf build report.pdf
