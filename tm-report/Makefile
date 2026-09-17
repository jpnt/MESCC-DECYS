.PHONY: all dfd report clean install

all: dfd report

install:
	uv sync

dfd: install
	uv run python dfd/tm_network.py --dfd | dot -Grankdir=LR -Tpng -o dfd/appshield-dfd-network.png
	uv run python dfd/tm_bootable.py --dfd | dot -Grankdir=LR -Tpng -o dfd/appshield-dfd-bootable.png

report: dfd
	typst compile main.typ report.pdf

clean:
	rm -f dfd/appshield-dfd-network.png dfd/appshield-dfd-bootable.png report.pdf
