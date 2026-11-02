#!/usr/bin/env python3

import csv
import statistics
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT_DIR = "../"
ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def read_length(path):
    rows = defaultdict(list)
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows[int(r["length"])].append(float(r["elapsed_ms"]))
    return {k: statistics.median(v) for k, v in sorted(rows.items())}


def read_chars(path):
    rows = defaultdict(lambda: defaultdict(list))
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows[int(r["position"])][r["candidate"]].append(float(r["elapsed_ms"]))
    medians = {}
    for pos, cands in rows.items():
        medians[pos] = {c: statistics.median(v) for c, v in cands.items()}
    return medians


def prominence(medians, l):
    """How far length l rises above its neighbours (the true-length spike)."""
    lo = medians.get(l - 1, medians[l])
    hi = medians.get(l + 1, medians[l])
    return medians[l] - (lo + hi) / 2


def plot_length(medians, out):
    lengths = sorted(medians)
    values = [medians[l] for l in lengths]
    best = max(lengths, key=lambda l: prominence(medians, l))

    fig, ax = plt.subplots(figsize=(8, 4))
    colors = ["#c0392b" if l == best else "#5b8def" for l in lengths]
    ax.bar(lengths, values, color=colors)
    ax.set_xlabel("guessed length (chars)")
    ax.set_ylabel("median time to first response (ms)")
    ax.set_ylim(0, max(values) * 1.15)
    ax.set_title("Target 1 - length inference (bump at the true length)")
    ax.set_xticks(lengths)
    ax.text(0.02, 0.92, f"true length = {best}", transform=ax.transAxes,
            color="#c0392b", fontweight="bold")

    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)


def plot_position(pos_medians, pos, out):
    cands = [c for c in ALPHABET if c in pos_medians]
    values = [pos_medians[c] for c in cands]
    winner = max(cands, key=lambda c: pos_medians[c])
    colors = ["#c0392b" if c == winner else "#5b8def" for c in cands]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(cands, values, color=colors)
    ax.set_xlabel("candidate character")
    ax.set_ylabel("median time to first response (ms)")
    ax.set_title(f"Target 1 - character {pos + 1} (winner '{winner}')")
    ax.set_ylim(min(values) - 0.5, max(values) + 0.7)
    ax.annotate(f"'{winner}'", xy=(cands.index(winner), pos_medians[winner]),
                xytext=(cands.index(winner), pos_medians[winner] + 0.3),
                ha="center", color="#c0392b", fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    plt.close(fig)


def main():
    length_medians = read_length(ROOT_DIR + "timing-length.csv")
    plot_length(length_medians, ROOT_DIR + "length.png")

    char_medians = read_chars(ROOT_DIR + "timing-chars.csv")
    positions = sorted(char_medians)
    for pos in positions:
        plot_position(char_medians[pos], pos, ROOT_DIR + f"position-{pos + 1}.png")
    print(f"wrote length.png and position-1..{len(positions)}.png")


if __name__ == "__main__":
    raise SystemExit(main())
