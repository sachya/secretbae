#!/usr/bin/env python3
"""Renders bench/results.json into docs/assets/benchmark.png. Real data in, real chart out."""

import json
import pathlib
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

root = pathlib.Path(__file__).resolve().parent.parent
results = json.loads((root / "bench" / "results.json").read_text())

labels = list(results.keys())
p50 = [results[k]["p50_ms"] for k in labels]
p99 = [results[k]["p99_ms"] for k in labels]

fig, ax = plt.subplots(figsize=(8, 4.5))
y = range(len(labels))
height = 0.35

ax.barh([i + height / 2 for i in y], p50, height=height, label="p50", color="#2f9e44")
ax.barh([i - height / 2 for i in y], p99, height=height, label="p99", color="#5c7cfa")

ax.set_yticks(list(y))
ax.set_yticklabels(labels)
ax.invert_yaxis()
ax.set_xlabel("milliseconds (lower is better)")
ax.set_title("secretbae latency, measured (300 iterations each)")
ax.legend(loc="lower right")
ax.grid(axis="x", alpha=0.3)

for i, (v50, v99) in enumerate(zip(p50, p99)):
    ax.text(v50 + 0.5, i + height / 2, f"{v50:.1f}ms", va="center", fontsize=8)
    ax.text(v99 + 0.5, i - height / 2, f"{v99:.1f}ms", va="center", fontsize=8)

fig.tight_layout()
out = root / "docs" / "assets" / "benchmark.png"
fig.savefig(out, dpi=150)
print(f"wrote {out}")
