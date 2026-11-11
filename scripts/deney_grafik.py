"""FR-10 deney grafiği: target/deney/ozet.csv -> target/deney/grafik.png

Kullanım: python scripts/deney_grafik.py [ozet.csv] [cikti.png]
Çubuk = 30 tekrarın ortalaması, hata çubuğu = %95 güven aralığı.
"""
import csv
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

src = sys.argv[1] if len(sys.argv) > 1 else "target/deney/ozet.csv"
out = sys.argv[2] if len(sys.argv) > 2 else "target/deney/grafik.png"

with open(src, encoding="utf-8") as f:
    rows = list(csv.DictReader(f, delimiter=";"))

algos = list(dict.fromkeys(r["algoritma"] for r in rows))
sizes = sorted({int(r["belge_bayt"]) for r in rows})
labels = [f"{s / 2**20:.0f} MB" if s >= 1e6 else f"{s / 2**10:.0f} KB" for s in sizes]
by = {(r["algoritma"], int(r["belge_bayt"])): r for r in rows}

fig, axes = plt.subplots(1, 2, figsize=(10, 4))
width = 0.8 / len(algos)
for ax, key, title in ((axes[0], "imzalama", "İmzalama süresi"), (axes[1], "dogrulama", "Doğrulama süresi")):
    for i, a in enumerate(algos):
        xs = [j + (i - (len(algos) - 1) / 2) * width for j in range(len(sizes))]
        mean = [float(by[a, s][f"{key}_ort_ms"]) for s in sizes]
        ci = [float(by[a, s][f"{key}_ga95_ms"]) for s in sizes]
        ax.bar(xs, mean, width, yerr=ci, capsize=3, label=a.replace("_", "-"))
    ax.set_xticks(range(len(sizes)), labels)
    ax.set_xlabel("Belge boyutu")
    ax.set_ylabel("ms")
    ax.set_title(title)
    ax.grid(axis="y", alpha=0.3)
axes[0].legend()
fig.tight_layout()
fig.savefig(out, dpi=200)
print(out)
