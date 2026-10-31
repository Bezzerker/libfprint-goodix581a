#!/usr/bin/env python3
"""Evaluate score fusion on the labelled dataset: eval_ds2.py MATRIX
MATRIX is sigeval output over enroll/*.raw genuine/*.raw impostor/*.raw (20/15/30)."""
import sys

import numpy as np

S = np.loadtxt(sys.argv[1], dtype=int)
E, G, I = range(0, 20), range(20, 35), range(35, 65)
gen = S[np.ix_(G, E)]  # probe x enrolled sample
imp = S[np.ix_(I, E)]

rules = {
    "max": lambda v: v.max(axis=1),
    "top2": lambda v: np.sort(v, axis=1)[:, -2:].sum(axis=1),
    "top3": lambda v: np.sort(v, axis=1)[:, -3:].sum(axis=1),
    "2nd": lambda v: np.sort(v, axis=1)[:, -2],
    "cnt>=5": lambda v: (v >= 5).sum(axis=1),
    "sum>3": lambda v: np.clip(v - 3, 0, None).sum(axis=1),
}
print("genuine max per probe :", gen.max(axis=1))
print("impostor max per probe:", imp.max(axis=1))
for name, f in rules.items():
    g, i = f(gen), f(imp)
    thr = i.max() + 1
    print(f"{name:7s} impostor max {i.max():3d} | genuine accepted at thr {thr}: "
          f"{(g >= thr).mean():.2f}, at thr {thr + 1}: {(g >= thr + 1).mean():.2f} | genuine {np.sort(g)}")
