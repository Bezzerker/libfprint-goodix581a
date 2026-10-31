#!/usr/bin/env python3
"""Collect a labelled dataset of finger frames (frame - empty background,
int16, 80x64) using FDT for touch detection: collect.py N OUTDIR"""
import array
import os
import sys
import time

import capture as c
import fdt_stream as f
import stream
from probe import Dev


def main():
    n, out = int(sys.argv[1]), sys.argv[2]
    os.makedirs(out, exist_ok=True)
    dev = Dev()
    dev.cmd(0xA2, b"\x05\x14")
    tls = c.Tls()
    c.connect(dev, tls)
    dev.cmd(0x90, c.CONFIG)
    dev.cmd(0xC4, b"\x01\x00", reply=False)
    base_fdt = f.fdt_levels(dev)
    base = stream.frame(dev, tls, *stream.MODES[0])
    got, on, streak, t0 = 0, False, 0, time.time()
    print("READY", flush=True)
    while got < n and time.time() - t0 < 600:
        lv = f.fdt_levels(dev)
        d = max(abs(a - b) for a, b in zip(lv, base_fdt))
        streak = streak + 1 if (d >= 40) != on else 0
        if streak >= 2:
            on, streak = not on, 0
            img = stream.frame(dev, tls, *stream.MODES[0])
            if on:
                diff = array.array("h", (a - b for a, b in zip(img, base)))
                open(f"{out}/{got:02d}.raw", "wb").write(diff.tobytes())
                got += 1
                print(f"{time.time() - t0:5.1f}s captured {got}/{n}", flush=True)
            else:
                base = img
        elif not on and d < 15:
            base_fdt = lv
        time.sleep(0.05)


if __name__ == "__main__":
    main()
