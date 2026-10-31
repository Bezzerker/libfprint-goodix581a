#!/usr/bin/env python3
"""Diagnostic: poll MCU finger-detect (FDT) levels and image ridge energy
together, to find a presence signal that ignores latent prints."""
import struct
import sys
import time

import capture as c
import stream
from probe import Dev

FDT_QUERY = b"\x0d\x01" + c.FDT + bytes(16)


def fdt_levels(dev):
    dev.cmd(0x36, FDT_QUERY + b"\x00", reply=False)
    body = dev.cmd(0x36, FDT_QUERY + b"\x01")
    return struct.unpack("<8H", body[4:20])


def energy(img, base):
    d = [a - b for a, b in zip(img, base)]
    return sum(abs(d[i] - d[i - 1]) for i in range(len(d)) if i % 64) // len(d)


def main():
    dev = Dev()
    dev.cmd(0xA2, b"\x05\x14")
    tls = c.Tls()
    c.connect(dev, tls)
    dev.cmd(0x90, c.CONFIG)
    dev.cmd(0xC4, b"\x01\x00", reply=False)
    base_img = stream.frame(dev, tls, *stream.MODES[0])
    base_fdt = fdt_levels(dev)
    print("base fdt", [hex(v) for v in base_fdt])
    print("TOUCH AND LIFT SEVERAL TIMES NOW", flush=True)
    t0 = time.time()
    while time.time() - t0 < float(sys.argv[1]):
        f = fdt_levels(dev)
        img = stream.frame(dev, tls, *stream.MODES[0])
        delta = [a - b for a, b in zip(f, base_fdt)]
        print(f"{time.time() - t0:5.1f}s fdt d {delta} max {max(map(abs, delta)):4d} "
              f"energy {energy(img, base_img)}", flush=True)
        time.sleep(0.1)


if __name__ == "__main__":
    main()
