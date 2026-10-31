#!/usr/bin/env python3
"""Diagnostic: stream frames for N seconds and print how far each frame is
from the first one, for several capture modes. Touch the sensor meanwhile."""
import struct
import sys
import time

import capture as c
from probe import Dev

MODES = [  # (payload mode, reg 0x022c value, DAC)
    (b"\x01\x03", b"\x0a\x03", 0x127),
    (b"\x45\x03", b"\x05\x03", 0xE7),
    (b"\x81\x03", b"\x0a\x03", 0x118),
]


def frame(dev, tls, mode, reg, dac):
    dev.cmd(0x80, b"\x00\x2c\x02" + reg, reply=False)
    img = c.get_image(dev, tls, mode + struct.pack("<4H", dac, dac - 6, dac, dac - 4))
    dev.cmd(0x80, b"\x00\x2c\x02" + reg[:1] + b"\x02", reply=False)
    return img


def main():
    dev = Dev()
    dev.cmd(0xA2, b"\x05\x14")
    tls = c.Tls()
    c.connect(dev, tls)
    dev.cmd(0x90, c.CONFIG)
    dev.cmd(0xC4, b"\x01\x00", reply=False)
    first = [frame(dev, tls, *m) for m in MODES]
    t0 = time.time()
    n = 0
    print("TOUCH THE SENSOR SEVERAL TIMES NOW", flush=True)
    while time.time() - t0 < float(sys.argv[1]):
        row = []
        for i, m in enumerate(MODES):
            img = frame(dev, tls, *m)
            d = [a - b for a, b in zip(img, first[i])]
            mad = sum(abs(x) for x in d) // len(d)
            row.append(f"m{i} mean {sum(img) // len(img):4d} |d| {mad:4d}")
            if mad > 150:
                c.save_pgm(d, c.OUT + f"/s{i}_{n}.pgm")
        print(f"{time.time() - t0:5.1f}s  " + "  ".join(row), flush=True)
        n += 1


if __name__ == "__main__":
    main()
