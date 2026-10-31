#!/usr/bin/env python3
"""Prototype: TLS-PSK session + one fingerprint image from Goodix 27c6:581a.
Sequence follows goodix-fp-dump driver_52xd.py; sensor config is the one the
Windows driver uploads (Wbdi.dll file offset 0x2124c0)."""
import os
import ssl
import struct
import sys
import time

from probe import Dev, pack, proto, unpack

ROOT = __file__.rsplit("/tools/", 1)[0]
WBDI = os.environ.get("WBDI", "Wbdi.dll")  # Goodix Windows driver 3.0.81.320
OUT = os.environ.get("OUT", ROOT + "/out")  # debug images
CONFIG = bytearray(open(WBDI, "rb").read()[0x2124C0:0x2124C0 + 256])
# Windows patches TCODE (tag 0x5c) from OTP at runtime; the template holds 0x0100.
# shortcut: fixed TCODE values from a calibrated 52xd, derive from OTP if FDT misfires
CONFIG[175:177] = b"\xea\x00"
CONFIG[235:237] = b"\xe8\x00"
CONFIG[-2:] = struct.pack("<H", (0x10000 - (0xA5A5 + sum(
    struct.unpack("<127H", CONFIG[:254])))) & 0xFFFF)
CONFIG = bytes(CONFIG)
PSK = bytes(32)
W, H = 80, 64
FDT = b"\x27\x01\x21\x01\x27\x01\x23\x01"
FDT_DOWN_BASE = b"\x8d\x8d\x86\x86\x97\x97\x8f\x8f\x9b\x9b\x92\x92\x96\x96\x8c\x8c"


class Tls:
    """TLS 1.2 server in memory; the sensor MCU is the client."""

    def __init__(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("PSK-AES128-CBC-SHA256:@SECLEVEL=0")
        ctx.set_psk_server_callback(lambda identity: PSK)
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.s = ctx.wrap_bio(self.inc, self.out, server_side=True)

    def feed(self, data: bytes) -> bytes:
        self.inc.write(data)
        try:
            self.s.do_handshake()
        except ssl.SSLWantReadError:
            pass
        return self.out.read()

    def decrypt(self, data: bytes, n: int) -> bytes:
        self.inc.write(data)
        buf = b""
        while len(buf) < n:
            buf += self.s.read(n - len(buf))
        try:
            extra = self.s.read(1 << 16)
            print("WARNING: extra plaintext bytes", len(extra))
        except ssl.SSLWantReadError:
            pass
        return buf


def read_pack(dev, flags):
    data = dev.read(5000)
    f, length = struct.unpack("<BH", data[:3])
    while len(data) < 4 + length:
        data += dev.read(5000)
    assert f == flags, f"flags {f:#x} != {flags:#x}"
    return data[4:4 + length]


def connect(dev, tls):
    hello = dev.cmd(0xD0, b"\0\0", reply=False) or read_pack(dev, 0xB0)
    out = tls.feed(hello)
    dev.write(pack(out, 0xB0))
    for _ in range(3):
        out = tls.feed(read_pack(dev, 0xB0))
    dev.write(pack(out, 0xB0))
    time.sleep(0.01)
    print("TLS:", tls.s.version(), tls.s.cipher()[0])


def get_image(dev, tls, payload) -> bytes:
    dev.cmd(0x20, payload, reply=False)
    raw = tls.decrypt(read_pack(dev, 0xB2)[9:], W * H * 3 // 2 + 4)[:-4]
    img = []
    for i in range(0, len(raw), 6):
        c = raw[i:i + 6]
        img += [((c[0] & 0xF) << 8) + c[1], (c[3] << 4) + (c[0] >> 4),
                ((c[5] & 0xF) << 8) + c[2], (c[4] << 4) + (c[5] >> 4)]
    return img


def save_pgm(img, path):
    lo, hi = min(img), max(img)
    px = bytes((v - lo) * 255 // max(hi - lo, 1) for v in img)
    # MCU streams column-major (H values per line), so the picture is H x W
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "wb").write(b"P5\n%d %d\n255\n" % (H, W) + px)
    print("saved", path, "range", lo, hi)


def main():
    dev = Dev()
    ok = dev.cmd(0xA2, b"\x05\x14")
    print("reset:", ok.hex())
    print("chip id:", dev.cmd(0x82, b"\x00\x00\x00\x04").hex())
    print("otp:", dev.cmd(0xA6, b"\0\0").hex())

    tls = Tls()
    connect(dev, tls)
    print("config upload:", dev.cmd(0x90, CONFIG).hex())
    dev.cmd(0xC4, b"\x01\x00", reply=False)       # set_drv_state
    print("pov:", dev.cmd(0xD2, b"\0\0").hex())    # mcu_get_pov_image
    dev.cmd(0x36, b"\x0d\x01" + FDT + bytes(17), reply=False)
    print("fdt:", dev.cmd(0x36, b"\x0d\x01" + FDT + bytes(16) + b"\x01").hex())

    dev.cmd(0x80, b"\x00\x2c\x02\x0a\x03", reply=False)
    base = get_image(dev, tls, b"\x01\x03" + FDT)
    dev.cmd(0x80, b"\x00\x2c\x02\x0a\x02", reply=False)
    save_pgm(base, OUT + "/base.pgm")

    print("Place finger on the sensor...")
    dev.cmd(0x32, b"\x9c\x01" + FDT + FDT_DOWN_BASE + b"\x00\x00\x05\x03\xa7\x00\xa1\x00\xa7\x00\xa3\x00\x00", reply=False)
    dev.write(pack(proto(0x32, b"\x9c\x01" + FDT + FDT_DOWN_BASE + b"\x01\x00\x05\x03\xa7\x00\xa1\x00\xa7\x00\xa3\x00\x00")))
    _, c, ack = unpack(dev.read())
    _, c, body = unpack(dev.read(int(sys.argv[1]) * 1000 if len(sys.argv) > 1 else 30000))
    print("finger down:", c == 0x32, body.hex()[:40])

    dev.cmd(0x36, b"\x0d\x01" + FDT + FDT_DOWN_BASE + b"\x00", reply=False)
    dev.cmd(0x36, b"\x0d\x01" + FDT + FDT_DOWN_BASE + b"\x01")
    imgs = {dac: shot(dev, tls, dac) for dac in DACS}
    print("Lift finger now")
    time.sleep(4)
    for dac, img in imgs.items():
        save_pgm(img, OUT + f"/f_{dac:x}.pgm")
        d = [b - v for v, b in zip(img, shot(dev, tls, dac))]
        print(f"dac {dac:#x}: mean {sum(img) // len(img)} base-diff range {min(d)}..{max(d)}")
        save_pgm(d, OUT + f"/d_{dac:x}.pgm")


DACS = (0xC7, 0xE7, 0x107)


def shot(dev, tls, dac):
    # payload = mode(2) + 4 x DAC(u16); reg 0x022c selects gain (Windows: HV DAC)
    dev.cmd(0x80, b"\x00\x2c\x02\x05\x03", reply=False)
    img = get_image(dev, tls, b"\x45\x03" + struct.pack("<4H", dac, dac - 6, dac, dac - 4))
    dev.cmd(0x80, b"\x00\x2c\x02\x05\x02", reply=False)
    return img


if __name__ == "__main__":
    main()
