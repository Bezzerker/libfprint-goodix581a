#!/usr/bin/env python3
"""Read-only probe for Goodix 27c6:581a. Sends only query commands: NOP,
firmware version, OTP and PSK-hash read. Never writes PSK or firmware."""
import struct
import sys

import usb.core
import usb.util

VID, PID = 0x27C6, 0x581A
EP_OUT, EP_IN = 0x01, 0x83

CMD_NOP, CMD_ACK = 0x00, 0xB0
CMD_READ_OTP, CMD_FW_VERSION = 0xA6, 0xA8
CMD_PSK_READ = 0xE4
CMD_READ_FW = 0xF2


def pack(payload: bytes, flags=0xA0) -> bytes:
    hdr = struct.pack("<BH", flags, len(payload))
    return hdr + bytes([sum(hdr) & 0xFF]) + payload


def proto(cmd: int, payload: bytes, checksum=True) -> bytes:
    d = struct.pack("<BH", cmd, len(payload) + 1) + payload
    return d + bytes([(0xAA - sum(d)) & 0xFF if checksum else 0x88])


def unpack(data: bytes):
    flags, length = struct.unpack("<BH", data[:3])
    assert sum(data[:3]) & 0xFF == data[3], "bad pack checksum"
    body = data[4:4 + length]
    cmd, plen = struct.unpack("<BH", body[:3])
    return flags, cmd, body[3:2 + plen]


class Dev:
    def __init__(self):
        self.d = usb.core.find(idVendor=VID, idProduct=PID)
        if self.d is None:
            sys.exit("device 27c6:581a not found")
        if self.d.is_kernel_driver_active(0):
            self.d.detach_kernel_driver(0)
        usb.util.claim_interface(self.d, 0)
        self.drain()

    def drain(self):
        try:
            while True:
                self.d.read(EP_IN, 0x10000, 100)
        except usb.core.USBTimeoutError:
            pass

    def write(self, data: bytes):
        data += b"\0" * (-len(data) % 64)
        for i in range(0, len(data), 64):
            self.d.write(EP_OUT, data[i:i + 64], 1000)

    def read(self, timeout=2000) -> bytes:
        return bytes(self.d.read(EP_IN, 0x10000, timeout))

    def cmd(self, cmd: int, payload: bytes, reply=True):
        self.write(pack(proto(cmd, payload)))
        _, c, ack = unpack(self.read())
        assert c == CMD_ACK and ack[0] == cmd, f"bad ack {c:#x} {ack.hex()}"
        if not reply:
            return None
        _, c, body = unpack(self.read())
        assert c == cmd, f"unexpected reply {c:#x}"
        return body


def main():
    dev = Dev()
    dev.write(pack(proto(CMD_NOP, b"\0\0\0\0", checksum=False)))
    try:
        dev.read(200)
    except usb.core.USBTimeoutError:
        pass

    fw = dev.cmd(CMD_FW_VERSION, b"\0\0").split(b"\0")[0].decode()
    print("firmware:", fw)

    otp = dev.cmd(CMD_READ_OTP, b"\0\0")
    print("otp:", otp.hex())

    # flags 0xbb020001 = PMK hash (GM168SEC family, see goodix-fp-dump 52xd/53xd)
    for flags in (0xBB020001, 0xBB020007):
        body = dev.cmd(CMD_PSK_READ, struct.pack("<IIII", 32, 0, flags, 0))
        if body[0] != 0:
            print(f"psk_read {flags:#x}: status {body[0]:#x}")
            continue
        n = struct.unpack("<I", body[5:9])[0]
        print(f"psk_read {flags:#x}: {body[9:9 + n].hex()}")

    if "--dump" in sys.argv:
        out = b""
        try:
            for off in range(0, 0x8000, 256):
                body = dev.cmd(CMD_READ_FW, struct.pack("<II", off, 256))
                out += body[:256]
        except (AssertionError, usb.core.USBError) as e:
            print(f"read_firmware stopped at {len(out):#x}: {e}")
        open(sys.argv[sys.argv.index("--dump") + 1], "wb").write(out)
        print(f"dumped {len(out)} bytes, head {out[:12].hex()}")

    usb.util.release_interface(dev.d, 0)


if __name__ == "__main__":
    main()
