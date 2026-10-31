#!/usr/bin/env python3
"""Install a known (all-zero) TLS PSK on Goodix 27c6:581a, the same way the
Windows driver does in ProcessPsk (Wbdi.dll): IAP mode -> write PSK -> flash APP.

  provision.py build-fw          extract GFUSB_GM168SEC_APP_10035 from Wbdi.dll
                                 ($WBDI, default ./Wbdi.dll) into the current directory
  provision.py psk-app           try PSK write in APP mode (no erase)
  provision.py full FW.bin       erase APP, write PSK, flash FW.bin
"""
import hashlib
import os
import hmac
import struct
import sys
import time

import usb.core

from probe import CMD_FW_VERSION, CMD_PSK_READ, Dev, pack, proto, unpack

WBDI = os.environ.get("WBDI", "Wbdi.dll")  # Goodix Windows driver 3.0.81.320
# .data table entry at file 0x210278 points here; blob = len(1) + name(24) + body
FW_BLOB_OFF, FW_BLOB_LEN = 0x154C80, 0x6449

PSK = bytes(32)
# zero PSK encrypted with the MCU white-box key (goodix-fp-dump driver_52xd.py)
PSK_WHITE_BOX = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")
PMK_HASH_ZERO = bytes.fromhex(
    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")

CMD_RESET, CMD_ERASE_APP = 0xA2, 0xA4
CMD_PSK_WRITE, CMD_WRITE_FW, CMD_CHECK_FW = 0xE0, 0xF0, 0xF4


def crc32_mpeg2(data: bytes) -> int:
    c = 0xFFFFFFFF
    for b in data:
        c ^= b << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) if c & 0x80000000 else c << 1
            c &= 0xFFFFFFFF
    return c


def build_fw() -> bytes:
    blob = open(WBDI, "rb").read()[FW_BLOB_OFF:FW_BLOB_OFF + FW_BLOB_LEN]
    assert blob[1:25] == b"GFUSB_GM168SEC_APP_10035", blob[:25]
    body = blob[25:]
    tail = struct.pack("<II", len(body), crc32_mpeg2(body))
    return struct.pack("<I", crc32_mpeg2(tail)) + tail + body


def fw_hmac(fw: bytes) -> bytes:
    pmk = hashlib.sha256((struct.pack(">H", len(PSK)) + PSK) * 2).digest()
    key = hmac.new(pmk, bytes(range(1, 65)), hashlib.sha256).digest()
    return hmac.new(key, fw, hashlib.sha256).digest()


def version(dev) -> str:
    return dev.cmd(CMD_FW_VERSION, b"\0\0").split(b"\0")[0].decode()


def pmk_hash(dev) -> bytes | None:
    body = dev.cmd(CMD_PSK_READ, struct.pack("<IIII", 32, 0, 0xBB020001, 0))
    return body[9:9 + struct.unpack("<I", body[5:9])[0]] if body[0] == 0 else None


def write_psk(dev) -> int:
    data = bytes.fromhex("56a5bb956b7c8d9e0000") + struct.pack(
        "<II", 0xBB010003, len(PSK_WHITE_BOX)) + PSK_WHITE_BOX
    data = struct.pack("<III", len(data), 114, 0) + data[:114]
    return dev.cmd(CMD_PSK_WRITE, data)[0]


def reopen(timeout=10) -> Dev:
    end = time.time() + timeout
    while time.time() < end:
        try:
            return Dev()
        except (SystemExit, usb.core.USBError):
            time.sleep(0.3)
    sys.exit("device did not come back")


def main():
    mode = sys.argv[1]
    if mode == "build-fw":
        fw = build_fw()
        open("GFUSB_GM168SEC_APP_10035.bin", "wb").write(fw)
        print(f"fw {len(fw)} bytes, header {fw[:12].hex()}")
        return

    dev = Dev()
    print("firmware:", version(dev), "pmk hash:", pmk_hash(dev).hex())

    if mode == "psk-app":
        print("psk write status:", hex(write_psk(dev)))
        print("pmk hash now:", pmk_hash(dev).hex(), "zero-psk:",
              pmk_hash(dev) == PMK_HASH_ZERO)
        return

    assert mode == "full"
    fw = open(sys.argv[2], "rb").read()
    if "IAP" not in version(dev):
        # mcu_erase_app(sleep=50, reply=True): MCU drops to the IAP bootloader
        print("erase app status:", dev.cmd(CMD_ERASE_APP, b"\x00\x32")[0])
        time.sleep(1)
        dev = reopen()
    print("now in:", version(dev))
    assert "IAP" in version(dev)

    if pmk_hash(dev) != PMK_HASH_ZERO:
        print("psk write status:", hex(write_psk(dev)))
    assert pmk_hash(dev) == PMK_HASH_ZERO, "PSK did not take"

    for off in range(0, len(fw), 256):
        ok = dev.cmd(CMD_WRITE_FW, struct.pack("<III", off, len(fw[off:off + 256]), 2)
                     + fw[off:off + 256])[0]
        assert ok == 1, f"write failed at {off:#x}"
    ok = dev.cmd(CMD_CHECK_FW, fw_hmac(fw))[0]
    print("check firmware:", ok)
    assert ok == 1, "firmware check failed (still in IAP, safe to retry)"

    # soft-reset MCU into the new APP (no reply expected)
    dev.cmd(CMD_RESET, b"\x02\x32", reply=False)
    time.sleep(1)
    dev = reopen()
    print("final firmware:", version(dev), "pmk hash ok:",
          pmk_hash(dev) == PMK_HASH_ZERO)


if __name__ == "__main__":
    main()
