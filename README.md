# goodix581a — Linux driver for the Goodix 27c6:581a fingerprint reader

[Русская версия](README.ru.md)

A [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) driver for the
Goodix USB fingerprint reader `27c6:581a`, found in the
**Xiaomi Mi Notebook Pro 15.6" 2021 (Ryzen Edition)**. Goodix only shipped a
Windows driver for this sensor. This driver was reconstructed from that Windows
driver and from the goodix-fp-dump research. It plugs into the standard
`libfprint` + `fprintd` stack, so enrolment, verification and PAM login work
like with any supported reader.

| | |
|---|---|
| Sensor | Goodix USB `27c6:581a`, firmware `GFUSB_GM168SEC_APP_10035` ("Milan HV" 52xd family) |
| Image | 64 × 80 px, ~500 dpi (about 3.2 × 4 mm) |
| Stack | libfprint 1.94.100 + `goodix581a`, fprintd 1.94 |
| Matching | on the host (the sensor has no match-on-chip), own SIFT implementation |

> **Status: experimental.** Not affiliated with Goodix or Xiaomi. On first use
> the driver may write a TLS pre-shared key into the sensor (see
> [Pairing key](#pairing-key-psk)). Use at your own risk.

## What works

- Sensor session: TLS 1.2 PSK, sensor configuration upload, image capture.
- Finger-down / finger-up detection with the sensor's own finger detector (FDT).
- Enrolment (20 touches), verification and identification through `fprintd`.
- PAM authentication (`pam_fprintd`), e.g. for `sudo`.

## Accuracy — read this before enabling PAM

The sensor sees only about 3 × 4 mm, a small part of the fingertip. If a touch
lands on an area that none of the 20 enrolment samples covers, there is nothing
to match against, and no threshold can fix that.

| Measurement | Result |
|---|---|
| Enrolled finger via fprintd, single touch | ~50–60 % accepted |
| Enrolled finger, 3 tries (`pam_fprintd` default) | ~90 % (estimate) |
| Other fingers via fprintd | 0 of 12 accepted |
| Other fingers, recorded sets (56 attempts) | max score 4, threshold 10 |

These numbers come from a small amount of test data from a single person, so
the real false-accept rate may be around 1–2 % per attempt. **Treat the
fingerprint as a convenience and keep your password as the primary factor.**
Every extra enrolled finger raises the false-accept chance roughly in
proportion, so one or two fingers are enough.

## Repository layout

```
driver/          the libfprint driver
  goodix581a.c     protocol, TLS, finger detection, capture, enrol/verify (FpDevice)
  sigmatch.c/.h    SIFT keypoints (port of OpenCV's SIFT) + geometric matching
  integrate.sh     adds the driver to a libfprint 1.94.x source tree
pkg/PKGBUILD     Arch Linux package libfprint-goodix581a (replaces libfprint)
tools/           Python/C research and test tools (see Development)
```

## Installation

### Arch Linux and derivatives

The package is libfprint 1.94.100 built from source with this driver added. It
`provides` and `conflicts` with `libfprint`.

`-s` installs the build dependencies and `-r` removes them again afterwards:

```bash
cd pkg
makepkg -sri
```

Then install fprintd:

```bash
sudo pacman -S fprintd
```

If fprintd was already running, restart it so it loads the new library:

```bash
sudo systemctl restart fprintd
```

### Other distributions

Add the driver to a libfprint 1.94.x source tree and build it as your
distribution builds libfprint. Start by fetching libfprint and integrating the
driver:

```bash
git clone -b v1.94.100 https://gitlab.freedesktop.org/libfprint/libfprint.git
sh driver/integrate.sh libfprint
```

Then configure and build. The driver needs OpenSSL, through the `openssl`
helper that `integrate.sh` registers:

```bash
meson setup build libfprint -Ddrivers=all -Ddoc=false -Dinstalled-tests=false
meson compile -C build
```

If you build with `-Dintrospection=false`, libfprint 1.94.100's
`tests/meson.build` needs the one-line fix from `pkg/PKGBUILD`.

Prefer packaging the result over installing it on top of your distribution's
libfprint.

### Pairing key (PSK)

The sensor encrypts images with a TLS session keyed by a pre-shared key that is
stored in the sensor. This driver uses an all-zero key. If the sensor holds a
different key, for example one written by the Windows driver, the driver
replaces it while opening the device. It writes the key in application mode,
without erasing the firmware. If you later install the Goodix Windows driver,
it writes its own key, and this driver replaces it again when you come back to
Linux.

## Usage

Enroll a finger with 20 touches. Touch naturally, the way you will when
unlocking, and shift or rotate the finger slightly between touches. Covering
deliberate zones of the finger (centre, tip, edges) works worse, because the
samples end up too sparse.

```bash
fprintd-enroll -f right-index-finger
```

Verify:

```bash
fprintd-verify
```

List enrolled fingers:

```bash
fprintd-list $USER
```

Delete all prints (`-f <finger>` deletes one):

```bash
fprintd-delete $USER
```

### sudo with a fingerprint

Add `pam_fprintd` to `/etc/pam.d/sudo`. The command keeps a backup of the
original file:

```bash
sudo sed -i.bak '2i auth      sufficient    pam_fprintd.so max-tries=3 timeout=15' /etc/pam.d/sudo
```

With `sufficient`, sudo falls back to the password if the fingerprint fails or
nobody touches the sensor within 15 s. Pressing Ctrl+C while it waits cancels
sudo entirely. To revert:

```bash
sudo mv /etc/pam.d/sudo.bak /etc/pam.d/sudo
```

## How it works

**Protocol.** The sensor belongs to Goodix's "52xd" family (MSP430 MCU), as
described in [goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump).
Traffic is 64-byte packets on bulk endpoints `0x01`/`0x83`. A packet carries a
message `[cmd, len, payload, checksum]`, and the sensor acknowledges every
command with `0xb0`. Opening the device:

1. Check the firmware version and the PSK hash; write the all-zero PSK if needed.
2. Reset the sensor (`0xa2`) and do the TLS handshake. The sensor is the TLS
   client and the host the server (PSK-AES128-CBC-SHA256). TLS records travel
   in `0xb0` packets.
3. Upload the 256-byte sensor configuration taken from the Windows driver
   (`Wbdi.dll` 3.0.81.320). The driver fills in the TCODE field of that
   template and recomputes the checksum; otherwise the sensor rejects it.

**Image.** Command `0x20`, mode `01 03`, DAC `0x127`. The reply is a TLS
encrypted `0xb2` packet: 7680 bytes of data, 12-bit pixels packed 4 per 6
bytes. The driver subtracts the empty-sensor background and stretches the
contrast to 8 bits between the 1st and 99th percentiles.

**Finger detection.** Image brightness cannot tell a finger from the latent
print it leaves behind. Instead the driver polls the sensor's finger detector
(FDT, `0x36`): 8 levels that vary by ≤ 2 when the sensor is empty and by
90–120 with a finger. A touch needs a change of 40, a lift a change of 15, and
each must hold for 2 consecutive readings. The empty-sensor background and the
FDT baseline survive close/open: fprintd reopens the device for every attempt,
often while the finger is still on the sensor. They are discarded after 60 s
of inactivity, because temperature drifts while the sensor is idle.

**Matching.** NBIS minutiae (bozorth3) are useless on such a small image: it
yields only 0–12 minutiae. The driver therefore uses its own SIFT, a faithful
port of OpenCV's:

- the image is upscaled 2×, and up to 150 keypoints are extracted;
- keypoints are paired using Lowe's ratio test (0.75);
- an exhaustive two-point search looks for a rigid transform that agrees with
  the pairs (2 px tolerance, ±15 % scale, 20° orientation consistency).

The score is the sum over the 20 enrolled samples of
`max(0, inliers − 3)`, and a print is accepted at 10. The template is stored
in the print's `fpi-data` (`(uaay)`, one blob per sample) and matched on the
host.

## Development

The Python tools need `pyusb`, and the evaluation scripts also need `numpy`:

```bash
python -m venv .venv && .venv/bin/pip install pyusb numpy
```

The tools talk to the sensor directly. Stop fprintd while using them, and run
them as root or give your user access to the USB device. Tools that read the
sensor configuration or firmware expect the Goodix Windows driver's `Wbdi.dll`
3.0.81.320. It is not included; point the `WBDI` environment variable at it.

- `tools/probe.py` is read-only: it prints the firmware version and the PSK hash.
- `tools/provision.py`:
  - `build-fw` extracts the 10035 firmware from `Wbdi.dll`;
  - `psk-app` writes the all-zero PSK.
- `tools/capture.py`, `tools/stream.py`, `tools/fdt_stream.py` are the capture
  prototype and diagnostics for the finger detector. Debug images go to `out/`
  (`OUT` overrides it).
- `tools/collect.py N DIR` records a labelled set of `.raw` frames (int16 80×64,
  frame minus background).
- `tools/sigeval.c` runs the matcher over `.raw` files and prints an
  "inliers/candidates" matrix.
- `tools/eval_ds2.py` compares score-fusion rules on such a matrix: 20 enrol,
  15 genuine, then impostor frames.

To build the matcher harness:

```bash
gcc -O2 -o sigeval tools/sigeval.c driver/sigmatch.c -lm
```

To run it over your own frames:

```bash
./sigeval 150 enroll/*.raw genuine/*.raw impostor/*.raw
```

Scores from `sigeval` match the live driver exactly. If you build the driver
with `-DGOODIX581A_DUMP` and set `GOODIX581A_DUMP=<dir>`, it saves every
captured frame as `.raw`. To see each match score in the logs, set
`G_MESSAGES_DEBUG=all`.

No fingerprint datasets are included in this repository, because they are
biometric data.

## Removal

On Arch, if libfprint was not installed before:

```bash
sudo pacman -Rns fprintd libfprint-goodix581a
```

If another program needs libfprint, install the stock package instead, which
replaces this one:

```bash
sudo pacman -S libfprint
```

The all-zero PSK stays in the sensor. Only this driver and the Goodix Windows
driver use it, and the Windows driver replaces it on installation.

## Credits and licenses

- The driver (`driver/`, `pkg/`, `tools/`) is licensed under
  **LGPL-2.1-or-later**, the same as libfprint (see [LICENSE](LICENSE)).
- [goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump)
  documented the 52xd protocol and provided the PSK white-box blob (MIT).
- The SIFT implementation in `driver/sigmatch.c` is a port of
  [OpenCV](https://github.com/opencv/opencv)'s (Apache-2.0).

See [NOTICE](NOTICE) for the third-party notices. The sensor configuration
embedded in the driver comes from the Goodix Windows driver and is used for
interoperability. The Windows driver and the sensor firmware themselves are
not distributed here.
