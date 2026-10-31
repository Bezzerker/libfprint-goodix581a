#!/bin/sh
# Add the goodix581a driver to a libfprint 1.94.x source tree: integrate.sh <libfprint-src>
set -eu
src=$1
here=$(dirname "$(readlink -f "$0")")

mkdir -p "$src/libfprint/drivers/goodix581a"
cp "$here/goodix581a.c" "$here/sigmatch.c" "$here/sigmatch.h" "$src/libfprint/drivers/goodix581a/"
grep -q goodix581a "$src/meson.build" || sed -i \
    "s|^    'goodixmoc': {},|&\n    'goodix581a': { 'helper': ['openssl'] },|" "$src/meson.build"
grep -q goodix581a "$src/libfprint/meson.build" || sed -i \
    "s|^    'uru4000' : files('drivers/uru4000.c'),|&\n    'goodix581a' : files('drivers/goodix581a/goodix581a.c', 'drivers/goodix581a/sigmatch.c'),|" "$src/libfprint/meson.build"
grep -q goodix581a "$src/meson.build" "$src/libfprint/meson.build" >/dev/null
