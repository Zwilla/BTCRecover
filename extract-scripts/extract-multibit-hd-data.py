#!/usr/bin/env python

# extract-electrum-partmpk.py -- MultiBit HD first block extractor
# Copyright (C) 2014, 2015 Christopher Gurnee
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see https://www.gnu.org/licenses/

import sys
import os.path
import base64
import zlib
import struct

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "MULTIBIT_HD_WALLET_FILE (typically named mbhd.wallet.aes)", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]

with open(wallet_filename, "rb") as wallet_file:
    encrypted_data = wallet_file.read(32)

if len(encrypted_data) < 32:
    raise ValueError("MultiBit HD wallet files must be at least 32 bytes long")

print("MultiBit HD first 32 bytes of encrypted wallet and crc in base64:", file=sys.stderr)

assert len(encrypted_data) == 32
l32bytes = b"m5:" + encrypted_data
crc_bytes = struct.pack("<I", zlib.crc32(l32bytes) & 0xffffffff)
print(base64.b64encode(l32bytes + crc_bytes).decode())
