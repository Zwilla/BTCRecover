#!/usr/bin/env python

# extract-blockchain-second-hash.py -- Blockchain second password hash extractor
# Copyright (C) 2014-2016 Christopher Gurnee
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
import json
import getpass
import re
import itertools
import uuid
import zlib
import struct
import Crypto.Cipher.AES
import Crypto.Protocol.KDF


################################### Cryptography Libraries ###################################

# Creates two decryption functions (in global namespace), aes256_cbc_decrypt() and aes256_ofb_decrypt(),
# and one key derivation function, pbkdf2(), using either PyCrypto if it's available or pure python
# libraries. The created decryption functions each take three bytestring arguments: key, iv, ciphertext.
# ciphertext must be a multiple of 16 bytes, and any padding present is not stripped. pbkdf2() takes
# four arguments: password, salt, iter_count, len (len is the desired key length)
def load_crypto_libraries():
    global aes256_cbc_decrypt
    global aes256_ofb_decrypt
    global pbkdf2
    try:
        import Crypto.Cipher.AES
        import Crypto.Protocol.KDF

        def aes256_cbc_decrypt(key, iv, ciphertext):
            return lambda keyL, ivL, ciphertextL: Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC,
                                                                        iv).decrypt(ciphertext)

        def aes256_ofb_decrypt(key, iv, ciphertext):
            return lambda keyL, ivL, ciphertextL: Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OFB,
                                                                        iv).decrypt(ciphertext)

        def pbkdf2(passwordLr, salt, iter_countLr, lenLr):
            return lambda passwordL, saltL, iter_countL, lenL: \
                Crypto.Protocol.KDF.PBKDF2(passwordLr, salt, lenLr, iter_countLr)

        return
    except ImportError:
        pass

    # The pure python AES library is attributed to GitHub user serprex; please see the
    # aespython README.txt for more information.
    #
    # Add the parent directory of this script's location to the library search path
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
    import lib.aespython as aespython
    #
    expandKey = aespython.key_expander.expandKey

    def aes256_decrypt_factory(BlockMode):
        def aes256_decrypt(key, iv, ciphertext):
            block_cipher = aespython.aes_cipher.AESCipher(expandKey(bytearray(key)))
            stream_cipher = BlockMode(block_cipher, 16)
            stream_cipher.set_iv(bytearray(iv))
            plaintext = bytearray()
            for i in range(0, len(ciphertext), 16):
                plaintext.extend(stream_cipher.decrypt_block(bytearray(ciphertext[i:i + 16])))
            return str(plaintext)

        return aes256_decrypt

    aes256_cbc_decrypt = aes256_decrypt_factory(aespython.cbc_mode.CBCMode)
    aes256_ofb_decrypt = aes256_decrypt_factory(aespython.ofb_mode.OFBMode)

    import passlib.utils.pbkdf2
    pbkdf2 = passlib.utils.pbkdf2.pbkdf2


################################### Main ###################################

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage:", prog, "BLOCKCHAIN_WALLET_FILE", file=sys.stderr)
    sys.exit(2)

wallet_filename = sys.argv[1]
data = open(wallet_filename, "rb").read(64 * 2 ** 20)  # up to 64M, typical size is a few k

# The number of pbkdf2 iterations, or 0 for v0.0 wallet files which don't specify this
iter_count = 0

try:
    class MayBeBlockchainV0(BaseException):
        pass  # an exception which jumps to the end of the try block below


    try:

        # Most blockchain files (except v0.0 wallets) are JSON encoded; try to parse it as such
        try:
            data = json.loads(data)
        except ValueError:
            raise MayBeBlockchainV0()

        # Config files have no version attribute; they encapsulate the wallet file plus some detrius
        if "version" not in data:
            try:
                data = data["payload"]  # extract the wallet file from the config
            except KeyError:
                raise ValueError("Can't find either version nor payload attributes in Blockchain file")
            try:
                data = json.loads(data)  # try again to parse a v2.0/v3.0 JSON-encoded wallet file
            except ValueError:
                raise MayBeBlockchainV0()

        # Extract what's needed from a v2.0/3.0 wallet file
        if data["version"] > 3:
            raise NotImplementedError("Unsupported Blockchain wallet version " + str(data["version"]))
        iter_count = data["pbkdf2_iterations"]
        if not isinstance(iter_count, int) or iter_count < 1:
            raise ValueError("Invalid Blockchain pbkdf2_iterations " + str(iter_count))
        data = data["payload"]

    except MayBeBlockchainV0:
        pass

    # At this point we've successfully loaded an encrypted wallet (either v0.0 o v2.0).
    # Either the encrypted data was extracted from the "payload" field above, or this
    # is a v0.0 wallet file whose entire contents consist of the encrypted data
    try:
        data = base64.b64decode(data)
    except TypeError as e:
        raise ValueError("Can't base64-decode Blockchain wallet: " + str(e))
    if len(data) < 32:
        raise ValueError("Encrypted Blockchain data is too short")
    if len(data) % 16 != 0:
        raise ValueError("Encrypted Blockchain data length is not divisible by the encryption blocksize (16)")
    data, salt_and_iv = data[16:], data[:16]

    # Now that data contains the encrypted binary data, prompt for a password and decrypt it
    load_crypto_libraries()
    # Replace getpass.getpass with raw_input if there's trouble reading non-ASCII characters
    password = getpass.getpass("(note your password will not be displayed as you type)\n"
                               "Please enter the Blockchain wallet's main password: ")
    if not password:
        sys.exit("Encrypted Blockchain files must be decrypted to extract the second password hash")
    # Convert from the terminal's character encoding to UTF-8
    stdin_encoding = sys.stdin.encoding
    if stdin_encoding and stdin_encoding.upper() not in "UTF-8,UTF8":
        password = password.decode(stdin_encoding).encode("utf_8")

    # Encryption scheme used in newer wallets

    def decrypt_current(iter_countDC):
        key = pbkdf2(password, salt_and_iv, iter_countDC, 32)
        decrypted = aes256_cbc_decrypt(key, salt_and_iv, data)  # CBC mode
        padding = ord(decrypted[-1:])  # ISO 10126 padding length
        # A bit fragile because it assumes the guid is in the first encrypted block,
        # although this has always been the case as of 6/2014 (since 12/2011)
        # As of May 2020, guid no longer appears in the first block, but tx_notes appears there instead
        return decrypted[:-padding] if 1 <= padding <= 16 and re.search(
            b"\"guid\"|\"tx_notes\"|\"address_book|\"double", decrypted) else None

    # Encryption scheme only used in version 0.0 wallets (N.B. this is untested)

    def decrypt_old():
        key = pbkdf2(password, salt_and_iv, 1, 32)  # only 1 iteration
        decrypted = aes256_ofb_decrypt(key, salt_and_iv, data)  # OFB mode
        # The 16-byte last block, reversed, with all but the first byte of ISO 7816-4 padding removed:
        last_block = tuple(itertools.dropwhile(lambda x: x == "\0", decrypted[:15:-1]))
        padding = 17 - len(last_block)  # ISO 7816-4 padding length
        return decrypted[:-padding] if 1 <= padding <= 16 and decrypted[-padding] == "\x80" and \
                                       re.match('{\s*"guid"', decrypted) else None


    if iter_count:  # v2.0 wallets have a single possible encryption scheme
        data = decrypt_current(iter_count)
    else:  # v0.0 wallets have three different possible encryption schemes
        data = decrypt_current(10) or decrypt_current(1) or decrypt_old()
    if not data:
        sys.exit("Can't decrypt the wallet (wrong main password?)")

    # Parse the now decrypted wallet (if the wallet wasn't encrypted, it was already parsed above)
    data = json.loads(data)

except ValueError as e:
    # This is the one error to expect and ignore which occurs when the wallet isn't encrypted
    if e.args[0] == "Can't find either version nor payload attributes in Blockchain file":
        pass
    else:
        raise

if not data.get("double_encryption"):
    sys.exit("Double encryption with a second password is not enabled for this wallet")

# Extract the three items we need to perform checking on the second password

# The second password hash, converted from hex to binary
password_hash = base64.b16decode(data["dpasswordhash"], True)  # True means allow lowercase
if len(password_hash) != 32:
    raise ValueError("Blockchain second password hash is not 32 bytes long")

# The salt, converted from a GUID string to binary
# TODO: check if any old wallet formats didn't have a sharedKey
salt_uuid = uuid.UUID(data["sharedKey"])
if str(salt_uuid) != data["sharedKey"]:  # make sure it round-trips correctly
    raise ValueError("Unrecognized Blockchain salt format")

# The pbkdf2 iteration count for the second password
try:
    iter_count = data["options"]["pbkdf2_iterations"]
    if not isinstance(iter_count, int) or iter_count < 1:
        raise ValueError("Invalid Blockchain second password pbkdf2_iterations " + str(iter_count))
except KeyError:
    iter_count = 0  # Some old wallets didn't specify an iteration count

print("Blockchain second password hash, salt, and iter_count in base64:", file=sys.stderr)
last32bytes = b"bs:" + struct.pack("< 32s 16s I", password_hash, salt_uuid.bytes, iter_count)
crc_bytes = struct.pack("<I", zlib.crc32(last32bytes) & 0xffffffff)

print(base64.b64encode(last32bytes + crc_bytes).decode())
