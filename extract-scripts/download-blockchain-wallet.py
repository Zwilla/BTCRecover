#!/usr/bin/env python

# download-blockchain-wallet.py -- Blockchain.info wallet file downloader
# Copyright (C) 2016, 2017 Christopher Gurnee
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
import atexit
import uuid
import urllib.request
import urllib.error
import urllib.parse
import json
import time
import ssl
from json import JSONDecodeError

# Context to ignore SSL Errors
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# The base URL
BASE_URL = "https://login.blockchain.com/"
# The api_code (as of Feb 2 2017)
API_CODE = "1770d5d9-bcea-4d28-ad21-6cbd5be018a8"

prog = os.path.basename(sys.argv[0])

if len(sys.argv) < 2:
    atexit.register(lambda: input("\nPress Enter to exit ..."))
    filename = "wallet.aes.json"
elif len(sys.argv) == 2 and not sys.argv[1].startswith("-"):
    filename = sys.argv[1]
else:
    print("usage:", prog, "[NEW_BLOCKCHAIN_WALLET_FILE]", file=sys.stderr)
    sys.exit(2)

# Refuse to overwrite an existing file
assert not os.path.exists(filename), filename + " already exists, won't overwrite"

print("Please enter your wallet's ID (e.g. 9bb4c672-563e-4806-9012-a3e8f86a0eca)")
wallet_id = str(uuid.UUID(input("> ").strip()))

# Performs a web request, adding the api_code and (if available) auth_token
auth_token = None


def do_request(query, body=None):
    if body is None:
        assert "?" in query
        query += "&api_code=" + API_CODE
    req = urllib.request.Request(BASE_URL + query)
    if body is not None:
        req.data = ((body + "&" if body else "") + "api_code=" + API_CODE).encode()
    if auth_token:
        req.add_header("authorization", "Bearer " + auth_token)
    try:
        return urllib.request.urlopen(req, context=ctx)  # fixed because otherwise SSL errors abound
    except TypeError:
        return urllib.request.urlopen(req, context=ctx)


#
# Performs a do_request(), decoding the result as json
def do_request_json(query, body=None):
    return json.load(do_request(query, body))


# Get an auth_token
try:
    auth_token = do_request_json("sessions", "")["token"]  # a POST request
except urllib.error.HTTPError:
    # This tool worked with the old blockchain.info domain for some time, then needed to swtich the base url to
    # login.blockchain.com
    # A recent (28th Jan 2021) change broke this, though the tool still works as normal with the old domain.
    # (Interestingly, logins via the official website were failing over to blockchain.info as well...)
    print("Download from login.blockchain.com failed, attempting via blockchain.info")
    BASE_URL = "https://blockchain.info/"
    auth_token = do_request_json("sessions", "")["token"]  # a POST request

# Try to download the wallet
try:
    wallet_data = do_request_json(
        "wallet/{}?format=json".format(wallet_id)
    ).get("payload")

# If IP address / email verification is required
except urllib.error.HTTPError as e:
    error_msg = e.read()
    try:
        error_msg = str(json.loads(error_msg)["initial_error"])
    except JSONDecodeError:
        pass
    print(error_msg)
    if str("unknown wallet identifier") in error_msg:
        sys.exit(1)

    # Wait for the user to complete the requested authorization
    time.sleep(5)
    print("Waiting for authorization (press Ctrl-C to give up)...")
    while True:
        poll_data = do_request_json("wallet/poll-for-session-guid?format=json")
        if "guid" in poll_data:
            break
        time.sleep(5)
    print()

    # Try again to download the wallet (this shouldn't fail)
    wallet_data = do_request_json(
        "wallet/{}?format=json".format(wallet_id)
    ).get("payload")

# If there was no payload data, then 2FA is enabled
while not wallet_data:

    print("This wallet has two-factor authentication enabled, please enter your 2FA code")
    two_factor = input("> ").strip()

    try:
        # Send the 2FA to the server and download the wallet
        wallet_data = do_request("wallet",
                                 "method=get-wallet&guid={}&payload={}&length={}"
                                 .format(wallet_id, two_factor, len(two_factor))
                                 ).read()

    except urllib.error.HTTPError as e:
        print(e.read() + "\n", file=sys.stderr)

# Save the wallet
with open(filename, "wb") as wallet_file:
    if isinstance(wallet_data, str):
        wallet_file.write(wallet_data.encode())
    else:
        wallet_file.write(wallet_data)

print("Wallet file saved as " + filename)
