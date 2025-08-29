#!/usr/bin/env python
#
# Copyright (c) 2020 Ethan Kosakovsky <ethankosakovsky@protonmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import hmac
import hashlib
import math
from mnemonic import Mnemonic as bip39
from .BIP85DRNG import new as DRNG
from pycoin.symbols.btc import network as BTC
from pycoin.encoding.bytes32 import from_bytes_32, to_bytes_32
from .bip93 import CHARSET, ms32_recover, fingerprint, convertbits, ms32_interpolate, ms32_encode, validate_set
import base58



class BIP85(object):
    def _decorate_path(self, path):
        return path.replace("m/", "").replace("'", "p")

    def _get_k_from_node(self, node):
        return to_bytes_32(node.secret_exponent())

    def _derive_k(self, path, xprv):
        path = self._decorate_path(path)
        node = xprv.subkey_for_path(path)
        return self._get_k_from_node(node)

    def _hmac_sha512(self, message_k):
        return hmac.new(key=b'bip-entropy-from-k', msg=message_k, digestmod=hashlib.sha512).digest()

    def bip39_mnemonic_to_entropy(self, path, mnemonic, passphrase=''):
        bip39_seed = bip39.to_seed(mnemonic, passphrase=passphrase)
        xprv = BTC.keys.bip32_seed(bip39_seed)
        return self._hmac_sha512(self._derive_k(path, xprv))

    def bip32_xprv_to_entropy(self, path, xprv_string):
        xprv = BTC.parse(xprv_string)
        if xprv is None:
            raise ValueError('ERROR: Invalid xprv')
        return self._hmac_sha512(self._derive_k(path, xprv))

    def bip32_xprv_to_hex(self, path, width, xprv_string):
        # export entropy as hex
        path = self._decorate_path(path)
        ent = self.bip32_xprv_to_entropy(path, xprv_string)
        return ent[0:width].hex()

    def bip32_xprv_to_xprv(self, path, xprv_string):
        path = self._decorate_path(path)
        ent = self.bip32_xprv_to_entropy(path, xprv_string)

        # From Peter Gray
        # Taking 64 bytes of the HMAC digest, the first 32 bytes are the chain code, and second 32 bytes are the private
        # key for BIP32 XPRV value. Child number, depth, and parent fingerprint are forced to zero.
        prefix = b'\x04\x88\xad\xe4'
        depth = b'\x00'
        parent_fingerprint = b'\x00\x00\x00\x00'
        child_num = b'\x00\x00\x00\x00'
        chain_code = ent[:32]
        private_key = b'\x00' + ent[32:]
        extended_key = prefix + depth + parent_fingerprint + child_num + chain_code + private_key
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        derived_xprv_string = base58.b58encode(extended_key + checksum).decode()
        node = BTC.parse(derived_xprv_string)

        return node.hwif(as_private=True)

    def entropy_from_wif(self, wif):
        node = BTC.keys.from_text(wif)
        return self._hmac_sha512(self._get_k_from_node(node))

    def entropy_to_wif(self, entropy):
        return BTC.keys.private(secret_exponent=from_bytes_32(entropy[:32])).wif()

    def entropy_to_bip39(self, entropy, words, language='english'):
        width = (words - 1) * 11 // 8 + 1
        assert 16 <= width <= 32
        m = bip39(language)
        return m.to_mnemonic(entropy[:width])
    
    def entropy_to_bip93(self, entropy, hrp='ms', threshold=2, n=3, byte_length=16, id=None):
        k = CHARSET.find(str(threshold))
        if threshold == 0 and n != 1:
            raise ValueError(f"Share count '{n}' is not an allowed value (for threshold=0, share_count must be 1).")
        payload_length = (byte_length * 8 + 4) // 5
        drng = DRNG(entropy)
        alphabetized_charset = 'sacdefghjk' # threshold above 9 is invalid
        initial_codex32_data = []
        for i in range(bool(threshold), min(threshold, n) + 1):
            data = [k] + id + [CHARSET.find(alphabetized_charset[i])]
            while len(data) < 6 + payload_length:
                data.append(int.from_bytes(drng.read(1), "big") >> 3)
            initial_codex32_data.append(data)
        codex32_secret = ms32_recover(initial_codex32_data) if len(
            initial_codex32_data) > 1 else initial_codex32_data[0]
        if 32 in id:
            bip32_fp = fingerprint(bytes(convertbits(codex32_secret[6:], 5, 8)))
            for data in initial_codex32_data:
                for i in range(1,5): # relabel shares with the BIP32 fingerprint
                    data[i] = data[i] if id[i - 1] < 32 else bip32_fp[i - 1]
        if threshold and n >= threshold:
            strings = []
            existing_share_indexes = [16]
            for i in range(n):
                fresh_share_index = 16
                while fresh_share_index in existing_share_indexes:
                    fresh_share_index = int.from_bytes(drng.read(1), "big") >> 3
                existing_share_indexes.append(fresh_share_index)
                if CHARSET[fresh_share_index] in alphabetized_charset[:len(initial_codex32_data)+1]:
                    share_data = initial_codex32_data[
                        alphabetized_charset.index(CHARSET[fresh_share_index]) - 1]
                else:
                    share_data = ms32_interpolate(initial_codex32_data, fresh_share_index)
                strings.append(ms32_encode(hrp, share_data))
        else:
            strings = [ms32_encode(hrp, data) for data in initial_codex32_data]
        assert validate_set(strings, len_must_match_k=False)

        return {
            "identifier": strings[0][len(hrp) + 2:len(hrp) + 6],
            "codex32": strings,
        }
    
    def do_rolls(self, entropy: bytes, sides: int, rolls: int) -> str:
        """sides > 1, 1 < rolls > 100"""
        max_width = len(str(sides - 1))
        history = []
        bits_per_roll = math.ceil(math.log(sides, 2))
        bytes_per_roll = math.ceil(bits_per_roll / 8)
        drng = DRNG(entropy)
        while len(history) < rolls:
            trial_int = int.from_bytes(drng.read(bytes_per_roll), "big")
            available_bits = 8 * bytes_per_roll
            excess_bits = available_bits - bits_per_roll
            trial_int >>= excess_bits
            if trial_int >= sides:
                continue
            else:
                history.append(f"{trial_int:0{max_width}d}")

        return ",".join(history)