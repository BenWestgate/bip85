#!/bin/python3
# Author: Leon Olsson Curr and Pearlwort Sneed <pearlwort@wpsoftware.net>
# License: BSD-3-Clause
"""Complete BIP-93 Codex32 implementation"""

from pycoin.key.BIP32Node import BIP32Node
from pycoin.ecdsa.secp256k1 import secp256k1_generator
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
MS32_CONST = 0x10CE0795C2FD1E62A
MS32_LONG_CONST = 0x43381E570BF4798AB26
bech32_inv = [
    0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31,
    22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15,
]


def ms32_polymod(values):
    GEN = [
        0x19DC500CE73FDE210,
        0x1BFAE00DEF77FE529,
        0x1FBD920FFFE7BEE52,
        0x1739640BDEEE3FDAD,
        0x07729A039CFC75F5A,
    ]
    residue = 0x23181B3
    for v in values:
        b = residue >> 60
        residue = (residue & 0x0FFFFFFFFFFFFFFF) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue


def ms32_verify_checksum(data):
    if len(data) >= 96:  # See Long codex32 Strings
        return ms32_verify_long_checksum(data)
    if len(data) <= 93:
        return ms32_polymod(data) == MS32_CONST
    return False


def ms32_create_checksum(data):
    if len(data) > 80:  # See Long codex32 Strings
        return ms32_create_long_checksum(data)
    values = data
    polymod = ms32_polymod(values + [0] * 13) ^ MS32_CONST
    return [(polymod >> 5 * (12 - i)) & 31 for i in range(13)]


def ms32_long_polymod(values):
    GEN = [
        0x3D59D273535EA62D897,
        0x7A9BECB6361C6C51507,
        0x543F9B7E6C38D8A2A0E,
        0x0C577EAECCF1990D13C,
        0x1887F74F8DC71B10651,
    ]
    residue = 0x23181B3
    for v in values:
        b = residue >> 70
        residue = (residue & 0x3FFFFFFFFFFFFFFFFF) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue


def ms32_verify_long_checksum(data):
    return ms32_long_polymod(data) == MS32_LONG_CONST


def ms32_create_long_checksum(data):
    values = data
    polymod = ms32_long_polymod(values + [0] * 15) ^ MS32_LONG_CONST
    return [(polymod >> 5 * (14 - i)) & 31 for i in range(15)]


def bech32_mul(a, b):
    res = 0
    for i in range(5):
        res ^= a if ((b >> i) & 1) else 0
        a *= 2
        a ^= 41 if (32 <= a) else 0
    return res


# noinspection PyPep8
def bech32_lagrange(l, x):
    n = 1
    c = []
    for i in l:
        n = bech32_mul(n, i ^ x)
        m = 1
        for j in l:
            m = bech32_mul(m, (x if i == j else i) ^ j)
        c.append(m)
    return [bech32_mul(n, bech32_inv[i]) for i in c]


def ms32_interpolate(l, x):
    w = bech32_lagrange([s[5] for s in l], x)
    res = []
    for i in range(len(l[0])):
        n = 0
        for j in range(len(l)):
            n ^= bech32_mul(w[j], l[j][i])
        res.append(n)
    return res


def ms32_recover(l):
    return ms32_interpolate(l, 16)


# Copyright (c) 2025 Ben Westgate
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


def ms32_encode(hrp, data):
    """Compute an MS32 string given HRP and data."""
    combined = data + ms32_create_checksum(data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def ms32_decode(bech):
    """Validate a ms32 string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return None, None, None, None, None
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 46 > len(bech) or len(bech) > 127:
        return None, None, None, None, None
    if not all(x in CHARSET for x in bech[pos + 1:]):
        return None, None, None, None, None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    k = bech[pos + 1]
    if not k.isdigit():
        return None, None, None, None, None
    ident = bech[pos + 2:pos + 6]
    share_index = bech[pos + 6]
    if k == "0" and share_index != "s":
        return None, None, None, None, None
    checksum_length = 13 if len(data) < 95 else 15
    if not ms32_verify_checksum(data):
        return None, None, None, None, None
    return hrp, k, ident, share_index, data[:-checksum_length]


def xor_pad(data, n):
    """Compute an n-bit XOR padding over converted data characters"""
    mask = (1 << n) -1
    acc = 0
    for value in data:
        acc ^= (value & 31)
    return acc & mask


def convertbits(data, frombits, tobits, pad=True, pad_val='xor', verify=False):
    """General power-of-2 base conversion with CRC padding."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        if pad_val == 'xor':
            pad_val = xor_pad(ret, (tobits - bits))
        ret.append(((acc << (tobits - bits)) + pad_val) & maxv)
    elif bits >= frombits:
        return None
    elif verify:
        if xor_pad(data, bits):
            return None
    return ret


def decode_secret(hrp, codex_str):
    """Decode a codex32 secret to bytes."""
    hrpgot, _, _, _, data = ms32_decode(codex_str)
    if hrpgot != hrp:
        return None
    decoded = convertbits(data[6:], 5, 8, False)
    if decoded is None or len(decoded) < 16 or len(decoded) > 64:
        return None
    return bytes(decoded)


def validate_set(string_list, len_must_match_k=True):
    """Validate set has unique indices & uniform: k, ident, length."""
    decoded = [ms32_decode(s) for s in string_list]
    headers = {tuple(d[:3]) for d in decoded}
    indices = {d[3] for d in decoded}
    lengths = {len(s) for s in string_list}
    k_val = int(next(iter(headers))[1]) if headers else 0

    if len(headers) > 1 or len(lengths) > 1:
        return None
    if len(indices) < len(string_list):
        return None
    if len_must_match_k and k_val != len(string_list):
        return None

    return [data[4] for data in decoded]


def recover_master_seed(share_list):
    """Derive master seed from a valid set of codex32 shares."""
    ms32_share_list = validate_set(share_list)
    if not ms32_share_list:
        return None
    return bytes(convertbits(ms32_recover(ms32_share_list)[6:], 5, 8, False))


def derive_share(string_list, fresh_share_index):
    """Derive an additional share from a valid codex32 string set."""
    ms32_share_index = CHARSET.find(fresh_share_index.lower())
    if ms32_share_index < 0:
        return None
    interpolated = ms32_interpolate(validate_set(string_list), ms32_share_index)
    return ms32_encode(ms32_decode(string_list[0])[0], interpolated)


def fingerprint(seed):
    """Generate a 4-character bech32 fingerprint from a master seed."""
    BIP32Node._generator = secp256k1_generator
    node = BIP32Node.from_master_secret(seed)
    return convertbits(node.fingerprint(), 8, 5)[:4]


def encode_secret(secret, hrp='ms', k='0', ident='', index='s', pad_val='xor'):
    """Encode a codex32 string."""
    if not ident:
        ident = [CHARSET(x) for x in fingerprint(secret)]
    ms32_header = [CHARSET.find(x) for x in k + ident + index]
    payload = convertbits(secret, 8, 5, pad_val=pad_val)
    ret = ms32_encode(hrp, ms32_header + payload)
    if not decode_secret(hrp, ret):
        return None
    return ret
