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

from bip85.bip93 import CHARSET
from bip85 import BIP85

LANGUAGE_LOOKUP = {
    'english': 0,
    'japanese': 1,
    'korean': 2,
    'spanish': 3,
    'chinese_simplified': 4,
    'chinese_traditional': 5,
    'french': 6,
    'italian': 7,
    'czech': 8
}

HRP_LOOKUP = {
    'ms': 0,
    'cl': 1,
}

def bip39(xprv_string, language, words, index):
    # 83696968'/39'/language'/words'/index'
    lang_code = LANGUAGE_LOOKUP[language]
    bip85 = BIP85()
    path = f"83696968p/39p/{lang_code}p/{words}p/{index}p"

    entropy = bip85.bip32_xprv_to_entropy(path, xprv_string)
    return bip85.entropy_to_bip39(entropy, words, language)


def bip93(xprv_string, hrp, threshold, n, byte_length, identifier, index):
    # 83696968'/93'/hrp'/threshold'/n'/byte_length'/identifier'
    hrp_code = HRP_LOOKUP[hrp]
    id = [32 if CHARSET.find(char.lower()) == -1 else CHARSET.find(char.lower()) for char in identifier]
    default_characters = id.count(32)
    # Identifiers SHOULD be unique per seed so index can't be too high
    if index > 0 and default_characters < 2:
        raise ValueError("ERROR: To use an index > 0, at least two identifier characters must be default (i.e. not in the charset).")
    elif index > 5 and default_characters < 3:
        raise ValueError("ERROR: To use an index > 5, at least three identifier characters must be default (i.e. not in the charset).")
    elif index > 26 and default_characters < 4:
        raise ValueError("ERROR: To use an index > 26, all four identifier characters must be default (i.e. not in the charset).")
    elif index > 146:
        raise ValueError("ERROR: Index must be between 0 and 146.")
    bip85 = BIP85()
    path = f"83696968p/93p/{hrp_code}p/{threshold}p/{n}p/{byte_length}p/{id[0]}p/{id[1]}p/{id[2]}p/{id[3]}p/{index}p"
    entropy = bip85.bip32_xprv_to_entropy(path, xprv_string)
    return bip85.entropy_to_bip93(entropy, hrp, threshold, n, byte_length, id)


def wif(xprv_string, index):
    # m/83696968'/2'/index'
    bip85 = BIP85()
    path = f"83696968p/2p/{index}p"
    return bip85.entropy_to_wif(bip85.bip32_xprv_to_entropy(path, xprv_string))


def hex(xprv_string, index, width):
    # m/83696968'/128169p'/index'
    bip85 = BIP85()
    path = f"83696968p/128169p/{width}p/{index}p"
    return bip85.bip32_xprv_to_hex(path, width, xprv_string)


def xprv(xprv_string, index):
    # 83696968'/32'/index'
    bip85 = BIP85()
    path = f"83696968p/32p/{index}p"
    return bip85.bip32_xprv_to_xprv(path, xprv_string)
