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

from bip85 import BIP85
from bip85 import app
import pytest

XPRV = 'xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb'


def test_mnemonic_to_entropy():
    bip85 = BIP85()
    mnemonic = 'install scatter logic circle pencil average fall shoe quantum disease suspect usage'
    test = bip85.bip39_mnemonic_to_entropy("m/83696968'/0'/0'", mnemonic)
    expected = 'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7'
    assert test.hex() == expected


def test_mnemonic_pwd():
    bip85 = BIP85()
    mnemonic = 'install scatter logic circle pencil average fall shoe quantum disease suspect usage'
    # with password
    test = bip85.bip39_mnemonic_to_entropy("m/83696968'/0'/0'", mnemonic, 'TREZOR')
    expected = 'd24cee04c61c4a47751658d078ae9b0cc9550fe43eee643d5c10ac2e3f5edbca757b2bd74d55ff5bcc2b1608d567053660d9c7447ae1eb84b6619282fd391844'
    assert test.hex() == expected


def test_xprv_to_entropy():
    bip85 = BIP85()
    test = bip85.bip32_xprv_to_entropy("m/83696968'/0'/0'", XPRV)
    expected = 'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7'
    assert test.hex() == expected


def test_entropy_to_mnemonic():
    bip85 = BIP85()
    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/0'/0'", XPRV)

    words12 = 'useful guitar veteran zone perfect october explain grant clarify december flight recycle'
    assert bip85.entropy_to_bip39(entropy, 12) == words12

    words15 = 'useful guitar veteran zone perfect october explain grant clarify december flight raw banana estate uncle'
    assert bip85.entropy_to_bip39(entropy, 15) == words15

    words24 = 'useful guitar veteran zone perfect october explain grant clarify december flight raw banana estate unfair grow search witness echo market primary alley forward boring'
    assert bip85.entropy_to_bip39(entropy, 24) == words24

def test_wif_from_entropy():
    bip85 = BIP85()
    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/2'/0'", XPRV)
    entropy = entropy[:32]
    assert bip85.entropy_to_wif(entropy) == 'Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp'

def test_mnemonic():
    bip85 = BIP85()
    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/39'/0'/12'/0'", XPRV)
    assert entropy[:16].hex() == '6250b68daf746d12a24d58b4787a714b'
    assert bip85.entropy_to_bip39(entropy, 12) == \
                     'girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose'

    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/39'/0'/18'/0'", XPRV)
    assert entropy[:24].hex() == '938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc'
    assert bip85.entropy_to_bip39(entropy, 18) == \
                     'near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token'

    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/39'/0'/24'/0'", XPRV)
    assert entropy[:32].hex() == 'ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f'
    assert bip85.entropy_to_bip39(entropy, 24) == \
                     'puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano'

def test_entropy_to_codex32():
    bip85 = BIP85()
    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/93'/0'/0'/1'/16'/24'/15'/32'/32'/0'", XPRV)
    unshared_ms_secret = {'identifier': 'c0ny', 'codex32': ['ms10c0nys4xklclp0lneyfjmyp9uhlfdzqfwwengqaduatsw']}
    assert bip85.entropy_to_bip93(entropy, threshold=0, n=1, byte_length=16, id=[24,15,32,32]) == unshared_ms_secret
    
    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/93'/1'/0'/1'/32'/32'/32'/32'/32'/0'", XPRV)
    unshared_cl_secret = {'identifier': 'wwak', 'codex32': ['cl10wwakss63h2vh43mjdk9sjjendkyy2mvt2n6frt83sly7afjh85xl3l9qlp63pyuukcyqyf']}
    assert bip85.entropy_to_bip93(entropy, hrp='cl', threshold=0, n=1, byte_length=32, id=[32,32,32,32]) == unshared_cl_secret

    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/93'/0'/2'/3'/16'/24'/15'/15'/31'/0'", XPRV)
    fresh_seed_one = {'identifier': 'c00l', 'codex32': ['ms12c00ln4kx8hawgstmrky88szf0qc7p9snrryzwl06tay6', 'ms12c00lpc9sddr6j0kl48m8j7n9sfg4p39ajmq4xx40xwvt', 'ms12c00lyj8fjetdxqhrvt58zalgllrdpx477puthmplvva8']}
    assert bip85.entropy_to_bip93(entropy, threshold=2, n=3, id=[24,15,15,31]) == fresh_seed_one

    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/93'/0'/3'/9'/16'/32'/32'/32'/32'/0'", XPRV)
    fresh_seed_two = {'identifier': 'ms8t', 'codex32': ['ms13ms8tu5dtz5c6d7lfg7l48mmewvhdu0z6q6eav29umjhl', 'ms13ms8tneyjzext4y7cd0s6c2gwn92smyldywhfrzc2xmhq', 'ms13ms8tz6nt2nvekkjyqn2lqdszm8pfydmmttfytvg28fcv', 'ms13ms8tdh6j27jgwvn49z9slur4xwu5rxxv0l8syy4u6qcn', 'ms13ms8tp85zuyk2ct2msvjjtvwxljg52fza02ln8plkfegf', 'ms13ms8tcfk9nlh8e6uhaqrxrk9pa8djsquk4xhs4zv87jnv', 'ms13ms8tenrpvzdmjtxkuputf72p4xy422s8n2dryeva3yk2', 'ms13ms8tjr3kayuh74yevw0hjz8wmyrhpwnuzzd6jecsfdjx', 'ms13ms8tf2pum4a46gstsuerm3ad49xt0fcq6rfaavu8lquq']}
    assert bip85.entropy_to_bip93(entropy, threshold=3, n=9, id=[32,32,32,32]) == fresh_seed_two

    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/93'/0'/3'/2'/16'/8'/15'/32'/32'/0'", XPRV)
    existing_seed_one = {'identifier': 'g0fy', 'codex32': ['ms13g0fyarrwyawuktl8qptwqy3np7jx3xfv992ytz5kcq8h', 'ms13g0fyc4e379zymy6tzdhgzwfeq6ymwlr36qext53v2vp4']}
    assert bip85.entropy_to_bip93(entropy, threshold=3, n=2, id=[8,15,32,32]) == existing_seed_one

    entropy = bip85.bip32_xprv_to_entropy("m/83696968'/93'/0'/2'/1'/64'/32'/29'/19'/19'/0'", XPRV)
    existing_seed_two = {'identifier': 'mann', 'codex32': ['ms12mannaczq4kkph3gtppqu5ehjes6fvsyh09m0tk3ag5z3tkq5p5menyjpukyy2dvddk4yu979949g08jlfdt4w946we8dynamcu22c0tr6s2rndpnrmqac6z23nd']}
    assert bip85.entropy_to_bip93(entropy, threshold=2, n=1, byte_length=64, id=[32,29,19,19]) == existing_seed_two

def test_xprv():
    bip85 = BIP85()
    result = bip85.bip32_xprv_to_xprv("83696968'/32'/0'", XPRV)
    assert result == 'xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX'

@pytest.mark.parametrize('path, width, expect', [
        ("83696968'/128169'/32'/0'", 32, 'ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc'),
        ("83696968'/128169'/64'/0'", 64, '492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c'),
        ("83696968'/128169'/64'/1234'", 64, '61d3c182f7388268463ef327c454a10bc01b3992fa9d2ee1b3891a6b487a5248793e61271066be53660d24e8cb76ff0cfdd0e84e478845d797324c195df9ab8e'),
    ])
def test_hex(path, width, expect):
    bip85 = BIP85()
    assert bip85.bip32_xprv_to_hex(path, width, XPRV) == expect

def test_bipentropy_applications():
    assert app.bip39(XPRV, 'english', 18, 0) == \
           'near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token'
    
    assert app.bip93(XPRV, hrp='ms', threshold=0, n=1, byte_length=16, identifier='c0??', index=1) == \
           {'identifier': 'c0zc', 'codex32': ['ms10c0zcs35ddcltwzsrjnz8vh97s8ml0dara49ch74gxm5x']}

    assert app.xprv(XPRV, 0) == \
           'xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX'

    assert app.wif(XPRV, 0) == 'Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp'

    assert app.hex(XPRV, 0, 32) == 'ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc'

    assert app.base64(XPRV, pwd_len=21, index=0) == b'dKLoepugzdVJvdL56ogNV'

    assert app.base85(XPRV, pwd_len=12, index=0) == b'_s`{TW89)i4`'

    assert app.dice(XPRV, sides=6, rolls=10, index=0) == '1,0,0,2,0,1,5,5,2,4'

if __name__ == "__main__":
    pytest.main()
