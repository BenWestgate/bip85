import argparse
import binascii

from mnemonic import Mnemonic as bip39
from pycoin.symbols.btc import network as BTC

from bip85 import app


def _bip32_master_seed_to_xprv(bip32_master_seed: bytes):
    if len(bip32_master_seed) < 16 or len(bip32_master_seed) > 64:
        raise ValueError('BIP32 master seed must be between 128 and 512 bits')
    xprv = BTC.keys.bip32_seed(bip32_master_seed).hwif(as_private=True)
    return xprv


def _get_xprv_from_args(args):
    if args.xprv:
        return args.xprv
    if args.bip32_master_seed:
        return _bip32_master_seed_to_xprv(
            bytearray.fromhex(args.bip32_master_seed))
    bip39_mnemonic = args.bip39_mnemonic
    if args.bip39_entropy:
        bip39_mnemonic = bip39(args.language).to_mnemonic(
            binascii.unhexlify(args.bip39_entropy))
    return _bip32_master_seed_to_xprv(bip39.to_seed(bip39_mnemonic))

def main():
    parser = argparse.ArgumentParser(description='BIP85 CLI tool')
    seed_group = parser.add_mutually_exclusive_group(required=True)
    seed_group.add_argument(
        '--bip32-master-seed',
        help='Input BIP32 master seed (AKA initial entropy), which is usually '
        'computed by hashing the BIP39 mnemonic. Must be in hex format')
    seed_group.add_argument('--bip39-entropy',
                            help='Input BIP39 initial entropy (used to derive '
                            'the mnemonic)')
    seed_group.add_argument('--bip39-mnemonic',
                            help='Input BIP39 mnemonic phrase')
    seed_group.add_argument('--xprv',
                            help='Input BIP32 root master private key')
    parser.add_argument('--index',
                        type=int,
                        required=True,
                        help='Derived key index')
    subparsers = parser.add_subparsers(dest='bip85_app')
    subparsers.required = True
    app_bip39_parser = subparsers.add_parser('bip39',
                                             help='Derive a BIP39 mnemonic')
    app_bip39_parser.add_argument('--language',
                                  choices=app.LANGUAGE_LOOKUP,
                                  default='english',
                                  help='Language for BIP39 mnemonic')
    app_bip39_parser.add_argument('--num-words',
                                  type=int,
                                  choices=(12, 15, 18, 21, 24),
                                  default=12,
                                  help='Number of words in the BIP39 mnemonic')
    app_bip93_parser = subparsers.add_parser('bip93',
                                             help='Derive a codex32 backup')
    app_bip93_parser.add_argument('--hrp',
                                  choices=app.HRP_LOOKUP,
                                  type=str,
                                  default='ms',
                                  help='Human readable prefix for codex32 backup')
    app_bip93_parser.add_argument('--threshold',
                                  type=int,
                                  required=True,
                                  choices=(0, 2, 3, 4, 5, 6, 7, 8, 9),
                                  help='Threshold value for codex32 backup')
    app_bip93_parser.add_argument('--n',
                                  type=int,
                                  required=True,
                                  choices=tuple(range(1, 32)),
                                  help='Number of codex32 strings for backup')
    app_bip93_parser.add_argument('--byte-length',
                                  type=int,
                                  choices=tuple(range(16, 65)),
                                  default=16,
                                  help='Payload bytes for codex32 backup')
    app_bip93_parser.add_argument('--identifier',
                                  type=str,
                                  default='????',
                                  help='Four character identifier for codex32 backup')
    subparsers.add_parser('wif', help='Derive a HD-Seed WIF')
    subparsers.add_parser('xprv', help='Derive an XPRV (master private key)')
    app_hex_parser = subparsers.add_parser('hex',
                                           help='Derive a HEX bytes sequence')
    app_hex_parser.add_argument('--num-bytes',
                                type=int,
                                required=True,
                                help='Number of bytes to generate')
    app_base64_parser = subparsers.add_parser('base64', help='Derive a Base64 password')
    app_base64_parser.add_argument('--pwd-len',
                                   type=int,
                                   required=True,
                                   choices=tuple(range(20,87)),
                                   help='Password length in characters')
    app_base85_parser = subparsers.add_parser('base85', help='Derive a Base85 password')
    app_base85_parser.add_argument('--pwd-len',
                                   type=int,
                                   required=True,
                                   choices=tuple(range(10,81)),
                                   help='Password length in characters')
    app_dice_parser = subparsers.add_parser('dice', help='Use this application to generate PIN numbers, numeric secrets, and secrets over custom alphabets')
    app_dice_parser.add_argument('--sides',
                                type=int,
                                required=True,
                                help='An N-sided die produces values in the range [0, N-1], inclusive'
                                )
    app_dice_parser.add_argument('--rolls',
                                type=int,
                                required=True,
                                help='Number of values to generate'
                                )
    args = parser.parse_args()
    xprv = _get_xprv_from_args(args)
    print(f"Using master private key: {xprv}")
    if args.bip85_app == 'bip39':
        print(app.bip39(xprv, args.language, args.num_words, args.index))
    elif args.bip85_app == 'bip93':
        print(app.bip93(xprv, args.hrp, args.threshold, args.n, args.byte_length,
                         args.identifier, args.index))
    elif args.bip85_app == 'wif':
        print(app.wif(xprv, args.index))
    elif args.bip85_app == 'xprv':
        print(app.xprv(xprv, args.index))
    elif args.bip85_app == 'hex':
        print(app.hex(xprv, args.index, args.num_bytes))
    elif args.bip85_app == 'base64':
        print(app.base64(xprv, args.pwd_len, args.index))
    elif args.bip85_app == 'base85':
        print(app.base85(xprv, args.pwd_len, args.index))
    elif args.bip85_app == 'dice':
        print(app.dice(xprv, args.sides, args.rolls, args.index))



if __name__ == "__main__":
    main()
