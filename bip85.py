#!/usr/bin/python3
import hashlib
import hmac
from electrum import bip32, ecc
from electrum.crypto import hash_160
import multiprocessing
from functools import partial


def derive_entropy(master_xprv, path):
    derived_private_key_k = bip32.BIP32Node.from_xkey(
        master_xprv).subkey_at_private_derivation(path).eckey.get_secret_bytes()
    return hmac.digest(b'bip-entropy-from-k', derived_private_key_k, 'sha512')


def derive_xprv(master_xprv, index='0'):
    I = derive_entropy(master_xprv, "m/83696968'/32'/"+index+"'")
    k = ecc.ECPrivkey(I[32:])
    c = I[:32]
    return bip32.BIP32Node(xtype="standard", eckey=k, chaincode=c)

def pgrind_index_for_fingerprint(master_xprv, ident_fingerprint='01010', index=-1):
    id_len = len(ident_fingerprint)
    fingerprint = 'g'
    while fingerprint[:id_len] != ident_fingerprint:
        index += 1
        candidate_xprv = derive_xprv(master_xprv, str(index))
        fingerprint = candidate_xprv.calc_fingerprint_of_this_node().hex()
    return str(index), derive_xprv(master_xprv, str(index)).calc_fingerprint_of_this_node().hex()




from electrum import ecc



def worker(index, master_node, path, ident_fingerprint):
    path += str(index) +"'"
    derived_private_key_k = master_node.subkey_at_private_derivation(
        path).eckey.get_secret_bytes()
    I = hmac.digest(b'bip-entropy-from-k', derived_private_key_k, 'sha512')
    if (hash_160(ecc.ECPrivkey(I[32:]).get_public_key_bytes()).hex()[:5]
            == ident_fingerprint):
        return index


def grind_index_for_fingerprint(master_xprv, ident_fingerprint):
    master_node = bip32.BIP32Node.from_xkey(master_xprv)
    path = "m/83696968'/32'/"

    pool = multiprocessing.Pool()
    worker_with_args = partial(worker, master_node=master_node, path=path,
                               ident_fingerprint=ident_fingerprint)
    # TODO find the optimum chunksize for finding fingerprint '00000'
    # TODO on dual-core vm and make a chunksize a function of cpu count
    results = pool.imap(worker_with_args, range(2 ** 31), chunksize=2*19)

    for result in results:
        if result:
            return result