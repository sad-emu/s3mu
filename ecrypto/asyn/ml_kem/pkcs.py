"""
Import and export of keys to PKCS #8 and SPKI format.

This module allows for importing private keys (decapsulation keys) from
PKCS #8 files, exporting them to PKCS #8 files, and both import and export
of the public keys (encapsulation keys) from the Subject Public Key Info
format used in X.509 certificates and in bare public keys.
"""

# try:
#     from ecdsa import der
# except ImportError:
#     raise ImportError("PKCS functionality requires the ecdsa library")

from .default_parameters import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from ecrypto.asyn.ml_kem.lite_der import *


OIDS = {
    ML_KEM_512.oid: ML_KEM_512,
    ML_KEM_768.oid: ML_KEM_768,
    ML_KEM_1024.oid: ML_KEM_1024,
}


def ek_to_der(kem, ek):
    """
    Convert an encapsulation key to a SPKI DER structure.

    :param kem: an ``ML_KEM`` object instance
    :param bytes ek: encapsulation key
    :rtype: bytes
    """
    if not kem.oid:
        raise ValueError("Only KEMs with specified OIDs can be encoded")

    if len(ek) != kem._ek_size():
        raise ValueError(f"Provided key size doesn't match the provided kem")

    enc = encode_sequence(
        encode_sequence(
            encode_oid(*kem.oid),
        ),
        encode_bitstring(ek, 0),
    )

    return enc


def ek_to_pem(kem, ek):
    """
    Convert an encapsulation key to a SPKI PEM structure.

    :param kem: an ``ML_KEM`` object instance
    :param bytes ek: encapsulation key
    :rtype: str
    """
    der_enc = ek_to_der(kem, ek)

    pem_enc = topem(der_enc, "PUBLIC KEY")

    return pem_enc


def ek_from_der(enc_key):
    """
    Extract an encapsulation key from DER encoding.

    :param bytes enc_key: SPKI DER encoding of a key
    :rtype: tuple(ML_KEM, bytes)
    """
    s1, empty = remove_sequence(enc_key)
    if empty:
        raise ValueError("Trailing junk after DER public key")

    alg_id, rem = remove_sequence(s1)

    # It IS in there, just not being parsed correctly - TODO fix
    alg_id, rest = remove_object(alg_id)

    if alg_id[-1:] == b'\x01':
        kem = OIDS[ML_KEM_512.oid]
    if alg_id[-1:] == b'\x02':
        kem = OIDS[ML_KEM_768.oid]
    if alg_id[-1:] == b'\x03':
        kem = OIDS[ML_KEM_1024.oid]
    # if alg_id not in OIDS:
    #     raise ValueError(f"Not recognised algoritm OID: {alg_id}")
    if rest:
        raise ValueError("Parameters specified for ML-KEM OID")

    # kem = OIDS[alg_id]

    key, empty = remove_bitstring(rem, 0)
    if empty:
        raise ValueError("Trailing junk after public key bitsting")

    if len(key) != kem._ek_size():
        raise ValueError("Wrong key size for the OID in structure")

    return kem, key


def ek_from_pem(enc_key):
    """
    Extract an encapsulation key from PEM encoding.

    :param str enc_key: SPKI PEM encoding of a key
    :rtype: tuple(ML_KEM, bytes)
    """
    der_key = unpem(enc_key)
    return ek_from_der(der_key)

def dk_to_der(kem, dk=None, seed=None, form=None):
    """
    Convert the decapsulation key to a PKCS #8 DER structure.

    ``ek``, ``seed``, or both need to be provided.
    If ``form`` is not specified (is set to ``None``), the format that
    preserves maximum amount of information will be used.

    Proposed in
    https://mailarchive.ietf.org/arch/msg/spasm/50v8oLi5XObC7AIL4DH337_Anos/
    for the draft-ietf-lamps-kyber-certificates

    :param kem: an ``ML_KEM`` object instance
    :param bytes dk: decapsulation key
    :param bytes seed: seed to generate ML-KEM keys
    :param str form: What format to write the key in, options are:
        None - for automatic selection based on ``dk`` and ``seed``,
        ``seed`` for writing seed only, ``expanded`` for writing
        the expanded key only, ``both`` for writing both key and expanded key.
    :rtype: bytes
    """
    if form not in ("seed", "expanded", "both", None):
        raise ValueError(
            f"Invalid form specified: {form}. "
            "Only 'seed', 'expanded', 'both', and None are allowed"
        )
    if not dk and not seed:
        raise ValueError("dk or seed must be provided")

    if dk and len(dk) != kem._dk_size():
        raise ValueError("Invalid decapsulation key size for the provided KEM")

    if seed and len(seed) != 64:
        raise ValueError("Invalid seed size")

    if form in ("both", "seed") and not seed:
        raise ValueError(f'Format "{form}" requires specifing seed')

    if form is None:
        if dk and seed:
            form = "both"
        elif dk:
            form = "expanded"
        else:
            assert seed
            form = "seed"

    if form in ("both", "seed") and not dk:
        _, dk = kem.key_derive(seed)

    if form == "seed":
        enc_key = encode_implicit(0, seed)
    elif form == "expanded":
        enc_key = encode_octet_string(dk)
    else:
        assert form == "both"
        enc_key = encode_sequence(
            encode_octet_string(seed), encode_octet_string(dk)
        )

    encoded_pkcs8 = encode_sequence(
        encode_integer(0),
        encode_sequence(encode_oid(*kem.oid)),
        encode_octet_string(enc_key),
    )

    return encoded_pkcs8


def dk_to_pem(kem, dk=None, seed=None, form=None):
    """
    Convert the decapsulation key to a PKCS #8 DER structure.

    ``ek``, ``seed``, or both need to be provided.
    If ``form`` is not specified (is set to ``None``), the format that
    preserves maximum amount of information will be used.

    Proposed in
    https://mailarchive.ietf.org/arch/msg/spasm/50v8oLi5XObC7AIL4DH337_Anos/
    for the draft-ietf-lamps-kyber-certificates

    :param kem: an ``ML_KEM`` object instance
    :param bytes dk: decapsulation key
    :param bytes seed: seed to generate ML-KEM keys
    :param str form: What format to write the key in, options are:
        None - for automatic selection based on ``dk`` and ``seed``,
        ``seed`` for writing seed only, ``expanded`` for writing
        the expanded key only, ``both`` for writing both key and expanded key.
    :rtype: bytes
    """
    der_enc = dk_to_der(kem, dk, seed, form)

    pem_enc = topem(der_enc, "PRIVATE KEY")

    return pem_enc


def dk_from_der(enc_key):
    """
    Extract encapsulation and decapsulation keys from PKCS #8 DER encoding.

    :param bytes enc_key: PKCS #8 DER encoding of the key
    :return: the first element returned is the ``ML_KEM`` object instance,
        second element is the decapsulation key, third is the seed (if present),
        and fourth is the encapsulation key.
    :rtype: tuple(ML_KEM, bytes, bytes, bytes)
    """
    s1, empty = remove_sequence(enc_key)
    if empty:
        raise ValueError("Trailing junk after private key structure")

    ver, rest = remove_integer(s1)

    if ver != 0:
        raise ValueError(f"Unsupported version: {ver}")

    alg_id, rest = remove_sequence(rest)

    alg_id, empty = remove_object(alg_id)
    if alg_id[-1:] == b'\x01':
        kem = OIDS[ML_KEM_512.oid]
    if alg_id[-1:] == b'\x02':
        kem = OIDS[ML_KEM_768.oid]
    if alg_id[-1:] == b'\x03':
        kem = OIDS[ML_KEM_1024.oid]
    # if alg_id not in OIDS:
    #     raise ValueError(f"Not recognised algorithm OID: {alg_id}")
    if empty:
        raise ValueError("Junk after algorithm OID")

    #kem = OIDS[alg_id]

    priv_key, _ = remove_octet_string(rest)
    # "rest" here can be either parameters of public key: we ignore those

    seed = None
    expanded = None
    ek = None

    if priv_key[0] == 0x04:
        # we have OCTET STRING: expanded only format
        expanded, empty = remove_octet_string(priv_key)
        if empty:
            raise ValueError("Junk after expandedKey")
    elif is_sequence(priv_key):
        both, empty = remove_sequence(priv_key)
        if empty:
            raise ValueError("Junk after both encoding")
        seed, key_val = remove_octet_string(both)
        expanded, empty = remove_octet_string(key_val)
        if empty:
            raise ValueError("Junk after 'expandedKey' in 'both' value")
    else:
        tag, seed, empty = remove_implicit(priv_key)
        if tag != 0:
            raise ValueError(f"Unexpected tag in private key encoding")
        if empty:
            raise ValueError("Junk after seed encoding")

    if expanded and len(expanded) != kem._dk_size():
        raise ValueError("Invalid expanded key size in encoding")

    if not expanded:
        ek, expanded = kem.key_derive(seed)

    if seed and len(seed) != 64:
        raise ValueError("Invalid length of seed in encoding")

    if not ek:
        ek = expanded[384 * kem.k : 768 * kem.k + 32]

    return kem, expanded, seed, ek


def dk_from_pem(enc_key):
    """
    Extract encapsulation and decapsulation keys from PKCS #8 PEM encoding.

    :param str enc_key: PKCS #8 PEM encoding of the key
    :return: the first element returned is the ``ML_KEM`` object instance,
        second element is the decapsulation key, third is the seed (if present),
        and fourth is the encapsulation key.
    :rtype: tuple(ML_KEM, bytes, bytes, bytes)
    """
    der_key = unpem(enc_key)
    return dk_from_der(der_key)