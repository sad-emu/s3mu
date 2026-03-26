from ecrypto.asyn.ml_kem.pkcs import dk_from_pem
from ecrypto.asyn.ml_kem.pkcs import ek_from_pem

def get_decryption_key_from_pem(pem_string: str):
    return dk_from_pem(pem_string)

def get_encryption_key_from_pem(pem_string: str):
    return ek_from_pem(pem_string)