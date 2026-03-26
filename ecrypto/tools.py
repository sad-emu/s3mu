
def int_to_bytes(int_val, num_bytes):
    return int_val.to_bytes(num_bytes, byteorder='big')

def bytes_to_int(bytes_val):
    return int.from_bytes(bytes_val, byteorder='big')

import hashlib

def get_md5(file_path: str, chunk_size: int = 4096):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        next_bytes = f.read(chunk_size)
        while len(next_bytes) != 0:
            md5_hash.update(next_bytes)
            next_bytes = f.read(chunk_size)
    return md5_hash.hexdigest()