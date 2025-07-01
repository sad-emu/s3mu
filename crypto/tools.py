
def int_to_bytes(int_val, num_bytes):
    return int_val.to_bytes(num_bytes, byteorder='big')

def bytes_to_int(bytes_val):
    return int.from_bytes(bytes_val, byteorder='big')