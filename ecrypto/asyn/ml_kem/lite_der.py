import base64

# Verified fixed
def topem(der_bytes: bytes, label: str = "PRIVATE KEY") -> bytes:
    b64 = base64.b64encode(der_bytes)
    lines = [f"-----BEGIN {label}-----".encode()]
    lines += [b64[i:i+76] for i in range(0, len(b64), 76)]
    lines.append(f"-----END {label}-----".encode())
    return b"\n".join(lines) + b"\n"

def unpem(pem_data) -> bytes:
    if isinstance(pem_data, str):
        pem_data = pem_data.encode('ascii')

    pem_data = pem_data.replace(b'-----BEGIN PRIVATE KEY-----', b'')
    pem_data = pem_data.replace(b'-----END PRIVATE KEY-----', b'')
    pem_data = pem_data.replace(b'-----BEGIN PUBLIC KEY-----', b'')
    pem_data = pem_data.replace(b'-----END PUBLIC KEY-----', b'')

    return base64.b64decode(pem_data)

def _read_length(data):
    if data[0] < 0x80:
        return data[0], data[1:]
    n = data[0] & 0x7F
    length = int.from_bytes(data[1:1+n], "big")
    return length, data[1+n:]

def _read_tag(data, expected_tag=None):
    tag = data[0]
    length, rest = _read_length(data[1:])
    content = rest[:length]
    remaining = rest[length:]
    if expected_tag is not None and tag != expected_tag:
        raise ValueError(f"Unexpected tag: got {tag}, expected {expected_tag}")
    return tag, content, remaining

def remove_integer(data):
    tag, content, rest = _read_tag(data, 0x02)
    return int.from_bytes(content, "big"), rest

def remove_sequence(data):
    tag, content, rest = _read_tag(data, 0x30)
    return content, rest

def remove_octet_string(data):
    tag, content, rest = _read_tag(data, 0x04)
    return content, rest

def remove_object(data):
    tag, content, rest = _read_tag(data, 0x06)
    return content, rest

def remove_implicit(data):
    tag = data[0]
    if (tag & 0xC0) != 0x80:
        raise ValueError(f"Expected context-specific tag, got {tag:#x}")
    return tag, *remove_sequence(data[2:])  # Skip tag and length byte

def encode_length(length):
    if length < 0x80:
        return bytes([length])
    l_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(l_bytes)]) + l_bytes

def encode_bitstring(data: bytes, tag_num: int = None) -> bytes:
    # Prepend unused bits byte (0)
    content = b'\x00' + data

    if tag_num is None:
        tag = 0x03  # Universal BIT STRING tag
    else:
        tag = 0x80 | tag_num  # Context-specific implicit tag

    return bytes([tag]) + encode_length(len(content)) + content

def encode_integer(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b'\x00' + b  # Ensure positive
    return bytes([0x02]) + encode_length(len(b)) + b

def encode_sequence(*elements):
    body = b''.join(elements)
    return bytes([0x30]) + encode_length(len(body)) + body

def encode_octet_string(data):
    return bytes([0x04]) + encode_length(len(data)) + data

def encode_oid(*oid_nums):
    if len(oid_nums) < 2:
        raise ValueError("OID must have at least two components")
    first_byte = 40 * oid_nums[0] + oid_nums[1]
    encoded = [first_byte]
    for num in oid_nums[2:]:
        parts = []
        while num:
            parts.insert(0, (num & 0x7F) | 0x80)
            num >>= 7
        if not parts:
            parts.append(0)
        parts[-1] &= 0x7F  # clear high bit on last byte
        encoded.extend(parts)
    content = bytes(encoded)
    return bytes([0x06]) + encode_length(len(content)) + content

def encode_implicit(tag_num, content):
    tag = 0x80 | tag_num
    return bytes([tag]) + encode_length(len(content)) + content

def is_sequence(data: bytes) -> bool:
    return data and data[0] == 0x30

def remove_bitstring(data: bytes, tag_num: int = None):
    tag = data[0]
    if tag_num is not None:
        expected_tag = 0x80 | tag_num  # context-specific implicit
        if tag != expected_tag:
            raise ValueError(f"Unexpected tag: got {tag:#x}, expected {expected_tag:#x}")
    _, content, rest = _read_tag(data)
    if not content:
        raise ValueError("BIT STRING is empty")
    unused_bits = content[0]
    if unused_bits != 0:
        raise ValueError("BIT STRING has unused bits (only 0 is supported)")
    return content[1:], rest