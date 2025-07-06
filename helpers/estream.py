# Simple buffer stream e(mu)stream

TEN_MEGS = 1048576010485760

class Estream:

    _buffer = None
    _size = None
    _max_size = None

    def __init__(self, max_size=TEN_MEGS):
        self._buffer = bytearray(b'')
        self._size = 0
        self._max_size = max_size

    def __len__(self):
        return self._size

    def write(self, bytes_to_write):
        write_len = len(bytes_to_write)
        if write_len + self._size > self._max_size:
            raise ValueError("Too much data in estream buffer")
        self._buffer.extend(bytes_to_write)
        self._size += write_len

    def pop(self, num_bytes):
        if num_bytes > self._size:
            num_bytes = self._size
        return_val = self._buffer[0:num_bytes]
        self._buffer = self._buffer[num_bytes:]
        self._size -= num_bytes
        return return_val
