import hashlib
import os
from enum import nonmember

import crypto.aes as aes
import crypto.tools as tools

# format is:
# header 4 bytes
# mode 2 bytes

# if mode 0
# IV
# Salt
# Ciphertext

CRYPT_HEADER_LEN = 4
CRYPT_HEADER = b'ecpt'
CRYPT_MODE_LEN = 2
CRYPT_MODE_ONE = 1
CRYPT_MODE_ONE_WORKLOAD = 999999

CRYPT_STREAM_MODE_ENCRYPT = 'ENCRYPT'
CRYPT_STREAM_MODE_DECRYPT = 'DECRYPT'

class EmuCrypt:
    _iv = None
    _salt = None
    _block_iv = None
    _stream_mode = None
    _secret = None
    _output_stream = None
    _data_buffer = None
    _first_write = None
    _workload = None
    _closed = None

    def setup_for_encrypt(self):
        self._iv = os.urandom(aes.IV_SIZE)
        self._salt = os.urandom(aes.IV_SIZE)
        if isinstance(self._secret, str):
            self._secret = self._secret.encode('utf-8')
        self._secret = EmuCrypt.gen_hash(self._salt, self._secret, self._workload, aes.KEY_SIZE)

    def setup_for_decrypt(self):
        # All the required data should be on the input stream
        return

    def __init__(self, stream_mode, secret, output_stream, crypt_mode=CRYPT_MODE_ONE):
        self._secret = secret
        if stream_mode == CRYPT_STREAM_MODE_ENCRYPT:
            if crypt_mode == CRYPT_MODE_ONE:
                self._workload = CRYPT_MODE_ONE_WORKLOAD
            self.setup_for_encrypt()
        elif stream_mode == CRYPT_STREAM_MODE_DECRYPT:
            self.setup_for_decrypt()
        else:
            raise ValueError('Invalid stream mode provided.')
        self._stream_mode = stream_mode
        self._output_stream = output_stream
        self._data_buffer = bytearray(b'')
        self._first_write = True
        self._closed = False

    # Write to the output stream
    def write(self, bytes_to_write):
        if self._closed:
            raise ValueError('This stream is already closed.')
        if self._stream_mode == CRYPT_STREAM_MODE_ENCRYPT:
            if self._first_write:
                self._first_write = False
                write_bytes = bytearray(b'')
                write_bytes.extend(CRYPT_HEADER)
                write_bytes.extend(tools.int_to_bytes(CRYPT_MODE_ONE, CRYPT_MODE_LEN))
                write_bytes.extend(self._iv)
                write_bytes.extend(self._salt)
                self._output_stream.write(write_bytes)
                self._block_iv = self._iv
        self._data_buffer.extend(bytes_to_write)
        next_write_max_size = len(self._data_buffer)
        if next_write_max_size < 16:
            return # we cannot do anything with less than 16 bytes
        next_write_remainder = (next_write_max_size % 16)
        next_write_len = next_write_max_size - next_write_remainder
        write_bytes = bytearray(b'')
        write_bytes.extend(self._data_buffer[0:next_write_len]) # do we need this copy?
        self._data_buffer = self._data_buffer[next_write_len:next_write_max_size] # shift the remaining data
        ciphertext = aes.AES(self._secret).encrypt_cbc(write_bytes, self._block_iv)
        # the last block is padding, drop it. The 2nd last block is the next IV
        self._output_stream.write(ciphertext[0:len(ciphertext)-aes.BLOCK_SIZE])
        self._block_iv = ciphertext[len(ciphertext)-(aes.BLOCK_SIZE * 2):len(ciphertext)-aes.BLOCK_SIZE]


    # Flush the stream - only for encrypt
    def flush(self):
        if self._closed:
            raise ValueError('This stream is already closed.')
        if self._stream_mode == CRYPT_STREAM_MODE_ENCRYPT:
            # Just add padding
            ciphertext = aes.AES(self._secret).encrypt_cbc(self._data_buffer, self._block_iv)
            self._output_stream.write(ciphertext)
        self._secret = b''
        self._iv = b''
        self._salt = b''
        self._data_buffer = b''
        self._closed = True

    @staticmethod
    def gen_hash(salt, secret, rounds, size):
        return hashlib.pbkdf2_hmac('sha512', password=secret, salt=salt, iterations=rounds, dklen=size)

    @staticmethod
    def block_encrypt(key, plaintext, mode=CRYPT_MODE_ONE):
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        workload = 0
        if mode == CRYPT_MODE_ONE:
            workload = CRYPT_MODE_ONE_WORKLOAD
        iv = os.urandom(aes.IV_SIZE)
        salt = os.urandom(aes.IV_SIZE)
        key = EmuCrypt.gen_hash(salt, key, workload, aes.KEY_SIZE)
        ciphertext = aes.AES(key).encrypt_cbc(plaintext, iv)
        return_bytes = bytearray(b'')
        return_bytes.extend(CRYPT_HEADER)
        return_bytes.extend(tools.int_to_bytes(CRYPT_MODE_ONE, CRYPT_MODE_LEN))
        return_bytes.extend(iv)
        return_bytes.extend(salt)
        return_bytes.extend(ciphertext)
        return return_bytes

    # First 16 bytes are the IV
    # The whole thing relies on a pre-shared-key
    @staticmethod
    def block_decrypt(key, ciphertext):
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        pos = 0
        header = ciphertext[0:CRYPT_HEADER_LEN]
        pos = CRYPT_HEADER_LEN
        if header != CRYPT_HEADER:
            raise ValueError("Data does not have expected header")
        mode = ciphertext[pos:pos+CRYPT_MODE_LEN]
        if mode != tools.int_to_bytes(CRYPT_MODE_ONE, CRYPT_MODE_LEN):
            raise ValueError("Block decrypt only supports MODE_ONE not " + str(tools.bytes_to_int(mode)))
        workload = 0
        if mode == tools.int_to_bytes(CRYPT_MODE_ONE, CRYPT_MODE_LEN):
            workload = CRYPT_MODE_ONE_WORKLOAD
        pos += CRYPT_MODE_LEN
        iv = ciphertext[pos:pos + aes.IV_SIZE]
        pos += aes.IV_SIZE
        salt = ciphertext[pos:pos + aes.KEY_SIZE]
        pos += aes.KEY_SIZE
        ciphertext = ciphertext[pos:len(ciphertext)]
        key = EmuCrypt.gen_hash(salt, key, workload, aes.KEY_SIZE)
        return aes.AES(key).decrypt_cbc(ciphertext, iv)
