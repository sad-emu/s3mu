import hashlib
import os

import ecrypto.sync.aes as aes
import ecrypto.tools as tools


# format is:
# header 4 bytes
# mode 2 bytes

# if mode 1 (SYNC)
# IV
# Salt
# Ciphertext
# TODO Ciphertext hash

# if mode 1 (ASYNC)
# IV
# Salt
# 2 bytes length of next blob
# Encrypted key (len above)
# TODO Ciphertext hash

CRYPT_HEADER_LEN = 4
CRYPT_HEADER = b'ecpt'
CRYPT_MODE_LEN = 2
CRYPT_MODE_ONE = 1
CRYPT_MODE_TWO = 2
CRYPT_MODE_ONE_WORKLOAD = 999999
CRYPT_MODE_TWO_WORKLOAD = 10000

CRYPT_MODE_TWO_KEY_SIZE_LEN = 2

CRYPT_STREAM_MODE_ENCRYPT = 'ENCRYPT'
CRYPT_STREAM_MODE_DECRYPT = 'DECRYPT'

class EmuCrypt:
    _iv = None
    _salt = None
    _block_iv = None
    _stream_mode = None
    _crypt_mode = None
    _secret = None
    _enc_secret = None
    _output_stream = None
    _data_buffer = None
    _decrypt_tail = None
    _first_write = None
    _workload = None
    _closed = None
    _ek = None
    _kem = None
    _mode_two_key_len = None

    def setup_for_encrypt(self):
        self._iv = os.urandom(aes.IV_SIZE)
        self._salt = os.urandom(aes.IV_SIZE)
        if self._crypt_mode == CRYPT_MODE_ONE:
            if isinstance(self._secret, str):
                self._secret = self._secret.encode('utf-8')
            self._secret = EmuCrypt.gen_hash(self._salt, self._secret, self._workload, aes.KEY_SIZE)
        if self._crypt_mode == CRYPT_MODE_TWO:
            secret, ciphertext = self._kem.encaps(self._ek)
            self._secret = EmuCrypt.gen_hash(self._salt, secret, self._workload, aes.KEY_SIZE)
            self._enc_secret = ciphertext

    def setup_for_decrypt(self):
        if self._secret is None:
            return
        if isinstance(self._secret, str):
            self._secret = self._secret.encode('utf-8')

    def __init__(self, stream_mode, secret_key, output_stream, crypt_mode=CRYPT_MODE_ONE, ek=None, kem=None):
        self._secret = secret_key
        self._crypt_mode = crypt_mode
        self._ek = ek
        self._kem = kem
        if stream_mode == CRYPT_STREAM_MODE_ENCRYPT:
            if crypt_mode == CRYPT_MODE_ONE:
                self._workload = CRYPT_MODE_ONE_WORKLOAD
            elif crypt_mode == CRYPT_MODE_TWO:
                self._workload = CRYPT_MODE_TWO_WORKLOAD
            self.setup_for_encrypt()
        elif stream_mode == CRYPT_STREAM_MODE_DECRYPT:
            self.setup_for_decrypt()
        else:
            raise ValueError('Invalid stream mode provided.')
        self._stream_mode = stream_mode
        self._output_stream = output_stream
        self._data_buffer = bytearray(b'')
        self._first_write = True
        self._mode_two_key_len = 0
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
                write_bytes.extend(tools.int_to_bytes(self._crypt_mode, CRYPT_MODE_LEN))
                write_bytes.extend(self._iv)
                write_bytes.extend(self._salt)
                if self._crypt_mode == CRYPT_MODE_TWO:
                    write_bytes.extend(tools.int_to_bytes(len(self._enc_secret), CRYPT_MODE_TWO_KEY_SIZE_LEN))
                    write_bytes.extend(self._enc_secret) # Write the AES encrypted key here
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
            self._output_stream.write(ciphertext[0:len(ciphertext) - aes.BLOCK_SIZE])
            self._block_iv = ciphertext[len(ciphertext)-(aes.BLOCK_SIZE * 2):len(ciphertext) - aes.BLOCK_SIZE]
        else:
            self._data_buffer.extend(bytes_to_write)
            if self._first_write:
                if len(self._data_buffer) < 6:
                    return # we need at least 6 bytes to work out the mode
                header = self._data_buffer[0:CRYPT_HEADER_LEN]
                pos = CRYPT_HEADER_LEN
                if header != CRYPT_HEADER:
                    raise ValueError("Data does not have expected header")
                mode = self._data_buffer[pos:pos + CRYPT_MODE_LEN]
                pos += CRYPT_MODE_LEN
                if mode != tools.int_to_bytes(CRYPT_MODE_ONE, CRYPT_MODE_LEN) and \
                    mode != tools.int_to_bytes(CRYPT_MODE_TWO, CRYPT_MODE_LEN):
                    raise ValueError("Stream decrypt only supports MODE_ONE&TWO not " + str(tools.bytes_to_int(mode)))
                min_start_bytes = 0
                if mode == tools.int_to_bytes(CRYPT_MODE_ONE, CRYPT_MODE_LEN):
                    self._workload = CRYPT_MODE_ONE_WORKLOAD
                    # min bytes to start mode one
                    min_start_bytes = pos + aes.KEY_SIZE + aes.IV_SIZE
                elif mode == tools.int_to_bytes(CRYPT_MODE_TWO, CRYPT_MODE_LEN):
                    self._workload = CRYPT_MODE_TWO_WORKLOAD
                    # min bytes to start mode one
                    min_start_bytes = pos + aes.KEY_SIZE + aes.IV_SIZE + CRYPT_MODE_TWO_KEY_SIZE_LEN + self._mode_two_key_len
                # We can't start until we have the full header
                if len(self._data_buffer) <  min_start_bytes:
                    return
                # Pull the MODE ONE data out
                self._iv = self._data_buffer[pos:pos + aes.IV_SIZE]
                self._block_iv = self._iv
                pos += aes.IV_SIZE
                self._salt = self._data_buffer[pos:pos + aes.KEY_SIZE]
                pos += aes.KEY_SIZE
                if mode == tools.int_to_bytes(CRYPT_MODE_TWO, CRYPT_MODE_LEN):
                    key_len_bytes = self._data_buffer[pos:pos + CRYPT_MODE_TWO_KEY_SIZE_LEN]
                    pos += CRYPT_MODE_TWO_KEY_SIZE_LEN
                    # We might not actually be able to continue
                    last_key_len = self._mode_two_key_len
                    self._mode_two_key_len = tools.bytes_to_int(key_len_bytes)
                    if last_key_len != self._mode_two_key_len:
                        min_start_bytes += self._mode_two_key_len
                        if len(self._data_buffer) < min_start_bytes:
                            return

                    self._enc_secret = self._data_buffer[pos:pos + self._mode_two_key_len]
                    pos += self._mode_two_key_len
                self._data_buffer = self._data_buffer[pos:]
                self._decrypt_tail = bytearray(b'')
                if mode == tools.int_to_bytes(CRYPT_MODE_ONE, CRYPT_MODE_LEN):
                    self._secret = EmuCrypt.gen_hash(self._salt, self._secret,
                                                     self._workload, aes.KEY_SIZE)
                elif mode == tools.int_to_bytes(CRYPT_MODE_TWO, CRYPT_MODE_LEN):
                    self._secret = self._kem.decaps(self._ek, self._enc_secret)
                    self._secret = EmuCrypt.gen_hash(self._salt, self._secret,
                                                     self._workload, aes.KEY_SIZE)
                self._first_write = False

            next_write_max_size = len(self._data_buffer)
            if next_write_max_size < 32:
                return # we cannot do anything with less than 32 bytes due to padding
            next_write_remainder = (next_write_max_size % 16)
            next_write_len = next_write_max_size - next_write_remainder
            write_bytes = bytearray(b'')
            write_bytes.extend(self._data_buffer[0:next_write_len]) # do we need this copy?
            next_block_iv = write_bytes[next_write_len - aes.BLOCK_SIZE:next_write_len]
            self._data_buffer = self._data_buffer[next_write_len:next_write_max_size] # shift the remaining data
            plaintext = aes.AES(self._secret).decrypt_cbc(write_bytes, self._block_iv, padded_data=False)
            # the last block is padding, drop it. The 2nd last block is the next IV
            self._output_stream.write(self._decrypt_tail)
            self._output_stream.write(plaintext[0:len(plaintext)-(aes.BLOCK_SIZE + aes.IV_SIZE)])
            self._block_iv = next_block_iv
            self._decrypt_tail = plaintext[len(plaintext)-(aes.BLOCK_SIZE + aes.IV_SIZE):]

    # TODO hash for type 2 stream
    # Flush the stream
    def flush(self):
        if self._closed:
            raise ValueError('This stream is already closed.')
        if self._stream_mode == CRYPT_STREAM_MODE_ENCRYPT:
            # Just add padding
            ciphertext = aes.AES(self._secret).encrypt_cbc(self._data_buffer, self._block_iv)
            self._output_stream.write(ciphertext)
        else:
            if len(self._decrypt_tail) != aes.BLOCK_SIZE*2:
                raise ValueError('Flush failed. Incorrect padding.')
            self._output_stream.write(aes.unpad(self._decrypt_tail))
        self._decrypt_tail = b''
        self._secret = b''
        self._enc_secret = b''
        self._ek = b''
        self._kem = b''
        self._iv = b''
        self._salt = b''
        self._data_buffer = b''
        self._closed = True
        self._output_stream.flush()

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
