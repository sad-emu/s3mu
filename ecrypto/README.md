# E(mu)crypto

This package is for a hobby project. Use at your own risk.

### Credits

Licences have been included at their source file directories

Built using:
1. AES - MIT Licence - https://github.com/boppreh/aes
2. KYBER - MIT Licence - https://github.com/GiacomoPope/kyber-py

### Features

1. Pure python. Only imports os, hashlib, unittest and base64
2. Data is streamed
2. Cyphertext is hashed and verified on decryption
3. MODE_ONE for AES with a pre-shared key 
4. MODE_TWO for AES with the key encrypted with PKI and stored in the payload

### Examples

Synchronous encryption with a pre-shared key.

```python
        key = "passphrase_preshared"

        secret = (b"Really important data")

        mem_out_stream = io.BytesIO()

        ec = EmuCrypt(CRYPT_STREAM_MODE_ENCRYPT, key, mem_out_stream, CRYPT_MODE_ONE)

        ec.write(secret)
        ec.flush()

        mem_out_stream.seek(0)
        ciphertext = mem_out_stream.read()

        mem_out_stream = io.BytesIO()

        ec = EmuCrypt(CRYPT_STREAM_MODE_DECRYPT, key, mem_out_stream, CRYPT_MODE_ONE)
        ec.write(ciphertext)
        ec.flush()

        mem_out_stream.seek(0)
        plaintext = mem_out_stream.read()
```

Async example with Kyber keys

```python
        # Key generation
        kem = ML_KEM_1024
        seed = os.urandom(64)
        ek, dk = kem.key_derive(seed)

        # This is a PEM format decryption key that can be saved to disk
        dks = dk_to_pem(kem, dk=dk)
        # This is a PEM format encryption key that can be saved to disk
        eks = ek_to_pem(kem, ek)

        # Pretend we are importing from a PEM from disk
        kem, ek = ek_from_pem(eks)

        secret = (b"This is secret data")
        
        mem_out_stream = io.BytesIO()

        ec = EmuCrypt(CRYPT_STREAM_MODE_ENCRYPT, None, mem_out_stream, CRYPT_MODE_TWO, kem=kem, ek=ek)

        ec.write(secret)
        ec.flush()

        mem_out_stream.seek(0)
        ciphertext = mem_out_stream.read()

        mem_out_stream = io.BytesIO()

        # Pretend we are importing the decryption pem from disk
        kem, dk, _, _ = dk_from_pem(dks)

        ec = EmuCrypt(CRYPT_STREAM_MODE_DECRYPT, None, mem_out_stream, CRYPT_MODE_TWO, kem=kem, ek=dk)

        ec.write(ciphertext)
        ec.flush()

        mem_out_stream.seek(0)
        plaintext = mem_out_stream.read()
```
