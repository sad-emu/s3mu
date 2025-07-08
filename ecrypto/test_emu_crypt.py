import os
import unittest
import io

from ecrypto.asyn.ml_kem import ML_KEM_1024
from ecrypto.asyn.ml_kem.pkcs import ek_from_pem, dk_from_pem, dk_to_pem, ek_to_pem
from ecrypto.emu_crypt import EmuCrypt, CRYPT_STREAM_MODE_ENCRYPT, CRYPT_MODE_ONE, CRYPT_STREAM_MODE_DECRYPT, \
    CRYPT_MODE_TWO


class TestStringMethods(unittest.TestCase):

    def test_block_encrypt_block_decrypt(self):
        key = "bad_password"
        secret = "this text is really secret 010101"

        ciphertext = EmuCrypt.block_encrypt(key, secret)
        self.assertNotEqual(secret.encode('utf-8'), ciphertext)

        plaintext = EmuCrypt.block_decrypt(key, ciphertext)
        self.assertEqual(secret, plaintext.decode('utf-8'))

    def test_block_encrypt_stream_decrypt(self):
        key = "bad_password"
        secret = "this text is really secret 010101"

        ciphertext = EmuCrypt.block_encrypt(key, secret)
        self.assertNotEqual(secret.encode('utf-8'), ciphertext)

        mem_out_stream = io.BytesIO()

        ec = EmuCrypt(CRYPT_STREAM_MODE_DECRYPT, key, mem_out_stream, CRYPT_MODE_ONE)

        ec.write(ciphertext[0:])
        ec.flush()

        mem_out_stream.seek(0)
        plaintext = mem_out_stream.read()
        self.assertEqual(secret, plaintext.decode('utf-8'))

    def test_stream_encrypt_block_decrypt(self):
        key = "a slightly better passphrase +_)((**&^%$#@!"

        secret = (b"fdasfdafdafadfadfdsafdasfasdfdsafadsfasdf"
                  b"FFFFFFFFFFFFFFFFFFFFFfff"
                  b"SSSSSSSSSSSSSSSSSSSSSSSs"
                  b"43254365789590098765432w"
                  b"43254365789590098765432d"
                  b"43254365789590098765432a"
                  b"43254365789590098765432c"
                  b"43254365789590098765432b"
                  b"43254365789590098765432g")

        mem_out_stream = io.BytesIO()

        ec = EmuCrypt(CRYPT_STREAM_MODE_ENCRYPT, key, mem_out_stream, CRYPT_MODE_ONE)

        ec.write(secret[0:12])
        ec.write(secret[12:56])
        ec.write(secret[56:111])
        ec.write(secret[111:])
        ec.flush()

        mem_out_stream.seek(0)
        ciphertext = mem_out_stream.read()
        self.assertNotEqual(secret, ciphertext)
        plaintext = EmuCrypt.block_decrypt(key, ciphertext)
        self.assertEqual(secret, plaintext)


    def test_stream_encrypt_stream_decrypt(self):
        key = "a slightly better passphrase +_)((**&^%$#@!"

        secret = (b"fdasfdafdafadfadfdsafdasfasdfdsafadsfasdf"
                  b"FFFFFFFFFFFFFFFFFFFFFfff"
                  b"SSSSSSSSSSSSSSSSSSSSSSSs"
                  b"43254365789590098765432w"
                  b"43254365789590098765432d"
                  b"43254365789590098765432a"
                  b"43254365789590098765432c"
                  b"43254365789590098765432b"
                  b"43254365789590098765432gENDEND")

        mem_out_stream = io.BytesIO()

        ec = EmuCrypt(CRYPT_STREAM_MODE_ENCRYPT, key, mem_out_stream, CRYPT_MODE_ONE)

        ec.write(secret[0:12])
        ec.write(secret[12:56])
        ec.write(secret[56:111])
        ec.write(secret[111:])
        ec.flush()

        mem_out_stream.seek(0)
        ciphertext = mem_out_stream.read()

        mem_out_stream = io.BytesIO()
        self.assertNotEqual(secret, ciphertext)
        ec = EmuCrypt(CRYPT_STREAM_MODE_DECRYPT, key, mem_out_stream, CRYPT_MODE_ONE)

        ec.write(ciphertext[0:12])
        ec.write(ciphertext[12:56])
        ec.write(ciphertext[56:111])
        ec.write(ciphertext[111:])
        ec.flush()

        mem_out_stream.seek(0)
        plaintext = mem_out_stream.read()
        self.assertEqual(secret, plaintext)

    def test_stream_encrypt_stream_decrypt_mode_two_1024_keys(self):
        kem = ML_KEM_1024
        seed = os.urandom(64)

        ek, dk = kem.key_derive(seed)

        dks = dk_to_pem(kem, dk=dk)
        eks = ek_to_pem(kem, ek)

        kem, ek = ek_from_pem(eks)

        secret = (b"fdasfdafdafadfadfdsafdasfasdfdsafadsfasdf"
                  b"FFFFFFFFFFFFFFFFFFFFFfff"
                  b"SSSSSSSSSSSSSSSSSSSSSSSs"
                  b"43254365789590098765432w"
                  b"43254365789590098765432d"
                  b"43254365789590098765432a"
                  b"43254365789590098765432c"
                  b"43254365789590098765432b"
                  b"43254365789590098765432c"
                  b"43254365789590098765432b"
                  b"43254365789590098765432c"
                  b"43254365789590098765432b"
                  b"43254365789590098765432g")

        mem_out_stream = io.BytesIO()

        ec = EmuCrypt(CRYPT_STREAM_MODE_ENCRYPT, None, mem_out_stream, CRYPT_MODE_TWO, kem=kem, ek=ek)

        ec.write(secret[0:12])
        ec.write(secret[12:56])
        ec.write(secret[56:111])
        ec.write(secret[111:178])
        ec.write(secret[178:])
        ec.flush()

        mem_out_stream.seek(0)
        ciphertext = mem_out_stream.read()

        mem_out_stream = io.BytesIO()
        self.assertNotEqual(secret, ciphertext)

        kem, dk, _, _ = dk_from_pem(dks)

        ec = EmuCrypt(CRYPT_STREAM_MODE_DECRYPT, None, mem_out_stream, CRYPT_MODE_TWO, kem=kem, ek=dk)

        ec.write(ciphertext[0:12])
        ec.write(ciphertext[12:56])
        ec.write(ciphertext[56:111])
        ec.write(ciphertext[111:155])
        ec.write(ciphertext[155:249])
        ec.write(ciphertext[249:])
        ec.flush()

        mem_out_stream.seek(0)
        plaintext = mem_out_stream.read()
        self.assertEqual(secret, plaintext)


    def test_stream_encrypt_stream_decrypt_mode_two_512_keys(self):
        eks = "-----BEGIN PUBLIC KEY-----" \
             "MIIDMjALBglghkgBZQMEBAGAggMhAMy6w9Vpi0IDbPPZo3N5ekrxQs7LX3vxoe9osbI6a+18ZX9D" \
             "FjAAcVXYed9xbwjRnZoGI3ZBy9uZek4lqxXVE3y4NcCmCzbsNWiwxuQgbxZMHc30RqxmRLV5zv7E" \
             "ufW2GzeBl0oqryLFU7rQg/dLeoIQCp1iRoRFlRN2T5RpRWiQPZVjcLe5jLU6dAoWF1JXF1dTxNem" \
             "kx3lr4BLlD6CuPNpFVPFqNo1ugsZAdzzPY4IUSdiK633zOjiguUHSpjJvKXFzGfpxrAjcU0VYs0D" \
             "fZ6qrYp3bh00ZOMZahssv1XGfvOKMma2ThgVmDxzCHwEAWSEirlTLemXmY5Bzwgge6sxFConrjrw" \
             "PEnqPvNLp6dnV9RrIu6rgAB9Vd1pTOZmmN3RWrmMgjcnoHXEIl8hyS/qAP6gTAWGL0tUlBEcBXfr" \
             "H06ESuUCPED3QIwADGAGWkYZmUdriUIYB4AlA3eIqV5wPdPEZYiUBBIwxtDHlwyYJ+qDlNQSPCoZ" \
             "GhMGwLilPWc3UpkbY0DFj6a8up9ZhbRDHpHXZtqjYBvcdsjhZwocDflWjmWQcEp6wHqjxLs0hALB" \
             "YrPBsD54l0QBrswJTKHwjas7HxHJkA8hhEE2V1iskWBAdO6JaOJ6opdYLzAQd1CGWuZyc+d4CWtX" \
             "lpKVrB9gyyLYgl/1jXk5YC8YPe46c1Esx7dZMVUaRZtgUvOMkxHoetQ1HPC3G13GNNh0STAoCXeK" \
             "rYg8OqNxXaVIGZiGj+2LzYeaI1Nkw1VStq8lLHOBVbkYzeB7PtEMzdF0eTKVaGPaWbWwegzCzTGy" \
             "XP+3hS/Vz0vKpNlsNcobTbAZG/PLCLxokkGLufdEUoUDj65cox3ALR8aFbgMUaCSEK8XCNcKnOZG" \
             "zRgHmwrLw13GbsuqvTJ8jk1DrgdYhHOoDV+aaibKKQHghEeFccD1b/MQaRmDYl/0JPJBlgZMURl0" \
             "CVxJQRkQMO4WuZOnh6P6Ae7IkmG1xgSrhx71suUkymm0xIisn6bDw63LIjk7dAggBFeiLQ33YXdQ" \
             "08qcpeOTona1+welRGALC2uNsblT7RD9" \
             "-----END PUBLIC KEY-----"

        dks = "-----BEGIN PRIVATE KEY-----" \
            "MIIGvgIBADALBglghkgBZQMEBAEEggaqMIIGpgRA6WeezdJ0xW7dDK21y/tj2hlzsDHXbysRR7pz" \
            "M4lnAJPfU8m8TlI6c/55hsTcbVrAf+LnF99iB8n/PsfoiDQqEwSCBmA4iw5YMUmLdqZc62a5eRT5" \
            "fA/LvEe7YgAE3Cizgpi6VBCDCsIoR1km0sJHRbykkCWKlkkisXQqUphn1Ca00Lz32JVwaV+wZgfQ" \
            "ZDOKl2zl4Q4dkkxPtMxTJnVA/G495XbDyc7RgWHAhXipkMqvmy29ia6KWzqjAMmY9Gihmye4RkXJ" \
            "AlPg7Gc7IW1OUCXplBjQeZb/kBC/eS9sWj5T5LmiBTk647/JsFgjST5YqHHX2Exa03ERhjFP5qzM" \
            "fGTzqw984ht0yhxORJhgiwaIJce4lqWJ10NW7BPswKqZMiR1QhrLkaUoJZE56DbvI0N0pUIIabpY" \
            "CzRJpbriEKblhIumehcNSaUXVFO/iRII8yrhIhCZ+IFPRCWoAElPrKWg+TySQEn+Z7WTG7jrxqna" \
            "acKMMGRtuYGw+MIypI2+5BmAZVw+ShYsLG/iShmhxy4rdZJjEWF42JtJ0Ze+67AkpIrS25WA15v3" \
            "UaIuErl0GMYrewq3uigoKEX+qCQsNgudiMJUoq3OjFhF0BxrAIvly6Z3ioYsEl0IkpycQj7rZ3fh" \
            "ZCIKYmXquaSh6xw3d54iCn4TY7pB5i+TKM6KqlOv9r2aFl6qzHPj+DQQHBMlx87KZq8c2FKT7MWa" \
            "Zayg+0bi8ByTPJYXI5kXOHt4RB9icmIDG0oCEKvTWVsRMzREESmvgztmhaUEC2wrSVOv1ySdzJD1" \
            "JZ6IpWIHEbZ3k86rNpuqJG/SVwd+0oGLCotTWAJrcg6bVM/fS47BgXuSUcKHi6H9+nkahoDsYW2E" \
            "oKr4dsAIu5HgySr7KIW4IAa7CUtkrI8CeH/8C006tAMoNartA5FbdVZQ532WUEkv924o0BCZ1Yxq" \
            "U4w1pT7QAbNqEjnX24htOngL2Vbt+WLomTU9l4DjZbfKFonWAwPesIXMSSYz0A98FL2D+U3PfJtW" \
            "y1+XHJwIEQnb4w6Uu3f9YRe+AaUP+Rvt48aoiHzip8eEcbnAVadvN2BcNIGoUy4hEkyfuE8JAaPO" \
            "Qhr1BxS85bse6JfMusPVaYtCA2zz2aNzeXpK8ULOy1978aHvaLGyOmvtfGV/QxYwAHFV2HnfcW8I" \
            "0Z2aBiN2QcvbmXpOJasV1RN8uDXApgs27DVosMbkIG8WTB3N9EasZkS1ec7+xLn1ths3gZdKKq8i" \
            "xVO60IP3S3qCEAqdYkaERZUTdk+UaUVokD2VY3C3uYy1OnQKFhdSVxdXU8TXppMd5a+AS5Q+grjz" \
            "aRVTxajaNboLGQHc8z2OCFEnYiut98zo4oLlB0qYybylxcxn6cawI3FNFWLNA32eqq2Kd24dNGTj" \
            "GWobLL9Vxn7zijJmtk4YFZg8cwh8BAFkhIq5Uy3pl5mOQc8IIHurMRQqJ6468DxJ6j7zS6enZ1fU" \
            "ayLuq4AAfVXdaUzmZpjd0Vq5jII3J6B1xCJfIckv6gD+oEwFhi9LVJQRHAV36x9OhErlAjxA90CM" \
            "AAxgBlpGGZlHa4lCGAeAJQN3iKlecD3TxGWIlAQSMMbQx5cMmCfqg5TUEjwqGRoTBsC4pT1nN1KZ" \
            "G2NAxY+mvLqfWYW0Qx6R12bao2Ab3HbI4WcKHA35Vo5lkHBKesB6o8S7NIQCwWKzwbA+eJdEAa7M" \
            "CUyh8I2rOx8RyZAPIYRBNldYrJFgQHTuiWjieqKXWC8wEHdQhlrmcnPneAlrV5aSlawfYMsi2IJf" \
            "9Y15OWAvGD3uOnNRLMe3WTFVGkWbYFLzjJMR6HrUNRzwtxtdxjTYdEkwKAl3iq2IPDqjcV2lSBmY" \
            "ho/ti82HmiNTZMNVUravJSxzgVW5GM3gez7RDM3RdHkylWhj2lm1sHoMws0xslz/t4Uv1c9LyqTZ" \
            "bDXKG02wGRvzywi8aJJBi7n3RFKFA4+uXKMdwC0fGhW4DFGgkhCvFwjXCpzmRs0YB5sKy8Ndxm7L" \
            "qr0yfI5NQ64HWIRzqA1fmmomyikB4IRHhXHA9W/zEGkZg2Jf9CTyQZYGTFEZdAlcSUEZEDDuFrmT" \
            "p4ej+gHuyJJhtcYEq4ce9bLlJMpptMSIrJ+mw8OtyyI5O3QIIARXoi0N92F3UNPKnKXjk6J2tfsH" \
            "pURgCwtrjbG5U+0Q/YrQ1MXr+X+V/Veon/n8bPRxOIeyH8NGAS3GfLiwHnVj31PJvE5SOnP+eYbE" \
            "3G1awH/i5xffYgfJ/z7H6Ig0KhM=" \
            "-----END PRIVATE KEY-----"

        kem, ek = ek_from_pem(eks)

        secret = (b"fdasfdafdafadfadfdsafdasfasdfdsafadsfasdf"
                  b"FFFFFFFFFFFFFFFFFFFFFfff"
                  b"SSSSSSSSSSSSSSSSSSSSSSSs"
                  b"43254365789590098765432w"
                  b"43254365789590098765432d"
                  b"43254365789590098765432a"
                  b"43254365789590098765432c"
                  b"43254365789590098765432b"
                  b"43254365789590098765432g")

        mem_out_stream = io.BytesIO()

        ec = EmuCrypt(CRYPT_STREAM_MODE_ENCRYPT, None, mem_out_stream, CRYPT_MODE_TWO, kem=kem, ek=ek)

        ec.write(secret[0:12])
        ec.write(secret[12:56])
        ec.write(secret[56:111])
        ec.write(secret[111:])
        ec.flush()

        mem_out_stream.seek(0)
        ciphertext = mem_out_stream.read()

        mem_out_stream = io.BytesIO()
        self.assertNotEqual(secret, ciphertext)

        kem, dk, _, _ = dk_from_pem(dks)

        ec = EmuCrypt(CRYPT_STREAM_MODE_DECRYPT, None, mem_out_stream, CRYPT_MODE_TWO, kem=kem, ek=dk)

        ec.write(ciphertext[0:12])
        ec.write(ciphertext[12:56])
        ec.write(ciphertext[56:111])
        ec.write(ciphertext[111:])
        ec.flush()

        mem_out_stream.seek(0)
        plaintext = mem_out_stream.read()
        self.assertEqual(secret, plaintext)

    def test_block_encrypt_block_decrypt_fast(self):
        key = "bad_password"
        secret = "this text is really secret 010101"

        ciphertext = EmuCrypt.block_encrypt(key, secret)
        self.assertNotEqual(secret.encode('utf-8'), ciphertext)

        plaintext = EmuCrypt.block_decrypt(key, ciphertext, fast=True)
        self.assertEqual(secret, plaintext.decode('utf-8'))


    def test_block_encrypt_fast_block_decrypt(self):
        key = "bad_password"
        secret = "this text is really secret 010101"

        ciphertext = EmuCrypt.block_encrypt(key, secret, fast=True)
        self.assertNotEqual(secret.encode('utf-8'), ciphertext)

        plaintext = EmuCrypt.block_decrypt(key, ciphertext)
        self.assertEqual(secret, plaintext.decode('utf-8'))

