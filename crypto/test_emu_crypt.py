import unittest
import io

from crypto.emu_crypt import EmuCrypt, CRYPT_STREAM_MODE_ENCRYPT, CRYPT_MODE_ONE, CRYPT_STREAM_MODE_DECRYPT


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


