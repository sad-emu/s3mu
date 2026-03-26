from helpers.estream import Estream
from ecrypto.emu_crypt import EmuCrypt, CRYPT_MODE_TWO, CRYPT_STREAM_MODE_DECRYPT
import os.path

def chunk_decrypt(input_path, output_path, part_size, ek, kem, hardware=True):
    if part_size < 4096:
        raise ValueError("Part size should be larger with how ecrypto has been implemented")

    total_size = os.path.getsize(input_path)
    amount_read = 0

    # Prepare decryption stream
    outstream = Estream(part_size*3)
    ecrypt = EmuCrypt(CRYPT_STREAM_MODE_DECRYPT, crypt_mode=CRYPT_MODE_TWO, ek=ek, kem=kem, output_stream=outstream,
                      hardware=hardware)

    with open(input_path, 'rb') as fi:
        with open(output_path, 'wb+') as fo:
            while amount_read < total_size:
                chunk = fi.read(part_size)

                ecrypt.write(chunk)

                if len(outstream) > 0:
                    fo.write(outstream.pop(len(outstream)))
                amount_read += len(chunk)

            # Flush final bytes
            ecrypt.flush()
            if len(outstream) > 0:
                fo.write(outstream.pop(len(outstream)))

    #print("Local decryption complete")