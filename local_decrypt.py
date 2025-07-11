import argparse
import datetime
import os.path

from helpers.estream import Estream
from ecrypto.asyn.ml_kem.pkcs import dk_from_pem
from ecrypto.emu_crypt import EmuCrypt, CRYPT_MODE_TWO, CRYPT_STREAM_MODE_DECRYPT

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

    print("Local decryption complete")

def main():
    parser = argparse.ArgumentParser(description="Decrypt a file on disk.")
    parser.add_argument("input_path", help="Name of the S3 bucket")
    parser.add_argument("output_path", help="Local path to save the decrypted file")
    parser.add_argument("decryption_pem", help="Local path to PEM file for decryption")
    parser.add_argument("--chunk_size", type=int, default=8, help="Chunk size in MB (default: 8MB)")
    parser.add_argument("--hardware", type=bool, default=True, help="Setting to False doesn't require "
                                                                        "the cryptography package but is significantly "
                                                                        "slower. "
                                                                        "Only set to true for very small (kb) files.")
    args = parser.parse_args()
    part_size = args.chunk_size * 1024 * 1024

    # Only supporting mode 2
    dk_string = ""
    with open(args.decryption_pem, 'r') as file:
        dk_string = file.read()
    kem, dk, _, _ = dk_from_pem(dk_string)

    print("Starting timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    chunk_decrypt(args.input_path, args.output_path, part_size, dk, kem, hardware=args.hardware)
    print("Ending timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

if __name__ == "__main__":
    main()