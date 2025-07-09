import boto3
import argparse
import datetime
from helpers.estream import Estream
from ecrypto.asyn.ml_kem.pkcs import dk_from_pem
from ecrypto.emu_crypt import EmuCrypt, CRYPT_MODE_TWO, CRYPT_STREAM_MODE_DECRYPT

def multipart_download(bucket, key, output_path, part_size, ek, kem, hardware=True):
    if part_size < 4096:
        raise ValueError("Part size should be larger with how ecrypto has been implemented")
    s3 = boto3.client('s3')

    # Get object metadata (e.g., content length)
    head = s3.head_object(Bucket=bucket, Key=key)
    total_size = head['ContentLength']
    amount_read = 0

    # Prepare decryption stream
    instream = Estream(part_size*3)
    ecrypt = EmuCrypt(CRYPT_STREAM_MODE_DECRYPT, crypt_mode=CRYPT_MODE_TWO, ek=ek, kem=kem, output_stream=instream,
                      hardware=hardware)

    with open(output_path, 'wb') as f:
        while amount_read < total_size:
            end_range = min(amount_read + part_size - 1, total_size - 1)
            response = s3.get_object(
                Bucket=bucket,
                Key=key,
                Range=f'bytes={amount_read}-{end_range}'
            )
            chunk = response['Body'].read()
            ecrypt.write(chunk)
            if len(instream) > 0:
                data = instream.pop(len(instream))
                if data:
                    f.write(data)
            amount_read += len(chunk)

        # Flush final bytes
        ecrypt.flush()
        if data:
            f.write(instream.pop(len(instream)))

    print("Download and decryption complete")

def main():
    parser = argparse.ArgumentParser(description="Download and decrypt a file from S3.")
    parser.add_argument("bucket_name", help="Name of the S3 bucket")
    parser.add_argument("key", help="S3 object key (source path)")
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
    multipart_download(args.bucket_name, args.key, args.output_path, part_size, dk, kem, hardware=args.hardware)
    print("Ending timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

if __name__ == "__main__":
    main()