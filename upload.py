import argparse
import datetime
from helpers import upload, async_keys

def main():
    parser = argparse.ArgumentParser(description="Upload a file to S3 using multipart upload.")
    parser.add_argument("file_path", help="Path to the local file")
    parser.add_argument("bucket_name", help="Name of the S3 bucket")
    parser.add_argument("key", help="S3 object key (destination path)")
    parser.add_argument("encryption_pem", help="Local path to PEM file for encryption")
    parser.add_argument("--chunk_size", type=int, default=8, help="Chunk size in MB (default: 8MB)")
    parser.add_argument("--encrypt", type=int, default=2, help="Modes: "
                                                                           "0 = none, "
                                                                           "1 = Sync with preshared key, "
                                                                           "2 = Async with kyber")
    parser.add_argument("--hardware", type=bool, default=True, help="Setting to False doesn't require "
                                                                        "the cryptography package but is significantly "
                                                                        "slower. "
                                                                        "Only set to false for very small (kb) files.")
    args = parser.parse_args()
    part_size = args.chunk_size * 1024 * 1024

    # if mode 1 - get sync key from config
    if args.encrypt != 2:
        raise ValueError("Only crypt mode 2 has been implemented")

    # if mode 2 - get async key from current directory
    ek_string = ""
    with open(args.encryption_pem, 'r') as file:
        ek_string = file.read()
    kem, ek = async_keys.get_encryption_key_from_pem(ek_string)
    print("Starting timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    upload.multipart_upload(args.file_path, args.bucket_name, args.key, part_size, ek, kem, hardware=args.hardware)
    print("Ending timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

if __name__ == "__main__":
    main()