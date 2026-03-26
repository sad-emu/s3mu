import argparse
import datetime
from helpers import download, async_keys

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
    kem, dk, _, _ = async_keys.get_decryption_key_from_pem(dk_string)

    print("Starting timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    download.multipart_download(args.bucket_name, args.key, args.output_path, part_size, dk, kem, hardware=args.hardware)
    print("Ending timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

if __name__ == "__main__":
    main()