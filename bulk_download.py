import argparse
import datetime
from helpers import download

def main():
    parser = argparse.ArgumentParser(description="Download and decrypt a full s3 bucket")
    parser.add_argument("bucket_name", help="Name of the S3 bucket")
    parser.add_argument("key", help="S3 object key (source path)")
    parser.add_argument("output_path", help="Local path store the downloaded files")
    parser.add_argument("--chunk_size", type=int, default=8, help="Chunk size in MB (default: 8MB)")

    args = parser.parse_args()
    part_size = args.chunk_size * 1024 * 1024

    # Raw files no decryption
    # Use BOTO3 to list all objects in the bucket
    print("Starting timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    s3 = boto3.client('s3')
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=args.bucket_name, Prefix=args.key):
        for obj in page.get('Contents', []):
            print(f"Processing {obj['Key']}...")
            key = obj['Key']
            output_path = os.path.join(args.output_path, os.path.relpath(key, args.key))
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            download.raw_multipart_download(args.bucket_name, key, output_path, part_size)
            print((f"Downloaded {key} to {output_path}"))


    # download.multipart_download(args.bucket_name, args.key, args.output_path, part_size, dk, kem, hardware=args.hardware)
    print("Ending timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

if __name__ == "__main__":
    main()