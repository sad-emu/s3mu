import boto3
import os
import argparse
import datetime
from helpers.estream import Estream
from ecrypto.asyn.ml_kem.pkcs import ek_from_pem
from ecrypto.emu_crypt import EmuCrypt, CRYPT_MODE_TWO, CRYPT_STREAM_MODE_ENCRYPT

def multipart_upload(file_path, bucket, key, part_size, ek, kem):
    if part_size < 4096:
        raise ValueError("Part size should be larger with how ecrypto has been implemented")
    s3 = boto3.client('s3')
    file_size = os.path.getsize(file_path)
    amount_read = 0
    mpu = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = mpu['UploadId']
    parts = []
    outstream = Estream(part_size*3)
    ecrypt = EmuCrypt(CRYPT_STREAM_MODE_ENCRYPT, crypt_mode=CRYPT_MODE_TWO, ek=ek, kem=kem, output_stream=outstream)
    flushed = False

    try:
        with open(file_path, 'rb') as f:
            part_number = 1
            last = False
            while amount_read < file_size or last:
                data = f.read(part_size)

                if len(data) < part_size or amount_read == file_size:
                    last = True # We might need to run twice to flush

                amount_read += len(data)

                if len(data) != 0:
                    ecrypt.write(data)

                if last and not flushed:
                    ecrypt.flush() # We are done
                    flushed = True

                if len(outstream) < part_size and not last:
                    continue # go again till we have enough data

                push_data = outstream.pop(part_size)

                if len(push_data) == 0:
                    break

                response = s3.upload_part(
                    Bucket=bucket,
                    Key=key,
                    PartNumber=part_number,
                    UploadId=upload_id,
                    Body=push_data
                )
                parts.append({
                    'PartNumber': part_number,
                    'ETag': response['ETag']
                })
                print(f"Uploaded part {part_number}")
                part_number += 1

        s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={'Parts': parts}
        )
        print("Upload complete")

    except Exception as e:
        print(f"Error: {e}")
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        print("Upload aborted")

def main():
    parser = argparse.ArgumentParser(description="Upload a file to S3 using multipart upload.")
    parser.add_argument("file_path", help="Path to the local file")
    parser.add_argument("bucket_name", help="Name of the S3 bucket")
    parser.add_argument("key", help="S3 object key (destination path)")
    parser.add_argument("encryption_pem", help="Local path to PEM file for encryption")
    parser.add_argument("--chunk-size", type=int, default=8, help="Chunk size in MB (default: 8MB)")
    parser.add_argument("--encrypt", type=int, default=2, help="Modes: "
                                                                           "0 = none, "
                                                                           "1 = Sync with preshared key, "
                                                                           "2 = Async with kyber")
    args = parser.parse_args()
    part_size = args.chunk_size * 1024 * 1024

    # if mode 1 - get sync key from config
    if args.encrypt != 2:
        raise ValueError("Only crypt mode 2 has been implemented")

    # if mode 2 - get async key from current directory
    ek_string = ""
    with open(args.encryption_pem, 'r') as file:
        ek_string = file.read()
    kem, ek = ek_from_pem(ek_string)
    print("Starting timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    multipart_upload(args.file_path, args.bucket_name, args.key, part_size, ek, kem)
    print("Ending timestamp:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

if __name__ == "__main__":
    main()