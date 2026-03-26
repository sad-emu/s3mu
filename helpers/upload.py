import boto3
import os
from helpers.estream import Estream
from ecrypto.emu_crypt import EmuCrypt, CRYPT_MODE_TWO, CRYPT_STREAM_MODE_ENCRYPT

def multipart_upload(file_path, bucket, key, part_size, ek, kem, hardware=True):
    if part_size < 4096:
        raise ValueError("Part size should be larger with how ecrypto has been implemented")
    s3 = boto3.client('s3')
    file_size = os.path.getsize(file_path)
    total_parts = file_size / part_size
    amount_read = 0
    mpu = s3.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = mpu['UploadId']
    parts = []
    outstream = Estream(part_size*3)
    ecrypt = EmuCrypt(CRYPT_STREAM_MODE_ENCRYPT, crypt_mode=CRYPT_MODE_TWO, ek=ek, kem=kem, output_stream=outstream,
                      hardware=hardware)
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
                print(f"Uploaded part {part_number} of {total_parts}")
                part_number += 1

        s3.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={'Parts': parts}
        )
        print("Upload complete!")

    except Exception as e:
        print(f"Error: {e}")
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        print("Upload aborted")