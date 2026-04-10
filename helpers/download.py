import boto3
from helpers.estream import Estream
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

def raw_multipart_download(bucket, key, output_path, part_size):
    if part_size < 4096:
        raise ValueError("Part size should be larger with how ecrypto has been implemented")
    s3 = boto3.client('s3')

    # Get object metadata (e.g., content length)
    head = s3.head_object(Bucket=bucket, Key=key)
    total_size = head['ContentLength']
    amount_read = 0

    with open(output_path, 'wb') as f:
        while amount_read < total_size:
            end_range = min(amount_read + part_size - 1, total_size - 1)
            response = s3.get_object(
                Bucket=bucket,
                Key=key,
                Range=f'bytes={amount_read}-{end_range}'
            )
            chunk = response['Body'].read()

            f.write(chunk)
            amount_read += len(chunk)

    print("Download and decryption complete")