# s3mu

This package is for a hobby project. Use at your own risk.

Designed to handle encryption and s3 upload/downloads.

### How to use
1. Generate ek and dk -> python3 -m ecrypto.asyn.scripts.keygen --dk /path/to/dk --ek /path/to/ek --kem ML-KEM-1024
2. Upload -> /path/to/file/to/upload.mkv awsbucketname aws/bucket/path.mkv.enc /path/to/ek
3. Download -> awsbucketname aws/bucket/path.mkv.enc /path/to/location/after/download.mkv  /path/to/dk

### Requirements
python 3.x (only tested on latest)

boto3 for s3 handling

cryptography for speeding up AES (Not required but recommended & on by default)

### Credits (Licences at source locations in this repo)
#### e(mu)crypto
1. AES - MIT Licence - https://github.com/boppreh/aes
2. KYBER - MIT Licence - https://github.com/GiacomoPope/kyber-py

#### s3mu
None