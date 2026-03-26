import setuptools
setuptools.setup(
     name="s3mu",
     version="0.0.1",
     python_requires=">=3.12",
     packages=["ecrypto", "helpers", "ecrypto.hash"],
     install_requires=["boto3", "cryptography"],
)