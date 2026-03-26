import setuptools
setuptools.setup(
     name="s3mu",
     version="0.0.1",
     python_requires=">=3.12",
     packages=["ecrypto", "helpers", "ehash"],
     install_requires=["boto3", "cryptography"],
)