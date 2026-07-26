from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from config import (
    PRIVATE_KEY_FILE,
    PUBLIC_KEY_FILE,
    RSA_KEY_SIZE,
)


def generate_keys():
    """
    Generates an RSA key pair.

    Creates:
        private_key.pem
        public_key.pem

    Run this only once.
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )

    public_key = private_key.public_key()

    # Save Private Key
    with open(PRIVATE_KEY_FILE, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save Public Key
    with open(PUBLIC_KEY_FILE, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("\nRSA Keys Generated Successfully")
    print(f"Private Key : {PRIVATE_KEY_FILE}")
    print(f"Public Key  : {PUBLIC_KEY_FILE}")


if __name__ == "__main__":
    generate_keys()