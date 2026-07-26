import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from config import PUBLIC_KEY_FILE


def load_public_key():
    """
    Load the RSA public key.
    """
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read()
        )


def verify_license(license_file):

    if not Path(license_file).exists():
        print("License file not found.")
        return

    with open(license_file, "r", encoding="utf-8") as file:
        license_data = json.load(file)

    payload = license_data.get("payload")
    signature = license_data.get("signature")

    if payload is None or signature is None:
        print("Invalid license format.")
        return

    payload_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    signature_bytes = base64.b64decode(signature)

    public_key = load_public_key()

    try:

        public_key.verify(

            signature_bytes,

            payload_bytes,

            padding.PSS(

                mgf=padding.MGF1(hashes.SHA256()),

                salt_length=padding.PSS.MAX_LENGTH

            ),

            hashes.SHA256()

        )

        print("\nLICENSE VERIFIED SUCCESSFULLY\n")

        print("------------------------------------")
        print(f"Company     : {payload['company_name']}")
        print(f"Domain      : {payload['domain']}")
        print(f"Issued On   : {payload['issued_on']}")
        print(f"Expires On  : {payload['expires_on']}")
        print("------------------------------------")

    except InvalidSignature:

        print("\nINVALID LICENSE SIGNATURE")


if __name__ == "__main__":

    path = input("License File : ").strip()

    verify_license(path)