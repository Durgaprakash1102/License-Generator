import base64
import json
from datetime import date, datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from config import PRIVATE_KEY_FILE, OUTPUT_DIR


def load_private_key():
    """
    Load the RSA private key.
    """
    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


def create_payload(company_name, domain, expires_on):
    """
    Create the license payload.
    """

    try:
        datetime.strptime(expires_on, "%Y-%m-%d")
    except ValueError:
        raise ValueError(
            "Expiry date must be in YYYY-MM-DD format."
        )

    return {
        "company_name": company_name.strip(),
        "domain": domain.strip().lower(),
        "issued_on": str(date.today()),
        "expires_on": expires_on,
    }


def sign_payload(payload):
    """
    Digitally sign the payload.
    """

    private_key = load_private_key()

    payload_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    signature = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode()


def save_license(payload, signature):
    """
    Save the signed license.
    """

    license_data = {
        "payload": payload,
        "signature": signature,
    }

    filename = (
        payload["company_name"]
        .replace(" ", "_")
        .replace("/", "_")
        .lower()
        + ".lic"
    )

    filepath = OUTPUT_DIR / filename

    with open(filepath, "w", encoding="utf-8") as file:
        json.dump(
            license_data,
            file,
            indent=4
        )

    return filepath


def generate_license():
    """
    Interactive license generation.
    """

    print("=" * 50)
    print("LICENSE GENERATOR")
    print("=" * 50)

    company_name = input("Company Name : ").strip()

    while not company_name:
        company_name = input("Company Name cannot be empty : ").strip()

    domain = input("Licensed Domain : ").strip().lower()

    while not domain:
        domain = input("Domain cannot be empty : ").strip().lower()

    expires_on = input("Expiry Date (YYYY-MM-DD): ").strip()

    payload = create_payload(
        company_name,
        domain,
        expires_on,
    )

    signature = sign_payload(payload)

    path = save_license(
        payload,
        signature,
    )

    print("\nLicense generated successfully.\n")
    print(f"License File : {path}")


if __name__ == "__main__":
    generate_license()