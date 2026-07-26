from pathlib import Path

# Base directory of the license generator project
BASE_DIR = Path(__file__).resolve().parent

# RSA Key Files
PRIVATE_KEY_FILE = BASE_DIR / "private_key.pem"
PUBLIC_KEY_FILE = BASE_DIR / "public_key.pem"

# Output directory for generated licenses
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Default signing algorithm
RSA_KEY_SIZE = 2048
SIGNING_ALGORITHM = "SHA256"