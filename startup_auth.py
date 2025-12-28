import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# file paths
LICENSE_FILE = Path("license.json")
LICENSE_SIG = Path("license.sig")
PUBLIC_KEY = Path("rootCA.pem")

def verify_license():
    # basic file existence check
    if not LICENSE_FILE.exists() or not LICENSE_SIG.exists() or not PUBLIC_KEY.exists():
        print("❌ Authentication failed: license or key missing.")
        sys.exit(1)

    # read files
    license_data = LICENSE_FILE.read_bytes()
    signature = LICENSE_SIG.read_bytes()

    try:
        # load public key
        public_key = serialization.load_pem_public_key(
            PUBLIC_KEY.read_bytes(), backend=default_backend()
        )
        # verify
        public_key.verify(
            signature,
            license_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("License verification successful.")
    except Exception as e:
        print("Invalid license signature.")
        sys.exit(1)
