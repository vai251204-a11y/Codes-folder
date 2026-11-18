import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PRIVATE_FILE = "private_key.pem"

with open(PRIVATE_FILE, "rb") as _f:
    _PRIV = serialization.load_pem_private_key(_f.read(), password=None)


def sign(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    der = _PRIV.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


if __name__ == "__main__":
    msg = sys.argv[1] if len(sys.argv) > 1 else "90"
    print(f"message:   {msg}")
    print(f"signature: {sign(msg)}")
