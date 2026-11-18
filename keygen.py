import os
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PRIVATE_FILE = "private_key.pem"
PUBLIC_FILE = "public_key.pem"
TOKENS_FILE = "tokens.txt"
NUM_TOKENS = 100
TOKEN_BYTES = 8


def main():
    if os.path.exists(PRIVATE_FILE):
        print(f"{PRIVATE_FILE} already exists, not overwriting it.")
        priv = serialization.load_pem_private_key(open(PRIVATE_FILE, "rb").read(), password=None)
    else:
        priv = ec.generate_private_key(ec.SECP256R1())
        with open(PRIVATE_FILE, "wb") as f:
            f.write(priv.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        os.chmod(PRIVATE_FILE, 0o600)
        print(f"Wrote {PRIVATE_FILE}")

    pub = priv.public_key()
    with open(PUBLIC_FILE, "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM,
                                 serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Wrote {PUBLIC_FILE}")

    if os.path.exists(TOKENS_FILE):
        print(f"{TOKENS_FILE} already exists, not overwriting it.")
        tokens = [t.strip() for t in open(TOKENS_FILE) if t.strip()]
    else:
        tokens = [secrets.token_hex(TOKEN_BYTES) for _ in range(NUM_TOKENS)]
        with open(TOKENS_FILE, "w") as f:
            f.write("\n".join(tokens) + "\n")
        print(f"Wrote {TOKENS_FILE} ({NUM_TOKENS} tokens)")

    raw = pub.public_bytes(serialization.Encoding.X962,
                           serialization.PublicFormat.UncompressedPoint)
    print("\n=== paste into the ESP8266 sketch ===")
    print("const uint8_t PUBLIC_KEY[65] = {" + ", ".join(f"0x{b:02x}" for b in raw) + "};")
    print(f"\nconst char* TOKENS[{NUM_TOKENS}] = {{")
    for i in range(0, NUM_TOKENS, 4):
        row = ", ".join(f'"{t}"' for t in tokens[i:i+4])
        print("  " + row + ("," if i + 4 < NUM_TOKENS else ""))
    print("};")
    print("\nNever copy private_key.pem off the Pi.")


if __name__ == "__main__":
    main()
