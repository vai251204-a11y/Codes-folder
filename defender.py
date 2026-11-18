import subprocess
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

BROKER = "localhost"
PORT = 1883
TOPIC_MSG = "/drone/channel"
TOPIC_SIG = "/drone/channel_sig"
TOKENS_FILE = "tokens.txt"
PUBLIC_FILE = "public_key.pem"
REJECT_LOG = "rejected.txt"
LOOKAHEAD = 10

PUBLIC_KEY = serialization.load_pem_public_key(open(PUBLIC_FILE, "rb").read())
TOKENS = [t.strip() for t in open(TOKENS_FILE) if t.strip()]


def verify(signed_string, sig_hex):
    try:
        sig = bytes.fromhex(sig_hex)
        if len(sig) != 64:
            return False
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        PUBLIC_KEY.verify(encode_dss_signature(r, s), signed_string.encode(),
                          ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def log_reject(command, sig_hex, reason):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}\tREJECTED\t{reason}\tcmd={command}\tsig={sig_hex}\n"
    with open(REJECT_LOG, "a") as f:
        f.write(line)
    print(line.strip())


def main():
    idx = 0
    pending_msg = None
    cmd = ["mosquitto_sub", "-h", BROKER, "-p", str(PORT),
           "-t", TOPIC_MSG, "-t", TOPIC_SIG, "-q", "1", "-v"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
    print(f"defender watching the bus; rejects go to {REJECT_LOG}")

    for line in proc.stdout:
        topic, _, payload = line.rstrip("\n").partition(" ")
        if topic == TOPIC_MSG:
            pending_msg = payload
            continue
        sig_hex = payload
        if pending_msg is None:
            log_reject("", sig_hex, "signature-with-no-message")
            continue
        command, pending_msg = pending_msg, None

        matched = None
        for j in range(idx, idx + LOOKAHEAD + 1):
            if verify(f"{command}|{TOKENS[j % len(TOKENS)]}", sig_hex):
                matched = j
                break
        if matched is not None:
            idx = (matched + 1) % len(TOKENS)
            print(f"ok      cmd={command} (token #{matched % len(TOKENS)})")
        else:
            log_reject(command, sig_hex, "bad-signature-or-replay")

    proc.terminate()


if __name__ == "__main__":
    main()
