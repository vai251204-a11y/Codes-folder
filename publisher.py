import os
import subprocess
import sys
from signer import sign

BROKER = "localhost"
PORT = 1883
TOPIC_MSG = "/drone/channel"
TOPIC_SIG = "/drone/channel_sig"
TOKENS_FILE = "tokens.txt"
IDX_FILE = "pub_idx.txt"


def load_tokens():
    return [t.strip() for t in open(TOKENS_FILE) if t.strip()]


def load_idx():
    if os.path.exists(IDX_FILE):
        return int(open(IDX_FILE).read().strip() or 0)
    return 0


def save_idx(i):
    with open(IDX_FILE, "w") as f:
        f.write(str(i))


def publish(topic, payload):
    subprocess.run(["mosquitto_pub", "-h", BROKER, "-p", str(PORT),
                    "-t", topic, "-m", payload, "-q", "1"], check=True)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "90"
    if command == "reset":
        save_idx(0)
        print("publisher index reset to 0")
        return
    tokens = load_tokens()
    idx = load_idx() % len(tokens)
    signed_string = f"{command}|{tokens[idx]}"
    sig = sign(signed_string)
    try:
        publish(TOPIC_MSG, command)
        publish(TOPIC_SIG, sig)
    except FileNotFoundError:
        sys.exit("mosquitto_pub not found. Run: sudo apt install mosquitto-clients")
    except subprocess.CalledProcessError:
        sys.exit(f"could not publish. Is the broker running at {BROKER}:{PORT}?")
    save_idx((idx + 1) % len(tokens))
    print(f"sent command '{command}' with token #{idx}")


if __name__ == "__main__":
    main()
