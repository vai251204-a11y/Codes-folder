import secrets
import subprocess
import sys
import time

BROKER = "localhost"
PORT = 1883
TOPIC_MSG = "/drone/channel"
TOPIC_SIG = "/drone/channel_sig"
TRY_LOG = "tried.txt"


def log_try(kind, command, sig_hex):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{kind}\tcmd={command}\tsig={sig_hex}\n"
    with open(TRY_LOG, "a") as f:
        f.write(line)
    print("tried:", line.strip())


def publish(topic, payload):
    subprocess.run(["mosquitto_pub", "-h", BROKER, "-p", str(PORT),
                    "-t", topic, "-m", payload, "-q", "1"], check=True)


def send_pair(kind, command, sig_hex):
    publish(TOPIC_MSG, command)
    publish(TOPIC_SIG, sig_hex)
    log_try(kind, command, sig_hex)


def sniff_pair(timeout=60):
    print("sniffing one genuine command... (run publisher.py on the Pi now)")
    proc = subprocess.Popen(["mosquitto_sub", "-h", BROKER, "-p", str(PORT),
                             "-t", TOPIC_MSG, "-t", TOPIC_SIG, "-q", "1", "-v"],
                            stdout=subprocess.PIPE, text=True, bufsize=1)
    msg = sig = None
    deadline = time.time() + timeout
    for line in proc.stdout:
        topic, _, payload = line.rstrip("\n").partition(" ")
        if topic == TOPIC_MSG:
            msg = payload
        elif topic == TOPIC_SIG:
            sig = payload
        if msg and sig:
            break
        if time.time() > deadline:
            break
    proc.terminate()
    if not (msg and sig):
        sys.exit("captured nothing; send a genuine command while this runs")
    print(f"captured: command={msg}  signature={sig[:32]}...")
    return msg, sig


def flip_one_bit(sig_hex):
    b = bytearray.fromhex(sig_hex)
    b[0] ^= 0x01
    return b.hex()


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    genuine_cmd, genuine_sig = sniff_pair()

    if which in ("all", "replay"):
        print("\n[1] REPLAY: resending the genuine pair unchanged")
        send_pair("replay", genuine_cmd, genuine_sig)
        time.sleep(0.5)
    if which in ("all", "flip"):
        print("\n[2] FLIP: same command, one bit of the signature changed")
        send_pair("flip", genuine_cmd, flip_one_bit(genuine_sig))
        time.sleep(0.5)
    if which in ("all", "forge"):
        print("\n[3] FORGE: made-up command with a random signature")
        send_pair("forge", "180", secrets.token_hex(64))
        time.sleep(0.5)

    print(f"\nattempts logged to {TRY_LOG}. Compare with rejected.txt on the Pi.")


if __name__ == "__main__":
    main()
