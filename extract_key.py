import argparse
import hashlib
import hmac
import sys
import time


def recover_key(dump, message, tag_hex, keylen, align):
    want = bytes.fromhex(tag_hex.strip())
    tested = 0
    last = len(dump) - keylen
    for off in range(0, last + 1, align):
        window = dump[off:off + keylen]
        tested += 1
        tag = hmac.new(window, message, hashlib.sha256).digest()
        if hmac.compare_digest(tag, want):
            return off, window, tested
    return None, None, tested


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--message", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--keylen", type=int, default=16)
    ap.add_argument("--align", type=int, default=1)
    args = ap.parse_args()

    with open(args.dump, "rb") as f:
        dump = f.read()
    print(f"dump: {len(dump):,} bytes, searching for a {args.keylen}-byte key, step {args.align}")

    t0 = time.time()
    off, key, tested = recover_key(dump, args.message.encode(), args.tag, args.keylen, args.align)
    if key is None and args.align != 1:
        print(f"nothing at step {args.align}, falling back to a full scan...")
        off, key, more = recover_key(dump, args.message.encode(), args.tag, args.keylen, 1)
        tested += more
    dt = time.time() - t0

    if key is None:
        print(f"no key found ({tested:,} windows tested in {dt:.1f}s)")
        sys.exit(1)

    print(f"\nKEY FOUND at offset {hex(off)} after {tested:,} windows in {dt:.1f}s")
    print(f"key (hex): {key.hex()}")
    print(f"C array:   const uint8_t SECRET_KEY[{args.keylen}] = {{" + ", ".join(f"0x{b:02x}" for b in key) + "};")


if __name__ == "__main__":
    main()
