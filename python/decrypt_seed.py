

#!/usr/bin/env python3
"""
decrypt_seed.py — decrypts blobs produced by seed_encrypt.py / seedcrypt.html
Format: [MAGIC "SEEDv1" | salt(16) | nonce(12) | tag(16) | ciphertext]
"""
from __future__ import annotations

from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac
import argparse
import getpass
import os
import sys

MAGIC = b"SEEDv1"
PBKDF2_ITERS = 200_000


def derive_key(password: str, salt: bytes) -> bytes:
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)


def load_blob(path: str):
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(MAGIC):
        raise ValueError("File does not start with SEEDv1 header")
    i = len(MAGIC)
    if len(data) < i + 16 + 12 + 16 + 1:
        raise ValueError("Blob is truncated")
    salt  = data[i:i+16]; i += 16
    nonce = data[i:i+12]; i += 12
    tag   = data[i:i+16]; i += 16
    ct    = data[i:]
    return salt, nonce, tag, ct


def decrypt_blob(blob_path: str, password: str) -> bytes:
    salt, nonce, tag, ct = load_blob(blob_path)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt


def write_secret(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Decrypt seed.enc produced by seed_encrypt.py / seedcrypt.html")
    ap.add_argument("blob", nargs="?", default="seed.enc", help="input encrypted blob (default: seed.enc)")
    ap.add_argument("--out", help="write plaintext to file (0600). If omitted, prints to stdout")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    password = getpass.getpass("\U0001F511 Enter encryption password: ")

    try:
        plaintext = decrypt_blob(args.blob, password)
    except Exception as e:
        print(f"[!] Decryption failed: {e}", file=sys.stderr)
        return 2

    if args.out:
        write_secret(args.out, plaintext)
        print(f"✅ Decrypted seed written to '{args.out}' (0600).")
    else:
        # Print as UTF-8 if possible, otherwise raw bytes
        try:
            print(plaintext.decode("utf-8").strip())
        except UnicodeDecodeError:
            sys.stdout.buffer.write(plaintext)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        try:
            sys.stderr.close()
        except Exception:
            pass
        raise SystemExit(0)