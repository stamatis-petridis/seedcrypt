

#!/usr/bin/env python3
"""
seed_encrypt.py — visible seed input, AES‑256‑GCM encryption, PBKDF2‑SHA256 KDF
Blob format compatible with seedcrypt.html and decrypt_seed.py:
[MAGIC "SEEDv1" | salt(16) | nonce(12) | tag(16) | ciphertext]
"""
from __future__ import annotations

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import pbkdf2_hmac
import argparse
import getpass
import hashlib
import os
import sys

MAGIC = b"SEEDv1"
PBKDF2_ITERS = 200_000


def derive_key(password: str, salt: bytes) -> bytes:
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)


def encrypt_seed(seed: str, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(seed.encode("utf-8"))
    return MAGIC + salt + nonce + tag + ct


def save_bytes(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Encrypt a seed phrase using AES‑256‑GCM + PBKDF2‑SHA256.")
    p.add_argument("out", nargs="?", default="seed.enc", help="output encrypted blob (default: seed.enc)")
    p.add_argument("--seed", help="seed phrase provided via CLI (visible). If omitted, you will be prompted.")
    p.add_argument("--sha256", action="store_true", help="also write a .sha256 checksum next to the output")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    # 1) Get seed phrase (VISIBLE as requested)
    if args.seed is not None:
        seed = args.seed.strip()
    else:
        print("\U0001F510 Enter your 12/24‑word seed (visible):")
        try:
            seed = input("> ").strip()
        except KeyboardInterrupt:
            print("\nAborted.")
            return 130

    if not seed:
        print("[!] Empty seed. Nothing to encrypt.", file=sys.stderr)
        return 1

    # 2) Get password (hidden)
    password = getpass.getpass("\U0001F511 Enter encryption password: ")
    if len(password) < 12:
        print("[!] Password must be at least 12 characters.", file=sys.stderr)
        return 1

    # 3) Encrypt
    blob = encrypt_seed(seed, password)

    # 4) Save with 0600 perms
    save_bytes(args.out, blob)

    # 5) Report and optional checksum file
    h = sha256_hex(blob)
    print(f"[+] Encrypted blob written to {args.out}")
    print(f"[+] SHA‑256: {h}")

    if args.sha256:
        save_bytes(args.out + ".sha256", (h + "\n").encode("ascii"))
        print(f"[+] Checksum written to {args.out}.sha256")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # Allow piping to tools that close early
        try:
            sys.stdout.close()
        except Exception:
            pass
        try:
            sys.stderr.close()
        except Exception:
            pass
        raise SystemExit(0)