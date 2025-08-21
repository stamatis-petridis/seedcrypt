

# seedcrypt

**Offline seed phrase encryption for humans.**  
A single-file HTML app and matching Python scripts that let you encrypt/decrypt your Bitcoin (or any text) seed phrases entirely offline, using modern authenticated encryption (AES‑256‑GCM + PBKDF2‑SHA256). No dependencies, no servers, no telemetry.

---

## Features
- 🔒 **AES‑256‑GCM encryption** with 200k PBKDF2 iterations for key derivation.
- 🌐 **Self‑contained HTML** — just open `seedcrypt.html` in any modern browser, no install required.
- 🐍 **Python reference scripts** — encrypt/decrypt with the same format for full round‑trip compatibility.
- 👁 **Show/Hide toggles** for seed, passwords, and decrypted output.
- 🛡 **UX safeguards**: no autocorrect/autocapitalize/spellcheck, whitespace trimmed, copy guard when hidden.
- 📦 **Deterministic format**: `[MAGIC "SEEDv1" | salt(16) | nonce(12) | tag(16) | ciphertext]`.
- 📴 **Designed for offline use** — keep your machine or phone airgapped.

---

## Usage

### HTML (browser)
1. Open `seedcrypt.html` locally (double‑click, or `file://` in browser).
2. Enter your seed phrase and a long passphrase (≥12 chars).
3. Download the `.enc` file.
4. To decrypt, upload the `.enc` file, enter the password, and reveal your plaintext.

### Python (CLI)
```bash
# Encrypt
python3 python/seed_encrypt.py
# Decrypt
python3 python/decrypt_seed.py
```

Both scripts save/read `seed.enc` by default.

---

## Security Notes
- Always use a **long, unique passphrase**. Diceware recommended.
- **Stay offline** when handling seed phrases.
- Store multiple copies of `.enc` alongside its SHA‑256 checksum.
- This tool is **not a wallet** — it does not generate keys or transact.

---

## License
MIT — do what you want, no warranty.