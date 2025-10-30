# CTF Steg Tool

A lightweight command-line steganography helper intended for CTFs and learning.

## Features

* Hide and reveal messages or files inside PNG/BMP images using least-significant-bit (LSB) steganography.
* Optional AES-GCM encryption (passphrase) and DEFLATE compression.
* Capacity checking and clear error messages.
* Single-file Python script: `ctf_steg_tool.py`.

## Requirements

* Python 3.8+
* See `requirements.txt` for Python package dependencies.

## Installation

```bash
# create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Quick usage

```bash
# Hide a short text message in cover.png -> steg.png
python3 ctf_steg_tool.py hide --in cover.png --out steg.png --message "picoCTF{example_flag}"

# Hide a file with compression + passphrase
python3 ctf_steg_tool.py hide --in cover.png --out steg.png --message-file secret.txt --compress --passphrase hunter2

# Reveal and print text (no passphrase)
python3 ctf_steg_tool.py reveal --in steg.png

# Reveal and save binary to file with passphrase
python3 ctf_steg_tool.py reveal --in steg.png --out extracted.bin --passphrase hunter2
```

## Notes and tips for CTF creators

* Use reasonably-sized PNG covers (bigger images allow larger payloads). This implementation embeds 1 LSB per color channel (3 bits/pixel for RGB). If you want larger capacity, add variable-depth LSB embedding (not implemented here).
* If you expect flags to be short (a few dozen bytes), a small image (e.g. 200×200) will suffice. Always check capacity using the tool (it will error if payload is too large).
* The header includes a small metadata header (payload length + flags) to enable robust extraction.

## Security

* AES-GCM is used with a PBKDF2-derived key from the passphrase. Use strong passphrases.
* This tool is intended for educational/CTF use only. Do not use as a substitute for production-grade secure file containers.

## Extending the tool

* Audio steganography, variable LSB depth, and GUI wrappers are common extensions.

## License and license key

* See `LICENSE` file.
* This repository includes an optional license key (for attribution/packaging) — see below.

### Sample License Key

```
CTF-STEGO-2025-9F3B-7A1C-2D8E
```

---

If you’d like runtime license enforcement, I can add a `--license` option that checks keys via HMAC-SHA256 verification.
