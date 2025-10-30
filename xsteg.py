
import argparse
import sys
import struct
import zlib
from io import BytesIO
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERS = 200_000
KEY_SIZE = 32  # AES-256
HEADER_FMT = ">I B"  # payload_len (4 bytes, big-endian) + flags (1 byte)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 5 bytes
FLAG_ENCRYPTED = 0x1
FLAG_COMPRESSED = 0x2


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2(passphrase.encode('utf-8'), salt, dkLen=KEY_SIZE, count=PBKDF2_ITERS)


def encrypt(plaintext: bytes, passphrase: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(passphrase, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # store: salt | nonce | tag | ciphertext
    return salt + nonce + tag + ciphertext


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if len(blob) < (SALT_SIZE + NONCE_SIZE + 16):
        raise ValueError("Encrypted blob is too short or corrupted")
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = blob[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + 16]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE + 16:]
    key = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def bytes_to_bits(data: bytes) -> list:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def bits_to_bytes(bits: list) -> bytes:
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | bits[i + j]
            else:
                byte = (byte << 1)
        b.append(byte)
    return bytes(b)


def embed_bits_into_image(img: Image.Image, bits: list) -> Image.Image:
    """Embed a list of bits into the LSB of the image's RGB channels (skips alpha).
    Assumes 1 bit per color channel (R,G,B) - so 3 bits per pixel for RGB images.
    """
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")

    pixels = list(img.getdata())
    out_pixels = []
    bit_idx = 0
    total_bits = len(bits)
    for px in pixels:
        r, g, b, *rest = px if isinstance(px, tuple) else (px,)
        a = rest[0] if rest else None
        # modify r,g,b LSBs if bits left
        channels = [r, g, b]
        for c_i in range(3):
            if bit_idx < total_bits:
                channels[c_i] = (channels[c_i] & ~1) | bits[bit_idx]
                bit_idx += 1
        if a is None:
            out_pixels.append(tuple(channels))
        else:
            out_pixels.append((channels[0], channels[1], channels[2], a))
    if bit_idx < total_bits:
        raise ValueError("Not all bits were embedded — image capacity miscalculation")

    out = Image.new(img.mode, img.size)
    out.putdata(out_pixels)
    return out


def extract_bits_from_image(img: Image.Image, num_bits: int) -> list:
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")
    pixels = list(img.getdata())
    bits = []
    for px in pixels:
        r, g, b, *rest = px if isinstance(px, tuple) else (px,)
        bits.append(r & 1)
        if len(bits) >= num_bits:
            break
        bits.append(g & 1)
        if len(bits) >= num_bits:
            break
        bits.append(b & 1)
        if len(bits) >= num_bits:
            break
    return bits[:num_bits]


def calculate_capacity_bits(img: Image.Image) -> int:
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")
    width, height = img.size
    return width * height * 3  # 3 color channels, 1 bit each


def pack_payload(payload: bytes, encrypt_flag: bool, compress_flag: bool, passphrase: str=None) -> bytes:
    data = payload
    if compress_flag:
        data = zlib.compress(data)
    flags = 0
    if encrypt_flag:
        if not passphrase:
            raise ValueError("Passphrase required for encryption")
        data = encrypt(data, passphrase)
        flags |= FLAG_ENCRYPTED
    if compress_flag:
        flags |= FLAG_COMPRESSED
    header = struct.pack(HEADER_FMT, len(data), flags)
    return header + data


def unpack_payload(raw: bytes, passphrase: str=None) -> bytes:
    if len(raw) < HEADER_SIZE:
        raise ValueError("Data too short to contain header")
    header = raw[:HEADER_SIZE]
    payload_len, flags = struct.unpack(HEADER_FMT, header)
    body = raw[HEADER_SIZE:HEADER_SIZE + payload_len]
    if len(body) != payload_len:
        raise ValueError("Payload length mismatch or corrupted data")
    if flags & FLAG_ENCRYPTED:
        if not passphrase:
            raise ValueError("Data is encrypted — passphrase needed to decrypt")
        body = decrypt(body, passphrase)
    if flags & FLAG_COMPRESSED:
        body = zlib.decompress(body)
    return body


def hide(args):
    # read input
    img = Image.open(args.infile)
    capacity = calculate_capacity_bits(img)

    if args.message_file:
        with open(args.message_file, 'rb') as f:
            payload = f.read()
    else:
        payload = args.message.encode('utf-8') if args.message is not None else b''

    packed = pack_payload(payload, encrypt_flag=bool(args.passphrase), compress_flag=args.compress, passphrase=args.passphrase)
    bits = bytes_to_bits(packed)
    if len(bits) > capacity:
        raise ValueError(f"Payload too large for cover image. Need {len(bits)} bits but image capacity is {capacity} bits")

    stego_img = embed_bits_into_image(img, bits)
    stego_img.save(args.outfile, format='PNG')
    print(f"Success: wrote stego image to {args.outfile} — embedded {len(bits)} bits")


def reveal(args):
    img = Image.open(args.infile)
    capacity = calculate_capacity_bits(img)
    # First read header (HEADER_SIZE bytes = 5 bytes -> 5*8 = 40 bits)
    header_bits = extract_bits_from_image(img, HEADER_SIZE * 8)
    header_bytes = bits_to_bytes(header_bits)
    try:
        payload_len, flags = struct.unpack(HEADER_FMT, header_bytes)
    except struct.error:
        raise ValueError("Failed to parse header — data likely not present or corrupted")
    total_payload_bits = (HEADER_SIZE + payload_len) * 8
    if total_payload_bits > capacity:
        raise ValueError("Header indicates payload larger than image capacity — corrupted or wrong image")
    all_bits = extract_bits_from_image(img, total_payload_bits)
    all_bytes = bits_to_bytes(all_bits)
    payload_raw = all_bytes
    # unpack
    extracted = unpack_payload(payload_raw, passphrase=args.passphrase)
    if args.outfile:
        with open(args.outfile, 'wb') as f:
            f.write(extracted)
        print(f"Extracted payload written to {args.outfile} ({len(extracted)} bytes)")
    else:
        # try to print as utf-8 text, else dump bytes length
        try:
            text = extracted.decode('utf-8')
            print("--- extracted text ---")
            print(text)
            print("--- end ---")
        except Exception:
            print(f"Extracted binary payload ({len(extracted)} bytes). Use --out to save to file.")


def build_parser():
    p = argparse.ArgumentParser(description='LSB Steganography tool for CTFs (hide/reveal)')
    sub = p.add_subparsers(dest='cmd', required=True)

    p_hide = sub.add_parser('hide', help='Hide message/file inside image')
    p_hide.add_argument('--in', dest='infile', required=True, help='Cover image (PNG/BMP recommended)')
    p_hide.add_argument('--out', dest='outfile', required=True, help='Output stego image (PNG)')
    g = p_hide.add_mutually_exclusive_group(required=True)
    g.add_argument('--message', help='Message text to hide')
    g.add_argument('--message-file', help='Path to file to hide')
    p_hide.add_argument('--passphrase', help='Passphrase to encrypt payload (optional)')
    p_hide.add_argument('--compress', action='store_true', help='Compress payload before (optional)')

    p_reveal = sub.add_parser('reveal', help='Reveal hidden payload from image')
    p_reveal.add_argument('--in', dest='infile', required=True, help='Stego image')
    p_reveal.add_argument('--out', dest='outfile', required=False, help='Save extracted payload to file (optional)')
    p_reveal.add_argument('--passphrase', help='Passphrase if payload was encrypted')

    return p
--------{

TEAM-1


TEAM-2


TEAM-3

}----------

def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.cmd == 'hide':
            hide(args)
        elif args.cmd == 'reveal':
            reveal(args)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
