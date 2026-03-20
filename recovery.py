#!/usr/bin/env python3
from pathlib import Path

KNOWN_PLAINTEXT = Path("img1.png")
CIPHERTEXT1 = Path("img1.enc")
CIPHERTEXT2 = Path("img2.enc")
RECOVERED = Path("recovered_img2.png")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> int:
    if not KNOWN_PLAINTEXT.exists():
        raise FileNotFoundError(f"File not found: {KNOWN_PLAINTEXT}")
    if not CIPHERTEXT1.exists():
        raise FileNotFoundError(f"File not found: {CIPHERTEXT1}")
    if not CIPHERTEXT2.exists():
        raise FileNotFoundError(f"File not found: {CIPHERTEXT2}")

    p1 = KNOWN_PLAINTEXT.read_bytes()
    c1 = CIPHERTEXT1.read_bytes()
    c2 = CIPHERTEXT2.read_bytes()

    n = min(len(p1), len(c1), len(c2))
    p1 = p1[:n]
    c1 = c1[:n]
    c2 = c2[:n]

    keystream = xor_bytes(c1, p1)
    recovered_p2 = xor_bytes(c2, keystream)

    RECOVERED.write_bytes(recovered_p2)

    print("[+] Known plaintext loaded")
    print("[+] Recovered keystream segment from ciphertext1")
    print(f"[+] Recovered plaintext written to: {RECOVERED}")
    print(f"[+] Recovered {n} bytes")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())