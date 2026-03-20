#!/usr/bin/env python3
import json
import hashlib
import secrets
from pathlib import Path
from base64 import b64encode

from Crypto.Cipher import AES
from ecdsa.ecdsa import generator_secp256k1, Public_key, Private_key

IMG1 = Path("img1.png")
IMG2 = Path("img2.png")

OUT1 = Path("img1.enc")
OUT2 = Path("img2.enc")
META = Path("challenge.json")

GEN = generator_secp256k1
N = GEN.order()


def b64(data: bytes) -> str:
    return b64encode(data).decode("ascii")


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_int(data: bytes) -> int:
    return int.from_bytes(sha256_bytes(data), "big")


def encrypt_ctr_same_nonce(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(plaintext)


def sign_with_fixed_k(privkey_int: int, message_hash_int: int, k: int):
    pub_point = privkey_int * GEN
    pub = Public_key(GEN, pub_point)
    priv = Private_key(pub, privkey_int)
    sig = priv.sign(message_hash_int, k)
    return sig.r, sig.s


def pubkey_hex_from_priv(d: int) -> str:
    point = d * GEN
    x = int(point.x())
    y = int(point.y())
    return f"04{x:064x}{y:064x}"


def main() -> int:
    if not IMG1.exists():
        raise FileNotFoundError(f"File not found: {IMG1}")
    if not IMG2.exists():
        raise FileNotFoundError(f"File not found: {IMG2}")

    pt1 = IMG1.read_bytes()
    pt2 = IMG2.read_bytes()

    aes_key = secrets.token_bytes(32)
    aes_nonce = secrets.token_bytes(8)
    ecdsa_priv = secrets.randbelow(N - 1) + 1

    ct1 = encrypt_ctr_same_nonce(aes_key, aes_nonce, pt1)
    ct2 = encrypt_ctr_same_nonce(aes_key, aes_nonce, pt2)

    OUT1.write_bytes(ct1)
    OUT2.write_bytes(ct2)

    z1 = sha256_int(ct1) % N
    z2 = sha256_int(ct2) % N
    reused_k = secrets.randbelow(N - 1) + 1

    r1, s1 = sign_with_fixed_k(ecdsa_priv, z1, reused_k)
    r2, s2 = sign_with_fixed_k(ecdsa_priv, z2, reused_k)

    if r1 != r2:
        raise RuntimeError("Unexpected failure: identical k should produce identical r.")

    pubkey_hex = pubkey_hex_from_priv(ecdsa_priv)

    meta = {
        "title": "ECDSA nonce reuse and AES-CTR nonce reuse demonstration",
        "warning": "This demo intentionally reuses the same AES-CTR nonce and the same ECDSA nonce. It is insecure by design.",
        "files": {
            "plaintext1": str(IMG1),
            "plaintext2": str(IMG2),
            "ciphertext1": str(OUT1),
            "ciphertext2": str(OUT2)
        },
        "aes_ctr": {
            "algorithm": "AES-256-CTR",
            "nonce_b64": b64(aes_nonce),
            "ciphertext1_sha256": sha256_bytes(ct1).hex(),
            "ciphertext2_sha256": sha256_bytes(ct2).hex(),
            "ciphertext1_size": len(ct1),
            "ciphertext2_size": len(ct2)
        },
        "ecdsa": {
            "curve": "secp256k1",
            "public_key_uncompressed_hex": pubkey_hex,
            "z1": hex(z1),
            "z2": hex(z2),
            "r1": hex(r1),
            "s1": hex(s1),
            "r2": hex(r2),
            "s2": hex(s2)
        }
    }

    with open(META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print("[OK] Images encrypted with AES-CTR using the same nonce.")
    print(f"[OK] Outputs: {OUT1} and {OUT2}")
    print("[OK] Ciphertexts signed with ECDSA using the same nonce k.")
    print(f"[OK] Public metadata saved to: {META}")
    print("[OK] No secret keys were printed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())