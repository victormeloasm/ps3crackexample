#!/usr/bin/env python3
import json
from pathlib import Path

from ecdsa.ecdsa import generator_secp256k1

META = Path("challenge.json")

GEN = generator_secp256k1
N = GEN.order()


def modinv(a: int, n: int) -> int:
    return pow(a % n, -1, n)


def recover_k(z1: int, z2: int, s1: int, s2: int, n: int) -> int:
    return ((z1 - z2) * modinv((s1 - s2) % n, n)) % n


def recover_d(r: int, s: int, z: int, k: int, n: int) -> int:
    return ((s * k - z) * modinv(r, n)) % n


def pubkey_hex_from_priv(d: int) -> str:
    point = d * GEN
    x = int(point.x())
    y = int(point.y())
    return f"04{x:064x}{y:064x}"


def main() -> int:
    if not META.exists():
        raise FileNotFoundError(f"File not found: {META}")

    data = json.loads(META.read_text(encoding="utf-8"))
    e = data["ecdsa"]

    z1 = int(e["z1"], 16)
    z2 = int(e["z2"], 16)
    r1 = int(e["r1"], 16)
    s1 = int(e["s1"], 16)
    r2 = int(e["r2"], 16)
    s2 = int(e["s2"], 16)
    expected_pub = e["public_key_uncompressed_hex"].lower()

    print("[+] Loaded public signature data")
    print(f"r1 = {hex(r1)}")
    print(f"s1 = {hex(s1)}")
    print(f"r2 = {hex(r2)}")
    print(f"s2 = {hex(s2)}")
    print()

    if r1 != r2:
        print("[-] r1 != r2, so the exact same nonce k was not reused.")
        return 1

    print("[+] Matching r detected. Attack is viable.")
    r = r1

    k = recover_k(z1, z2, s1, s2, N)
    d = recover_d(r, s1, z1, k, N)
    derived_pub = pubkey_hex_from_priv(d).lower()

    print(f"[+] Recovered nonce k            = {hex(k)}")
    print(f"[+] Recovered private key d      = {hex(d)}")
    print(f"[+] Derived public key           = {derived_pub}")
    print(f"[+] Expected public key          = {expected_pub}")
    print(f"[+] Match                        = {derived_pub == expected_pub}")

    return 0 if derived_pub == expected_pub else 2


if __name__ == "__main__":
    raise SystemExit(main())