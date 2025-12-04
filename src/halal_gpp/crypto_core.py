import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from argon2.low_level import hash_secret_raw, Type as Argon2Type

MAGIC = b"HGP1"
HEADER_MAC_LEN = 32
TAG_LEN = 16


@dataclass
class KdfParams:
    time_cost: int = 3
    memory_cost: int = 256 * 1024
    parallelism: int = 4
    salt_len: int = 16


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def derive_base_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    return hash_secret_raw(
        password.encode("utf-8"),
        salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    )


def derive_subkeys(base_key: bytes, hkdf_salt: bytes) -> tuple[bytes, bytes]:
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"enc_key",
    ).derive(base_key)
    hdr_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"hdr_key",
    ).derive(base_key)
    return enc_key, hdr_key


def mac_header(header_json: bytes, hdr_key: bytes) -> bytes:
    h = hmac.HMAC(hdr_key, hashes.SHA256())
    h.update(header_json)
    return h.finalize()


def write_header(out, header: dict, hdr_key: bytes) -> None:
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    m = mac_header(header_json, hdr_key)
    out.write(MAGIC)
    out.write(len(header_json).to_bytes(4, "little"))
    out.write(header_json)
    out.write(m)


def read_header(f) -> tuple[dict, int, bytes]:
    magic = f.read(4)
    if magic != MAGIC:
        raise ValueError("Bad magic")
    hlen = int.from_bytes(f.read(4), "little")
    hjson = f.read(hlen)
    mac = f.read(HEADER_MAC_LEN)
    header = json.loads(hjson.decode("utf-8"))
    return header, 8 + hlen + HEADER_MAC_LEN, hjson


class EncryptWriter:
    def __init__(self, dest, encryptor):
        self._dest = dest
        self._enc = encryptor
        self.bytes_in = 0
        self.bytes_out = 0

    def write(self, data: bytes):
        if not data:
            return 0
        self.bytes_in += len(data)
        ct = self._enc.update(data)
        self.bytes_out += len(ct)
        self._dest.write(ct)
        return len(data)

    def flush(self):
        if hasattr(self._dest, "flush"):
            self._dest.flush()


class DecryptReader:
    def __init__(self, src, decryptor, length: int):
        self._src = src
        self._dec = decryptor
        self._remain = length

    def read(self, n: Optional[int] = -1) -> bytes:
        if self._remain <= 0:
            return b""
        if n is None or n < 0:
            n = self._remain
        n = min(n, self._remain)
        data = self._src.read(n)
        self._remain -= len(data)
        return self._dec.update(data)


def create_encryptor(key: bytes, nonce: bytes):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    return cipher.encryptor()


def create_decryptor(key: bytes, nonce: bytes, tag: bytes):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    return cipher.decryptor()
