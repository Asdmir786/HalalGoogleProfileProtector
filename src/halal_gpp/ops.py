import io
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

import zstandard as zstd

from .crypto_core import (
    KdfParams,
    TAG_LEN,
    b64e,
    create_decryptor,
    create_encryptor,
    derive_base_key,
    derive_subkeys,
    mac_header,
    read_header,
    write_header,
)

# Small set of cache folders to optionally skip
CACHE_DIRS = {"Cache", "Code Cache", "GPUCache"}


@dataclass
class Progress:
    step: str
    percent: int


def _iter_paths(root: Path, skip_caches: bool) -> Iterable[Path]:
    for base, dirs, files in os.walk(root):
        b = Path(base)
        if skip_caches:
            dirs[:] = [d for d in dirs if d not in CACHE_DIRS]
        for f in files:
            yield b / f


def _safe_tar_extract(t: tarfile.TarFile, dest: Path):
    dest = dest.resolve()
    for m in t:
        name = m.name
        if name.startswith("/"):
            continue
        p = dest / name
        rp = p.resolve()
        if not str(rp).startswith(str(dest)):
            continue
        t.extract(m, dest)


def encrypt_directory(
    profile_dir: Path,
    out_file: Path,
    password: str,
    skip_caches: bool,
    progress: Optional[Callable[[Progress], None]] = None,
):
    profile_dir = profile_dir.resolve()
    out_file = out_file.resolve()

    if progress:
        progress(Progress("Preparing", 5))

    params = KdfParams()
    kdf_salt = os.urandom(params.salt_len)
    hkdf_salt = os.urandom(16)
    nonce = os.urandom(12)

    base_key = derive_base_key(password, kdf_salt, params)
    enc_key, hdr_key = derive_subkeys(base_key, hkdf_salt)

    # encoded argon2 string for quick verify
    from argon2.low_level import hash_secret, Type as Argon2Type

    pwd_hash = hash_secret(
        password.encode("utf-8"),
        kdf_salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    ).decode("utf-8")

    header = {
        "version": 1,
        "kdf": "argon2id",
        "kdf_salt": b64e(kdf_salt),
        "kdf_params": {
            "t": params.time_cost,
            "m": params.memory_cost,
            "p": params.parallelism,
        },
        "hkdf_salt": b64e(hkdf_salt),
        "aead": "aes-256-gcm",
        "nonce": b64e(nonce),
        "chunk_size": 8_388_608,
        "pwd_hash": pwd_hash,
    }

    tmp = out_file.with_suffix(out_file.suffix + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)

    total_files = sum(1 for _ in _iter_paths(profile_dir, skip_caches)) or 1
    done_files = 0

    with open(tmp, "wb") as f:
        # Reserve space by writing header now
        write_header(f, header, hdr_key)

        enc = create_encryptor(enc_key, nonce)

        # Set up zstd compressor streaming into our encrypt writer
        class EncryptWriter:
            def __init__(self, dest, encryptor):
                self._dest = dest
                self._enc = encryptor

            def write(self, b: bytes):
                if not b:
                    return 0
                ct = self._enc.update(b)
                self._dest.write(ct)
                return len(b)

            def flush(self):
                pass

        zc = zstd.ZstdCompressor(level=10)
        zw = zc.stream_writer(EncryptWriter(f, enc))

        # Stream a tar archive into zstd -> encrypt
        with tarfile.open(fileobj=zw, mode="w|") as tf:
            for p in _iter_paths(profile_dir, skip_caches):
                arcname = str(p.relative_to(profile_dir))
                tf.add(str(p), arcname=arcname, recursive=False)
                done_files += 1
                if progress:
                    percent = 5 + int(85 * done_files / max(1, total_files))
                    progress(Progress("Encrypting", min(percent, 90)))

        zw.flush(zstd.FLUSH_FRAME)
        zw.close()

        # finalize GCM and write tag
        enc.finalize()
        f.write(enc.tag)

    tmp.replace(out_file)
    if progress:
        progress(Progress("Done", 100))


def decrypt_archive(
    archive_file: Path,
    dest_dir: Path,
    password: str,
    progress: Optional[Callable[[Progress], None]] = None,
):
    archive_file = archive_file.resolve()
    dest_dir = dest_dir.resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    if progress:
        progress(Progress("Reading header", 5))

    with open(archive_file, "rb") as f:
        header, header_bytes, header_json = read_header(f)
        kdf = header.get("kdf")
        if kdf != "argon2id":
            raise ValueError("Unsupported KDF")
        from base64 import b64decode

        kdf_salt = b64decode(header["kdf_salt"])  # type: ignore
        kp = header["kdf_params"]
        params = KdfParams(kp["t"], kp["m"], kp["p"])  # type: ignore
        hkdf_salt = b64decode(header["hkdf_salt"])  # type: ignore
        nonce = b64decode(header["nonce"])  # type: ignore
        base_key = derive_base_key(password, kdf_salt, params)
        enc_key, hdr_key = derive_subkeys(base_key, hkdf_salt)

    # Reopen to compute body offsets and stream-decrypt
    with open(archive_file, "rb") as f:
        header, header_bytes, header_json = read_header(f)
        from base64 import b64decode
        kdf_salt = b64decode(header["kdf_salt"])  # type: ignore
        kp = header["kdf_params"]
        params = KdfParams(kp["t"], kp["m"], kp["p"])  # type: ignore
        hkdf_salt = b64decode(header["hkdf_salt"])  # type: ignore
        nonce = b64decode(header["nonce"])  # type: ignore

        base_key = derive_base_key(password, kdf_salt, params)
        enc_key, hdr_key = derive_subkeys(base_key, hkdf_salt)

        # Verify MAC again
        from cryptography.hazmat.primitives import hmac as _hmac, hashes as _hashes
        h = _hmac.HMAC(hdr_key, _hashes.SHA256())
        h.update(header_json)
        expected_mac = h.finalize()
        f.seek(4 + 4 + len(header_json))
        mac_stored = f.read(32)
        if mac_stored != expected_mac:
            raise ValueError("Header MAC mismatch (tampered)")

        # Compute ciphertext region and tag
        total = archive_file.stat().st_size
        ct_start = header_bytes
        ct_end = total - TAG_LEN
        if ct_end < ct_start:
            raise ValueError("Corrupt archive (too small)")
        f.seek(ct_end)
        tag = f.read(TAG_LEN)
        f.seek(ct_start)

        dec = create_decryptor(enc_key, nonce, tag)

        class DecryptReader(io.RawIOBase):
            def __init__(self, src, decryptor, remain):
                self._src = src
                self._dec = decryptor
                self._remain = remain

            def read(self, n=-1):
                if self._remain <= 0:
                    return b""
                if n is None or n < 0:
                    n = self._remain
                n = min(self._remain, n)
                data = self._src.read(n)
                self._remain -= len(data)
                return self._dec.update(data)

        remain = ct_end - ct_start
        reader = DecryptReader(f, dec, remain)

        if progress:
            progress(Progress("Decrypting", 50))

        zd = zstd.ZstdDecompressor()
        with zd.stream_reader(reader) as zr:
            with tarfile.open(fileobj=zr, mode="r|") as tf:
                _safe_tar_extract(tf, dest_dir)

        # finalize tag check
        dec.finalize()

    if progress:
        progress(Progress("Done", 100))
