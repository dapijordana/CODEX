"""Core cryptography helpers for the portable encrypt/decrypt UI.

The module defines a small header format to identify encrypted files:
- Magic bytes: b"CXENC01"
- Algorithm byte: 0 for AES-256-GCM, 1 for ChaCha20-Poly1305.
- Kind byte: 0 for file, 1 for folder/archive.
- Salt: 16 bytes
- Nonce: 12 bytes
- Name length: 1 byte (0-255) representing UTF-8 filename length
- Name bytes
The remainder is the ciphertext produced with the selected AEAD cipher.
"""
from __future__ import annotations

import os
import struct
import zipfile
from dataclasses import dataclass
from io import BytesIO
from typing import Literal, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"CXENC01"
ALG_MAP = {
    "AES-256-GCM": 0,
    "ChaCha20-Poly1305": 1,
}
ALG_MAP_INV = {v: k for k, v in ALG_MAP.items()}

ArchiveKind = Literal["file", "folder"]


@dataclass
class EncryptionHeader:
    algorithm: str
    kind: ArchiveKind
    salt: bytes
    nonce: bytes
    original_name: str

    def to_bytes(self) -> bytes:
        alg_id = ALG_MAP[self.algorithm]
        kind_id = 0 if self.kind == "file" else 1
        name_bytes = self.original_name.encode("utf-8")
        if len(name_bytes) > 255:
            raise ValueError("Original name is too long for header (max 255 UTF-8 bytes)")
        return b"".join(
            [
                MAGIC,
                struct.pack("B", alg_id),
                struct.pack("B", kind_id),
                self.salt,
                self.nonce,
                struct.pack("B", len(name_bytes)),
                name_bytes,
            ]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple["EncryptionHeader", int]:
        if not data.startswith(MAGIC):
            raise ValueError("File does not contain a valid CODEX encryption header")
        offset = len(MAGIC)
        alg_id = data[offset]
        offset += 1
        kind_id = data[offset]
        offset += 1
        salt = data[offset : offset + 16]
        if len(salt) != 16:
            raise ValueError("Invalid header: salt truncated")
        offset += 16
        nonce = data[offset : offset + 12]
        if len(nonce) != 12:
            raise ValueError("Invalid header: nonce truncated")
        offset += 12
        name_len = data[offset]
        offset += 1
        name_bytes = data[offset : offset + name_len]
        if len(name_bytes) != name_len:
            raise ValueError("Invalid header: filename truncated")
        offset += name_len

        algorithm = ALG_MAP_INV.get(alg_id)
        if algorithm is None:
            raise ValueError("Unknown algorithm id in header")
        kind: ArchiveKind = "folder" if kind_id == 1 else "file"
        return cls(
            algorithm=algorithm,
            kind=kind,
            salt=salt,
            nonce=nonce,
            original_name=name_bytes.decode("utf-8"),
        ), offset


def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a symmetric key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=390000)
    return kdf.derive(password.encode("utf-8"))


def select_cipher(algorithm: str, key: bytes):
    if algorithm == "AES-256-GCM":
        return AESGCM(key)
    if algorithm == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key)
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def zip_directory(path: str) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(path):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, start=path)
                zf.write(full, arcname=rel)
    return buffer.getvalue()


def unzip_to_directory(data: bytes, target_dir: str) -> None:
    os.makedirs(target_dir, exist_ok=True)
    buffer = BytesIO(data)
    with zipfile.ZipFile(buffer, mode="r") as zf:
        zf.extractall(path=target_dir)


def encrypt_path(path: str, password: str, algorithm: str) -> str:
    if algorithm not in ALG_MAP:
        raise ValueError("Unsupported algorithm")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    kind: ArchiveKind

    if os.path.isdir(path):
        kind = "folder"
        original_name = os.path.basename(os.path.abspath(path)) or "folder"
        payload = zip_directory(path)
    else:
        kind = "file"
        original_name = os.path.basename(path)
        with open(path, "rb") as fh:
            payload = fh.read()

    key = derive_key(password, salt)
    cipher = select_cipher(algorithm, key)
    ciphertext = cipher.encrypt(nonce, payload, b"codex")

    header = EncryptionHeader(
        algorithm=algorithm, kind=kind, salt=salt, nonce=nonce, original_name=original_name
    ).to_bytes()

    out_path = f"{path}.enc"
    with open(out_path, "wb") as fh:
        fh.write(header + ciphertext)
    return out_path


def decrypt_path(path: str, password: str, output_dir: str | None = None) -> str:
    with open(path, "rb") as fh:
        blob = fh.read()

    header, offset = EncryptionHeader.from_bytes(blob)
    ciphertext = blob[offset:]

    key = derive_key(password, header.salt)
    cipher = select_cipher(header.algorithm, key)
    try:
        plaintext = cipher.decrypt(header.nonce, ciphertext, b"codex")
    except Exception as exc:  # noqa: BLE001 - surface cryptographic errors to UI
        raise ValueError("Password atau algoritma salah, tidak dapat mendekripsi.") from exc

    target_base = os.path.splitext(path)[0]
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        target_base = os.path.join(output_dir, os.path.basename(target_base))

    if header.kind == "folder":
        unzip_to_directory(plaintext, target_base)
        return target_base

    with open(target_base, "wb") as fh:
        fh.write(plaintext)
    return target_base


def is_encrypted(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            prefix = fh.read(len(MAGIC))
        return prefix.startswith(MAGIC)
    except OSError:
        return False
