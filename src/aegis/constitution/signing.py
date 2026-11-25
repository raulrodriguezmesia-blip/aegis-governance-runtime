"""Aegis Constitution Signing — V1.5.

Ed25519 signature verification at startup.
Fail-closed if signature is invalid.
"""
import hashlib
import os
from pathlib import Path


class ConstitutionSigner:
    """Signs and verifies the constitution file."""

    def __init__(self, constitution_path: str):
        self.constitution_path = constitution_path
        self.sig_path = constitution_path + ".sig"
        self.hash_path = constitution_path + ".sha256"

    def compute_hash(self) -> str:
        """Compute SHA-256 of the constitution file."""
        content = Path(self.constitution_path).read_bytes()
        return hashlib.sha256(content).hexdigest()

    def sign(self, private_key_pem: str) -> str:
        """Sign the constitution hash with Ed25519 private key."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None)
        constitution_hash = self.compute_hash()
        signature = private_key.sign(constitution_hash.encode())

        # Save signature
        Path(self.sig_path).write_bytes(signature)
        Path(self.hash_path).write_text(constitution_hash)
        return signature.hex()

    def verify(self, public_key_pem: str) -> bool:
        """Verify the constitution signature. Returns True if valid."""
        if not Path(self.sig_path).exists():
            return False

        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = Path(self.sig_path).read_bytes()
        constitution_hash = self.compute_hash()

        try:
            public_key.verify(signature, constitution_hash.encode())
            return True
        except Exception:
            return False

    def verify_at_startup(self, public_key_pem: str) -> tuple[bool, str]:
        """Verify at startup. Returns (success, message)."""
        if not Path(self.constitution_path).exists():
            return (False, "CONSTITUTION_NOT_FOUND")
        if not Path(self.sig_path).exists():
            return (False, "CONSTITUTION_SIGNATURE_MISSING")
        if self.verify(public_key_pem):
            return (True, "CONSTITUTION_VERIFIED")
        return (False, "CONSTITUTION_COMPROMISED")


def generate_keypair():
    """Generate an Ed25519 keypair for testing."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return private_pem.decode(), public_pem.decode()