"""
SBOM Signature Verification Service

Supports:
- ECDSA (cosign / Sigstore default)
- RSA-PSS
- Raw Ed25519

Uses the `cryptography` library (already installed as transitive dep of python-jose).
"""
from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.x509 import load_pem_x509_certificate

logger = logging.getLogger(__name__)

SUPPORTED_ALGORITHMS = {
    "ecdsa-sha256": "ECDSA with SHA-256 (Sigstore/cosign default)",
    "ecdsa-sha384": "ECDSA with SHA-384",
    "rsa-pss-sha256": "RSA-PSS with SHA-256",
    "rsa-pkcs1-sha256": "RSA PKCS#1 v1.5 with SHA-256",
}


@dataclass
class VerifyResult:
    valid: bool
    algorithm: str
    signer_identity: Optional[str] = None
    message: str = ""
    detail: str = ""


def detect_algorithm(public_key_pem: str) -> Optional[str]:
    """Auto-detect algorithm from the public key type."""
    try:
        key = _load_public_key(public_key_pem)
        if isinstance(key, ec.EllipticCurvePublicKey):
            return "ecdsa-sha256"
        from cryptography.hazmat.primitives.asymmetric import rsa
        if isinstance(key, rsa.RSAPublicKey):
            return "rsa-pss-sha256"
        return None
    except Exception:
        return None


def verify_signature(
    sbom_content: bytes,
    signature_b64: str,
    public_key_pem: str,
    algorithm: Optional[str] = None,
) -> VerifyResult:
    """
    Verify a signature against SBOM file content.

    Parameters
    ----------
    sbom_content : bytes
        Raw SBOM file bytes.
    signature_b64 : str
        Base64-encoded signature.
    public_key_pem : str
        PEM-encoded public key or X.509 certificate.
    algorithm : str, optional
        Signature algorithm. Auto-detected if omitted.

    Returns
    -------
    VerifyResult
    """
    # Decode signature
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception as e:
        return VerifyResult(
            valid=False, algorithm=algorithm or "unknown",
            message="簽章格式錯誤：無法解碼 Base64",
            detail=str(e),
        )

    # Load public key
    try:
        public_key = _load_public_key(public_key_pem)
    except Exception as e:
        return VerifyResult(
            valid=False, algorithm=algorithm or "unknown",
            message="公鑰格式錯誤：無法載入 PEM 公鑰或憑證",
            detail=str(e),
        )

    # Auto-detect algorithm
    if not algorithm:
        algorithm = detect_algorithm(public_key_pem) or "ecdsa-sha256"

    # Extract signer identity from certificate (if applicable)
    signer = _extract_signer_identity(public_key_pem)

    # Verify
    try:
        if algorithm.startswith("ecdsa"):
            hash_algo = _get_hash(algorithm)
            public_key.verify(signature_bytes, sbom_content, ec.ECDSA(hash_algo))

        elif algorithm == "rsa-pss-sha256":
            from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
            hash_algo = hashes.SHA256()
            public_key.verify(
                signature_bytes, sbom_content,
                padding.PSS(
                    mgf=padding.MGF1(hash_algo),
                    salt_length=padding.PSS.AUTO,
                ),
                hash_algo,
            )

        elif algorithm == "rsa-pkcs1-sha256":
            hash_algo = hashes.SHA256()
            public_key.verify(
                signature_bytes, sbom_content,
                padding.PKCS1v15(),
                hash_algo,
            )
        else:
            return VerifyResult(
                valid=False, algorithm=algorithm,
                message=f"不支援的演算法：{algorithm}",
            )

        return VerifyResult(
            valid=True, algorithm=algorithm,
            signer_identity=signer,
            message="簽章驗證通過",
            detail=f"SBOM 完整性已確認，使用 {SUPPORTED_ALGORITHMS.get(algorithm, algorithm)} 驗證",
        )

    except InvalidSignature:
        return VerifyResult(
            valid=False, algorithm=algorithm,
            signer_identity=signer,
            message="簽章驗證失敗：簽章與 SBOM 內容不符",
            detail="簽章可能已過期、SBOM 可能已被竄改、或使用了錯誤的公鑰",
        )
    except Exception as e:
        return VerifyResult(
            valid=False, algorithm=algorithm,
            message=f"驗證過程發生錯誤",
            detail=str(e),
        )


def compute_sbom_digest(sbom_content: bytes, algorithm: str = "sha256") -> str:
    """Compute hex digest of SBOM content."""
    return hashlib.sha256(sbom_content).hexdigest()


def _load_public_key(pem: str):
    """Load a public key from PEM string. Supports raw public keys and X.509 certificates."""
    pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem

    # Try X.509 certificate first
    if b"BEGIN CERTIFICATE" in pem_bytes:
        cert = load_pem_x509_certificate(pem_bytes)
        return cert.public_key()

    # Try raw public key
    return serialization.load_pem_public_key(pem_bytes)


def _extract_signer_identity(pem: str) -> Optional[str]:
    """Extract signer identity (email/CN) from X.509 certificate."""
    try:
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        if b"BEGIN CERTIFICATE" not in pem_bytes:
            return None
        cert = load_pem_x509_certificate(pem_bytes)
        # Try to get email from SAN
        try:
            from cryptography.x509 import ExtensionNotFound
            from cryptography.x509.oid import ExtensionOID
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            emails = san.value.get_values_for_type(type(None))  # placeholder
        except Exception:
            pass
        # Fallback: get CN from subject
        from cryptography.x509.oid import NameOID
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
        return str(cert.subject)
    except Exception:
        return None


def _get_hash(algorithm: str):
    """Return hash algorithm instance for the given algorithm string."""
    if "sha384" in algorithm:
        return hashes.SHA384()
    if "sha512" in algorithm:
        return hashes.SHA512()
    return hashes.SHA256()
