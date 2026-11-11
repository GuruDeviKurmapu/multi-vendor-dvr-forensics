"""
hashing.py - Cryptographic Hashing and Integrity Verification.

This module provides:
1. SHA-256 hash calculation using Python's standard hashlib.
2. Verification comparing original acquisition hash against current file state.
3. Tamper simulation on working copies for viva/demonstration purposes.
"""

import hashlib
import os
import shutil


def calculate_sha256(file_path):
    """
    Calculates the SHA-256 cryptographic checksum of a file.
    Reads file in 64 KB (65,536 bytes) chunks to ensure:
    - Constant, low memory usage even for large CCTV video files.
    - Deterministic, bit-level cryptographic verification.
    
    Returns:
        Hexadecimal string representation of the 256-bit hash (64 hex characters).
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found for hash calculation: {file_path}")

    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest().lower()


def verify_file_integrity(original_hash, file_path):
    """
    Performs an integrity check on an evidence file.
    
    Calculates the current SHA-256 hash of the file on disk and compares
    it with the original hash recorded at acquisition.
    
    Returns:
        tuple: (is_valid: bool, current_hash: str, status_text: str)
        status_text is 'Integrity Verified' if hashes match,
        or 'Integrity Mismatch' if they differ.
    """
    current_hash = calculate_sha256(file_path)
    is_valid = (original_hash.lower().strip() == current_hash.lower().strip())
    status_text = "Integrity Verified" if is_valid else "Integrity Mismatch"

    return is_valid, current_hash, status_text


def simulate_tampering(working_path):
    """
    Academic Demonstration Helper:
    Simulates deliberate tampering by appending a 4-byte marker to the WORKING copy.
    The original evidence file is NEVER modified (forensic preservation).
    
    Returns:
        new_hash: str (The altered SHA-256 hash)
    """
    if not os.path.exists(working_path):
        raise FileNotFoundError(f"Working copy not found: {working_path}")

    # Append test tamper marker
    with open(working_path, 'ab') as f:
        f.write(b"\xDE\xAD\xBE\xEF_TAMPERED")

    return calculate_sha256(working_path)


def restore_working_copy(original_path, working_path):
    """
    Academic Demonstration Helper:
    Restores the working copy from the pristine, unmodified original evidence file.
    
    Returns:
        restored_hash: str
    """
    if not os.path.exists(original_path):
        raise FileNotFoundError(f"Original evidence file not found: {original_path}")

    shutil.copy2(original_path, working_path)
    return calculate_sha256(working_path)
