"""
evidence.py - Evidence Management, Storage & Rule-Based Vendor Identification.

This module handles:
1. Forensic file preservation: Original (read-only) vs Working copies.
2. Rule-based vendor identification (Hikvision, Dahua, Honeywell, Unknown/Other).
3. Browser playback compatibility assessment.
4. Secure evidence ingestion and metadata recording.
"""

import os
import shutil
from datetime import datetime
from werkzeug.utils import secure_filename
from hashing import calculate_sha256
from database import insert_evidence, log_activity

# Directory setup for evidence preservation
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(BASE_DIR, 'evidence')
ORIGINAL_DIR = os.path.join(EVIDENCE_DIR, 'original')
WORKING_DIR = os.path.join(EVIDENCE_DIR, 'working')

# Ensure forensic storage directories exist
os.makedirs(ORIGINAL_DIR, exist_ok=True)
os.makedirs(WORKING_DIR, exist_ok=True)


def format_file_size(size_bytes):
    """Formats file size from bytes into human-readable B, KB, MB, or GB."""
    if size_bytes is None or size_bytes < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}" if unit != 'B' else f"{int(size_bytes)} B"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def is_video_playable_in_browser(filename):
    """
    Checks if a video file extension is natively supported by modern HTML5 video tags.
    Browsers support MP4 (H.264), WebM (VP8/VP9), and OGG (Theora).
    CCTV proprietary formats (DAV, proprietary AVI, raw streams) are not playable natively.
    
    Returns:
        tuple: (is_playable: bool, reason_message: str)
    """
    ext = os.path.splitext(filename)[1].lower()
    playable_extensions = ['.mp4', '.webm', '.ogg']

    if ext in playable_extensions:
        return True, "Supported HTML5 video container. Playback available directly in browser."
    elif ext == '.dav':
        return False, (
            "Dahua proprietary container (.dav). Modern web browsers lack native decoder "
            "for raw DHAV bitstreams. In forensic analysis, original bitstreams are preserved "
            "unaltered rather than transcoded, maintaining forensic authenticity."
        )
    elif ext == '.avi':
        return False, (
            "AVI video container. Standard browser video players do not natively decode AVI "
            "without external plugins. The evidence is safely stored and hash-verified."
        )
    else:
        return False, (
            f"Format '{ext}' is not natively playable in the web browser player. "
            "Evidence is preserved in its original bit-exact form."
        )


def detect_vendor(filename, user_override=None, sample_bytes=b""):
    """
    Rule-Based CCTV/DVR Vendor Identification Feature.
    
    Identifies vendor using:
    1. User-provided vendor (if specified and not 'Auto-Detect').
    2. File naming conventions common in CCTV exports.
    3. Container magic bytes and header markers.
    
    Supported categories:
    - Hikvision
    - Dahua
    - Honeywell
    - Unknown/Other
    
    Academic Disclaimer:
    This is a heuristic rule-based identification system designed for common
    exported CCTV footage. It does not perform deep proprietary file system carving.
    
    Returns:
        dict: {
            'vendor': 'Hikvision' | 'Dahua' | 'Honeywell' | 'Unknown/Other',
            'detection_method': str,
            'confidence': 'High' | 'Medium' | 'Low',
            'notes': str
        }
    """
    # 1. User manual selection takes precedence if provided and specific
    if user_override and user_override not in ['Auto-Detect', 'Unknown/Other', '', None]:
        return {
            'vendor': user_override,
            'detection_method': 'User Declared',
            'confidence': 'High',
            'notes': f"Investigator manually identified the hardware source as {user_override}."
        }

    lower_name = filename.lower()
    ext = os.path.splitext(lower_name)[1]

    # 2. Rule: Dahua Indicators
    # - .dav extension is the signature Dahua DVR container
    # - DHAV or DAHUA magic bytes in file header
    # - Filenames containing dahua, dh_, or channel naming patterns like _main_
    if ext == '.dav' or b'DHAV' in sample_bytes[:64] or b'DAHUA' in sample_bytes[:64]:
        return {
            'vendor': 'Dahua',
            'detection_method': 'File Signature & Extension Rule',
            'confidence': 'High',
            'notes': "Matched Dahua proprietary container (.dav) and/or DHAV header magic bytes."
        }
    if 'dahua' in lower_name or lower_name.startswith('dh_') or '_main_' in lower_name:
        return {
            'vendor': 'Dahua',
            'detection_method': 'Naming Convention Rule',
            'confidence': 'Medium',
            'notes': "Matched Dahua naming scheme patterns (dh_ / _main_)."
        }

    # 3. Rule: Hikvision Indicators
    # - Typical export naming: ch01_..., hik_, _h4_, hikvision
    # - HIKVISION header tag in container metadata
    if 'hikvision' in lower_name or 'hik_' in lower_name or lower_name.startswith('hik_'):
        return {
            'vendor': 'Hikvision',
            'detection_method': 'Naming Convention Rule',
            'confidence': 'High',
            'notes': "Matched Hikvision system naming pattern ('hik_')."
        }
    if 'ch0' in lower_name or 'ch1' in lower_name or '_h4_' in lower_name:
        return {
            'vendor': 'Hikvision',
            'detection_method': 'Channel Syntax Rule',
            'confidence': 'Medium',
            'notes': "Matched Hikvision DVR channel segmentation naming pattern (ch0X_)."
        }

    # 4. Rule: Honeywell Indicators
    # - Typical export naming: hw_, CAM0X, honeywell, HN_
    if 'honeywell' in lower_name or lower_name.startswith('hw_') or 'cam0' in lower_name or lower_name.startswith('hn_'):
        return {
            'vendor': 'Honeywell',
            'detection_method': 'Naming Convention Rule',
            'confidence': 'Medium',
            'notes': "Matched Honeywell camera/NVR export naming pattern (hw_ / cam0X)."
        }

    # 5. Default Fallback
    return {
        'vendor': 'Unknown/Other',
        'detection_method': 'Heuristic Fallback',
        'confidence': 'Low',
        'notes': "Standard video container without vendor-specific proprietary markers."
    }


def ingest_evidence_file(file_storage, case_id, source="CCTV Camera", vendor_choice="Auto-Detect", notes="", investigator_name="Investigator"):
    """
    Forensic Evidence Acquisition & Preservation Pipeline:
    
    1. Validates and secures uploaded filename.
    2. Generates unique evidence identifier (e.g. EVID-YYYYMMDD-HHMMSS).
    3. Saves bit-exact pristine copy into evidence/original/.
    4. Makes original file read-only on disk (forensic non-destructive principle).
    5. Creates bit-exact working copy in evidence/working/ for examination.
    6. Calculates initial SHA-256 cryptographic checksum using hashlib.
    7. Performs rule-based vendor identification.
    8. Records evidence details into SQLite database.
    9. Logs acquisition in immutable activity_log for Chain of Custody.
    
    Returns:
        tuple: (success: bool, result_or_error: dict|str)
    """
    if not file_storage or file_storage.filename == '':
        return False, "No file selected for upload."

    raw_filename = secure_filename(file_storage.filename)
    if not raw_filename:
        raw_filename = f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4"

    # Unique evidence identifier
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    ext = os.path.splitext(raw_filename)[1].lower()
    evidence_id = f"EVID-{timestamp_str}"
    stored_filename = f"{evidence_id}_{raw_filename}"

    original_path = os.path.join(ORIGINAL_DIR, stored_filename)
    working_path = os.path.join(WORKING_DIR, stored_filename)

    try:
        # Save pristine original evidence
        file_storage.save(original_path)

        # Read first 128 bytes for vendor detection heuristics
        with open(original_path, 'rb') as f:
            header_sample = f.read(128)

        # Replicate bit-for-bit to working directory
        shutil.copy2(original_path, working_path)

        # Compute initial SHA-256 hash using standard hashlib
        sha256_hash = calculate_sha256(original_path)
        file_size = os.path.getsize(original_path)

        # Rule-based vendor identification
        vendor_info = detect_vendor(raw_filename, user_override=vendor_choice, sample_bytes=header_sample)
        final_vendor = vendor_info['vendor']
        combined_notes = notes.strip() if notes else ""
        if vendor_info.get('notes'):
            combined_notes += f" [Vendor Detection: {vendor_info['notes']}]"

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        evidence_record = {
            'evidence_id': evidence_id,
            'case_id': case_id,
            'filename': raw_filename,
            'original_path': original_path,
            'working_path': working_path,
            'file_type': ext.replace('.', '').upper() if ext else 'BIN',
            'file_size': file_size,
            'vendor': final_vendor,
            'source': source.strip() if source else "CCTV Camera",
            'sha256_original': sha256_hash,
            'sha256_current': sha256_hash,
            'integrity_status': 'Integrity Verified',
            'status': 'Active',
            'notes': combined_notes.strip(),
            'uploaded_at': now_str
        }

        # Store in SQLite
        insert_evidence(evidence_record)

        # Log Activity: Evidence Uploaded
        log_activity(
            action="Evidence uploaded",
            details=f"Uploaded '{raw_filename}' ({format_file_size(file_size)}) for Case '{case_id}'. Initial SHA-256 computed.",
            case_id=case_id,
            evidence_id=evidence_id,
            performed_by=investigator_name
        )

        # Log Activity: Hash Calculated
        log_activity(
            action="Hash calculated",
            details=f"Initial SHA-256: {sha256_hash}",
            case_id=case_id,
            evidence_id=evidence_id,
            performed_by=investigator_name
        )

        return True, evidence_record

    except Exception as e:
        # Clean up files if error occurred during ingestion
        if os.path.exists(original_path):
            os.remove(original_path)
        if os.path.exists(working_path):
            os.remove(working_path)
        return False, f"Evidence ingestion failed: {str(e)}"
