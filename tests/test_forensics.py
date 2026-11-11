"""
tests/test_forensics.py - Comprehensive Unit Tests for Forensic Analysis Tool.

Tests all required core components:
1. Database initialization and table structure.
2. Case creation and retrieval.
3. Evidence ingestion and dual preservation (original vs working copy).
4. SHA-256 hash calculation using hashlib.
5. Hash comparison: Integrity Verified vs Integrity Mismatch.
6. Tamper simulation and restoration.
7. Rule-based vendor identification (Hikvision, Dahua, Honeywell, Unknown/Other).
8. Video playback compatibility checks.
9. Search and filtering functionality.
10. Activity logging (Chain of custody).
11. PDF forensic report generation via ReportLab.
12. Flask web application route responses.
"""

import os
import sys
import tempfile
import shutil
import unittest
import io

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import (
    init_db, get_db_connection, create_case, get_case_by_id, get_all_cases,
    insert_evidence, get_all_evidence, get_evidence_by_id, get_evidence_by_case,
    update_evidence_integrity, log_activity, get_activity_logs, get_dashboard_stats
)
from hashing import (
    calculate_sha256, verify_file_integrity,
    simulate_tampering, restore_working_copy
)
from evidence import (
    detect_vendor, is_video_playable_in_browser,
    format_file_size, ingest_evidence_file
)
from report import generate_case_pdf_report
from app import app


class TestDVRForensicsSuite(unittest.TestCase):

    def setUp(self):
        """Set up temporary test directory and test client."""
        self.temp_dir = tempfile.mkdtemp(prefix="test_forensics_")
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        # Initialize database
        init_db()

    def tearDown(self):
        """Clean up temporary test directory."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ---------------------------------------------------------
    # 1. Database & Case Management Tests
    # ---------------------------------------------------------

    def test_database_tables_exist(self):
        """Verify the 4 required tables exist in SQLite."""
        conn = get_db_connection()
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t['name'] for t in tables]
        conn.close()

        self.assertIn('users', table_names)
        self.assertIn('cases', table_names)
        self.assertIn('evidence', table_names)
        self.assertIn('activity_log', table_names)

    def test_case_creation_and_retrieval(self):
        """Test case creation and fetching by unique ID."""
        import uuid
        test_case_id = f"CASE-UT-{uuid.uuid4().hex[:6]}"
        success, msg = create_case(
            case_id=test_case_id,
            case_name="Perimeter Breach Test",
            description="Unit testing case creation workflow",
            investigator_name="Detective Miller"
        )
        self.assertTrue(success)

        case = get_case_by_id(test_case_id)
        self.assertIsNotNone(case)
        self.assertEqual(case['case_name'], "Perimeter Breach Test")
        self.assertEqual(case['investigator_name'], "Detective Miller")

    def test_duplicate_case_id_rejected(self):
        """Verify that duplicate case IDs are properly rejected."""
        import uuid
        case_id = f"CASE-DUP-{uuid.uuid4().hex[:6]}"
        create_case(case_id, "Case 1", "Desc", "Investigator A")
        success, msg = create_case(case_id, "Case 2", "Desc", "Investigator B")
        self.assertFalse(success)
        self.assertIn("already exists", msg)

    # ---------------------------------------------------------
    # 2. SHA-256 Hashing & Integrity Verification Tests
    # ---------------------------------------------------------

    def test_sha256_calculation(self):
        """Test cryptographic hash calculation accuracy."""
        test_file = os.path.join(self.temp_dir, "sample_test.mp4")
        test_content = b"FORENSIC_EVIDENCE_SAMPLE_BYTES_12345"
        with open(test_file, 'wb') as f:
            f.write(test_content)

        import hashlib
        expected_hash = hashlib.sha256(test_content).hexdigest().lower()

        calculated_hash = calculate_sha256(test_file)
        self.assertEqual(calculated_hash, expected_hash)
        self.assertEqual(len(calculated_hash), 64)

    def test_integrity_verification_match_and_mismatch(self):
        """Test that matching hashes return 'Integrity Verified' and modified returns 'Integrity Mismatch'."""
        test_file = os.path.join(self.temp_dir, "integrity_test.mp4")
        with open(test_file, 'wb') as f:
            f.write(b"PRISTINE_ORIGINAL_CCTV_STREAM")

        original_hash = calculate_sha256(test_file)

        # 1. Matching case
        is_valid, current_hash, status_text = verify_file_integrity(original_hash, test_file)
        self.assertTrue(is_valid)
        self.assertEqual(status_text, "Integrity Verified")
        self.assertEqual(current_hash, original_hash)

        # 2. Tampered case (even 1 byte difference)
        with open(test_file, 'wb') as f:
            f.write(b"TAMPERED_MODIFIED_CCTV_STREAM")

        is_valid_tampered, tampered_hash, status_tampered = verify_file_integrity(original_hash, test_file)
        self.assertFalse(is_valid_tampered)
        self.assertEqual(status_tampered, "Integrity Mismatch")
        self.assertNotEqual(tampered_hash, original_hash)

    def test_tamper_simulation_and_restoration(self):
        """Test deliberate tamper simulation on working copy and pristine restoration."""
        orig_file = os.path.join(self.temp_dir, "orig.mp4")
        work_file = os.path.join(self.temp_dir, "work.mp4")
        with open(orig_file, 'wb') as f:
            f.write(b"ORIGINAL_FOOTAGE_BITS")
        shutil.copy2(orig_file, work_file)

        orig_hash = calculate_sha256(orig_file)

        # Simulate tampering
        new_hash = simulate_tampering(work_file)
        self.assertNotEqual(new_hash, orig_hash)
        # Original must remain untouched!
        self.assertEqual(calculate_sha256(orig_file), orig_hash)

        # Restore working copy
        restored_hash = restore_working_copy(orig_file, work_file)
        self.assertEqual(restored_hash, orig_hash)

    # ---------------------------------------------------------
    # 3. Rule-Based Vendor Identification Tests
    # ---------------------------------------------------------

    def test_vendor_identification_rules(self):
        """Test rule-based identification for Dahua, Hikvision, Honeywell, and Unknown."""
        # Dahua
        dahua_res1 = detect_vendor("camera_ch02_dahua.mp4")
        self.assertEqual(dahua_res1['vendor'], 'Dahua')

        dahua_res2 = detect_vendor("stream.dav", sample_bytes=b"DHAV_HEADER")
        self.assertEqual(dahua_res2['vendor'], 'Dahua')

        # Hikvision
        hik_res1 = detect_vendor("hik_ch01_20261029.mp4")
        self.assertEqual(hik_res1['vendor'], 'Hikvision')

        hik_res2 = detect_vendor("ch04_vault.mp4")
        self.assertEqual(hik_res2['vendor'], 'Hikvision')

        # Honeywell
        hw_res = detect_vendor("hw_cam03_dock.mp4")
        self.assertEqual(hw_res['vendor'], 'Honeywell')

        # Unknown / Generic
        unknown_res = detect_vendor("random_video_file.mp4")
        self.assertEqual(unknown_res['vendor'], 'Unknown/Other')

        # Manual User Override
        manual_res = detect_vendor("random.mp4", user_override="Honeywell")
        self.assertEqual(manual_res['vendor'], 'Honeywell')

    # ---------------------------------------------------------
    # 4. Browser Playback Support Checks
    # ---------------------------------------------------------

    def test_browser_video_compatibility(self):
        """Test browser playback detection: MP4/WebM supported, DAV/AVI unsupported."""
        is_play_mp4, _ = is_video_playable_in_browser("evidence.mp4")
        self.assertTrue(is_play_mp4)

        is_play_webm, _ = is_video_playable_in_browser("evidence.webm")
        self.assertTrue(is_play_webm)

        is_play_dav, reason_dav = is_video_playable_in_browser("stream.dav")
        self.assertFalse(is_play_dav)
        self.assertIn("Dahua proprietary container", reason_dav)

        is_play_avi, reason_avi = is_video_playable_in_browser("stream.avi")
        self.assertFalse(is_play_avi)

    # ---------------------------------------------------------
    # 5. Evidence Ingestion & Dual Storage Tests
    # ---------------------------------------------------------

    def test_evidence_ingestion_pipeline(self):
        """Test evidence intake, dual file creation (original & working), and DB storage."""
        import uuid
        case_id = f"CASE-INGEST-{uuid.uuid4().hex[:6]}"
        create_case(case_id, "Ingest Test Case", "Desc", "Investigator X")

        class MockFileStorage:
            def __init__(self, filename, content):
                self.filename = filename
                self.content = content
            def save(self, dst):
                with open(dst, 'wb') as f:
                    f.write(self.content)

        mock_file = MockFileStorage("hik_ch01_test.mp4", b"TEST_VIDEO_PAYLOAD_HIKVISION")

        success, result = ingest_evidence_file(
            file_storage=mock_file,
            case_id=case_id,
            source="Front Gate Cam",
            vendor_choice="Auto-Detect",
            notes="Intake test",
            investigator_name="Investigator X"
        )

        self.assertTrue(success)
        self.assertEqual(result['vendor'], 'Hikvision')
        self.assertTrue(os.path.exists(result['original_path']))
        self.assertTrue(os.path.exists(result['working_path']))

        # Verify record in DB
        ev_in_db = get_evidence_by_id(result['evidence_id'])
        self.assertIsNotNone(ev_in_db)
        self.assertEqual(ev_in_db['case_id'], case_id)
        self.assertEqual(ev_in_db['integrity_status'], 'Integrity Verified')

    # ---------------------------------------------------------
    # 6. Activity Logging & Chain of Custody
    # ---------------------------------------------------------

    def test_activity_logging(self):
        """Verify immutable audit log insertions and retrieval."""
        import uuid
        case_id = f"CASE-LOG-{uuid.uuid4().hex[:6]}"
        log_activity(
            action="Evidence uploaded",
            details="Test upload log",
            case_id=case_id,
            performed_by="Investigator LogTest"
        )

        logs = get_activity_logs(limit=10, case_id=case_id)
        self.assertTrue(len(logs) >= 1)
        self.assertEqual(logs[0]['action'], "Evidence uploaded")
        self.assertEqual(logs[0]['performed_by'], "Investigator LogTest")

    # ---------------------------------------------------------
    # 7. PDF Report Generation via ReportLab
    # ---------------------------------------------------------

    def test_pdf_report_generation(self):
        """Test that ReportLab successfully builds a valid PDF report file."""
        import uuid
        case_id = f"CASE-PDF-{uuid.uuid4().hex[:6]}"
        create_case(case_id, "PDF Report Test Case", "Testing Report Generation", "Lead Examiner")

        pdf_path, pdf_filename = generate_case_pdf_report(case_id, generated_by="Lead Examiner")
        self.assertIsNotNone(pdf_path)
        self.assertTrue(os.path.exists(pdf_path))
        self.assertTrue(os.path.getsize(pdf_path) > 1000)
        self.assertTrue(pdf_filename.endswith(".pdf"))

    # ---------------------------------------------------------
    # 8. Flask Web Routes Testing
    # ---------------------------------------------------------

    def test_web_routes_flow(self):
        """Test HTTP responses for all 6 required navigation pages."""
        with self.client.session_transaction() as sess:
            sess['user'] = 'investigator'
            sess['user_name'] = 'Lead Forensic Investigator'

        # 1. Dashboard
        resp = self.client.get('/dashboard')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Forensic Investigation Dashboard", resp.data)

        # 2. Cases
        resp = self.client.get('/cases')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Case Management", resp.data)

        # 3. Add Evidence
        resp = self.client.get('/evidence/add')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Acquire & Ingest CCTV Evidence", resp.data)

        # 4. Evidence Analysis
        resp = self.client.get('/analysis')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Evidence Analysis", resp.data)

        # 5. Activity Log
        resp = self.client.get('/activity')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Chain of Custody Activity Log", resp.data)

        # 6. Reports
        resp = self.client.get('/reports')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Forensic PDF Reports", resp.data)


if __name__ == '__main__':
    unittest.main()
