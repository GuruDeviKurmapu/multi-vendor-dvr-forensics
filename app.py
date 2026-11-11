"""
app.py - Main Flask Application Controller.

Multi-Vendor DVR/NVR Forensic Analysis Tool for CCTV Evidence.

This module provides the HTTP web routes for:
1. Dashboard (/dashboard)
2. Cases Management (/cases, /cases/<case_id>)
3. Evidence Acquisition & Upload (/evidence/add)
4. Evidence Analysis & Filter (/analysis)
5. Video Viewer & Integrity Verification (/evidence/view/<evidence_id>)
6. Activity Log / Chain of Custody (/activity)
7. Report Generation & Download (/reports)
"""

import os
import functools
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort
)

from database import (
    init_db, authenticate_user, get_dashboard_stats,
    get_all_cases, get_case_by_id, create_case,
    get_all_evidence, get_evidence_by_case, get_evidence_by_id,
    update_evidence_integrity, get_activity_logs, log_activity,
    insert_evidence, DB_PATH
)
from hashing import (
    calculate_sha256, verify_file_integrity,
    simulate_tampering, restore_working_copy
)
from evidence import (
    ingest_evidence_file, format_file_size,
    is_video_playable_in_browser, EVIDENCE_DIR, ORIGINAL_DIR, WORKING_DIR
)
from report import generate_case_pdf_report, REPORTS_DIR

app = Flask(__name__)
app.secret_key = 'forensic-academic-prototype-key-2026'

# Custom Jinja filters
@app.template_filter('format_bytes')
def jinja_format_bytes(size):
    return format_file_size(size)


def login_required(f):
    """Decorator to require login on protected forensic routes."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please sign in to access the forensic analysis tool.", "info")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles investigator sign-in and one-click demo login."""
    if request.method == 'POST':
        action = request.form.get('action')
        
        # One-click demo login for academic review
        if action == 'demo_login':
            session['user'] = 'investigator'
            session['user_name'] = 'Lead Forensic Investigator'
            session['role'] = 'Investigator'
            flash("Signed in successfully as Lead Forensic Investigator (Demo Mode).", "success")
            return redirect(url_for('dashboard'))

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = authenticate_user(username, password)
        if user:
            session['user'] = user['username']
            session['user_name'] = user['full_name']
            session['role'] = user['role']
            flash(f"Welcome back, {user['full_name']}.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. You may use the 'Demo Login' button below.", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logs out the current investigator."""
    session.clear()
    flash("You have signed out of the forensic workbench.", "info")
    return redirect(url_for('login'))


# -------------------------------------------------------------
# 1. Main Dashboard
# -------------------------------------------------------------

@app.route('/')
def index():
    """Default entry point redirects to dashboard."""
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@login_required
def dashboard():
    """
    Main forensic dashboard displaying:
    - Total Cases
    - Total Evidence Files
    - Videos Available
    - Recent Activities
    """
    stats = get_dashboard_stats()
    recent_cases = get_all_cases()[:5]
    recent_evidence = get_all_evidence()[:5]

    return render_template(
        'dashboard.html',
        stats=stats,
        recent_cases=recent_cases,
        recent_evidence=recent_evidence
    )


# -------------------------------------------------------------
# 2. Case Management
# -------------------------------------------------------------

@app.route('/cases')
@login_required
def cases():
    """View all registered cases and form to create a new case."""
    all_cases = get_all_cases()
    return render_template('cases.html', cases=all_cases)


@app.route('/cases/create', methods=['POST'])
@login_required
def create_case_route():
    """Handles POST submission to create a new case."""
    case_id = request.form.get('case_id', '').strip()
    case_name = request.form.get('case_name', '').strip()
    description = request.form.get('description', '').strip()
    investigator = request.form.get('investigator_name', session.get('user_name', 'Investigator')).strip()

    if not case_id or not case_name:
        flash("Case ID and Case Name are required fields.", "danger")
        return redirect(url_for('cases'))

    success, msg = create_case(case_id, case_name, description, investigator)
    if success:
        flash(f"Case '{case_id}' created successfully.", "success")
        return redirect(url_for('case_details', case_id=case_id))
    else:
        flash(msg, "danger")
        return redirect(url_for('cases'))


@app.route('/cases/<case_id>')
@login_required
def case_details(case_id):
    """Displays detailed view of a single case and its associated evidence."""
    case = get_case_by_id(case_id)
    if not case:
        flash(f"Case '{case_id}' was not found.", "danger")
        return redirect(url_for('cases'))

    evidence_list = get_evidence_by_case(case_id)
    case_logs = get_activity_logs(limit=20, case_id=case_id)

    return render_template(
        'case_details.html',
        case=case,
        evidence_list=evidence_list,
        logs=case_logs
    )


# -------------------------------------------------------------
# 3. Evidence Upload & Ingestion
# -------------------------------------------------------------

@app.route('/evidence/add', methods=['GET', 'POST'])
@login_required
def add_evidence():
    """Uploads CCTV evidence file and associates it with a case."""
    all_cases = get_all_cases()

    if request.method == 'POST':
        case_id = request.form.get('case_id')
        source = request.form.get('source', 'CCTV Camera')
        vendor_choice = request.form.get('vendor', 'Auto-Detect')
        notes = request.form.get('notes', '')
        file_obj = request.files.get('evidence_file')

        if not case_id:
            flash("Please select a valid Case to link this evidence.", "danger")
            return redirect(url_for('add_evidence'))

        if not file_obj or file_obj.filename == '':
            flash("Please choose a video evidence file to upload.", "danger")
            return redirect(url_for('add_evidence'))

        success, result = ingest_evidence_file(
            file_storage=file_obj,
            case_id=case_id,
            source=source,
            vendor_choice=vendor_choice,
            notes=notes,
            investigator_name=session.get('user_name', 'Investigator')
        )

        if success:
            flash(
                f"Evidence '{result['filename']}' successfully ingested as {result['evidence_id']}. "
                f"Detected Vendor: {result['vendor']}. Initial SHA-256 hash verified.",
                "success"
            )
            return redirect(url_for('evidence_view', evidence_id=result['evidence_id']))
        else:
            flash(f"Failed to ingest evidence: {result}", "danger")
            return redirect(url_for('add_evidence'))

    # Pre-select case if passed via query parameter (e.g. ?case_id=CASE-001)
    preselected_case = request.args.get('case_id', '')
    return render_template('add_evidence.html', cases=all_cases, preselected_case=preselected_case)


# -------------------------------------------------------------
# 4. Evidence Analysis & Filter
# -------------------------------------------------------------

@app.route('/analysis')
@login_required
def analysis():
    """
    Evidence analysis table displaying:
    Filename, File type, File size, Vendor, Date added, SHA-256 hash, Evidence status.
    Allows searching and filtering by case, vendor, and status.
    """
    case_filter = request.args.get('case_id', '')
    vendor_filter = request.args.get('vendor', '')
    status_filter = request.args.get('status', '')
    search_query = request.args.get('search', '').strip()

    evidence_list = get_all_evidence(
        case_id=case_filter if case_filter else None,
        search=search_query if search_query else None,
        vendor=vendor_filter if vendor_filter else None,
        status=status_filter if status_filter else None
    )

    all_cases = get_all_cases()

    return render_template(
        'analysis.html',
        evidence_list=evidence_list,
        cases=all_cases,
        selected_case=case_filter,
        selected_vendor=vendor_filter,
        selected_status=status_filter,
        search_query=search_query
    )


# -------------------------------------------------------------
# 5. Video Viewer & Integrity Verification
# -------------------------------------------------------------

@app.route('/evidence/view/<evidence_id>')
@login_required
def evidence_view(evidence_id):
    """
    Displays the video preview, available metadata, cryptographic hash,
    and integrity verification controls.
    """
    evidence = get_evidence_by_id(evidence_id)
    if not evidence:
        flash(f"Evidence '{evidence_id}' not found.", "danger")
        return redirect(url_for('analysis'))

    is_playable, play_message = is_video_playable_in_browser(evidence['filename'])
    case = get_case_by_id(evidence['case_id'])

    # Audit log entry for evidence examination
    log_activity(
        action="Evidence analyzed",
        details=f"Opened forensic examination viewer for '{evidence['filename']}' ({evidence_id}).",
        case_id=evidence['case_id'],
        evidence_id=evidence_id,
        performed_by=session.get('user_name', 'Investigator')
    )

    return render_template(
        'video_viewer.html',
        evidence=evidence,
        case=case,
        is_playable=is_playable,
        play_message=play_message
    )


@app.route('/evidence/stream/<evidence_id>')
@login_required
def stream_evidence(evidence_id):
    """Streams the working copy video file directly to the browser video element."""
    evidence = get_evidence_by_id(evidence_id)
    if not evidence or not os.path.exists(evidence['working_path']):
        abort(404, description="Video file not found on disk.")

    ext = os.path.splitext(evidence['filename'])[1].lower()
    mimetype = 'video/mp4'
    if ext == '.webm':
        mimetype = 'video/webm'
    elif ext == '.ogg':
        mimetype = 'video/ogg'

    return send_file(evidence['working_path'], mimetype=mimetype)


@app.route('/evidence/download/<evidence_id>')
@login_required
def download_evidence(evidence_id):
    """Downloads the working copy of the evidence file."""
    evidence = get_evidence_by_id(evidence_id)
    if not evidence or not os.path.exists(evidence['working_path']):
        abort(404, description="Evidence file not found.")

    return send_file(
        evidence['working_path'],
        as_attachment=True,
        download_name=evidence['filename']
    )


@app.route('/evidence/verify/<evidence_id>', methods=['POST'])
@login_required
def verify_integrity_route(evidence_id):
    """
    Calculates current SHA-256 hash using Python hashlib and compares
    it with the original recorded hash.
    Updates database integrity status to 'Integrity Verified' or 'Integrity Mismatch'.
    """
    evidence = get_evidence_by_id(evidence_id)
    if not evidence:
        flash("Evidence not found.", "danger")
        return redirect(url_for('analysis'))

    is_valid, current_hash, status_text = verify_file_integrity(
        evidence['sha256_original'], evidence['working_path']
    )

    update_evidence_integrity(evidence_id, current_hash, status_text)

    log_activity(
        action="Hash calculated",
        details=f"Integrity check performed: {status_text}. Current SHA-256: {current_hash}",
        case_id=evidence['case_id'],
        evidence_id=evidence_id,
        performed_by=session.get('user_name', 'Investigator')
    )

    if is_valid:
        flash(f"Integrity check passed! {status_text}: SHA-256 matches bit-for-bit.", "success")
    else:
        flash(f"CRITICAL WARNING! {status_text}: The current hash differs from the acquisition hash!", "danger")

    return redirect(url_for('evidence_view', evidence_id=evidence_id))


@app.route('/evidence/tamper/<evidence_id>', methods=['POST'])
@login_required
def simulate_tamper_route(evidence_id):
    """
    Academic Demonstration Feature:
    Simulates deliberate tampering by appending bytes to the WORKING copy only.
    Demonstrates how SHA-256 immediately detects unauthorized alterations.
    """
    evidence = get_evidence_by_id(evidence_id)
    if not evidence:
        flash("Evidence not found.", "danger")
        return redirect(url_for('analysis'))

    new_hash = simulate_tampering(evidence['working_path'])
    status_text = "Integrity Mismatch"
    update_evidence_integrity(evidence_id, new_hash, status_text)

    log_activity(
        action="Integrity verification",
        details=f"TAMPER SIMULATION: Altered working copy. SHA-256 changed to {new_hash}.",
        case_id=evidence['case_id'],
        evidence_id=evidence_id,
        performed_by=session.get('user_name', 'Investigator')
    )

    flash(
        "Tamper simulated on working copy! A 4-byte modification was made. "
        "Notice that the SHA-256 hash has changed and status is now 'Integrity Mismatch'.",
        "warning"
    )
    return redirect(url_for('evidence_view', evidence_id=evidence_id))


@app.route('/evidence/restore/<evidence_id>', methods=['POST'])
@login_required
def restore_working_copy_route(evidence_id):
    """
    Academic Demonstration Feature:
    Restores the working copy from the pristine, untouched original evidence file.
    """
    evidence = get_evidence_by_id(evidence_id)
    if not evidence:
        flash("Evidence not found.", "danger")
        return redirect(url_for('analysis'))

    restored_hash = restore_working_copy(evidence['original_path'], evidence['working_path'])
    status_text = "Integrity Verified"
    update_evidence_integrity(evidence_id, restored_hash, status_text)

    log_activity(
        action="Integrity verification",
        details="Restored working copy from pristine original. Integrity re-verified.",
        case_id=evidence['case_id'],
        evidence_id=evidence_id,
        performed_by=session.get('user_name', 'Investigator')
    )

    flash("Working copy restored from pristine original evidence. Integrity is now re-verified!", "success")
    return redirect(url_for('evidence_view', evidence_id=evidence_id))


# -------------------------------------------------------------
# 6. Activity Log
# -------------------------------------------------------------

@app.route('/activity')
@login_required
def activity():
    """
    Displays the complete forensic Activity Log:
    - Evidence uploaded
    - Hash calculated
    - Evidence analyzed
    - Report generated
    - Case created
    """
    case_filter = request.args.get('case_id', '')
    logs = get_activity_logs(limit=100, case_id=case_filter if case_filter else None)
    all_cases = get_all_cases()

    return render_template('activity.html', logs=logs, cases=all_cases, selected_case=case_filter)


# -------------------------------------------------------------
# 7. Reports
# -------------------------------------------------------------

@app.route('/reports')
@login_required
def reports():
    """Lists generated forensic PDF reports with download buttons."""
    all_cases = get_all_cases()
    report_files = []

    if os.path.exists(REPORTS_DIR):
        for fname in os.listdir(REPORTS_DIR):
            if fname.lower().endswith('.pdf'):
                fpath = os.path.join(REPORTS_DIR, fname)
                report_files.append({
                    'filename': fname,
                    'size': format_file_size(os.path.getsize(fpath)),
                    'date': os.path.getmtime(fpath)
                })
        # Sort newest first
        report_files.sort(key=lambda x: x['date'], reverse=True)

    return render_template('reports.html', cases=all_cases, reports=report_files)


@app.route('/reports/generate/<case_id>', methods=['POST', 'GET'])
@login_required
def generate_report_route(case_id):
    """Generates a downloadable PDF report for a case."""
    pdf_path, pdf_filename = generate_case_pdf_report(
        case_id=case_id,
        generated_by=session.get('user_name', 'Lead Forensic Investigator')
    )

    if not pdf_path:
        flash(f"Could not generate report: {pdf_filename}", "danger")
        return redirect(url_for('reports'))

    flash(f"Forensic report '{pdf_filename}' generated successfully.", "success")
    return redirect(url_for('reports'))


@app.route('/reports/download/<filename>')
@login_required
def download_report(filename):
    """Downloads a generated PDF report."""
    safe_name = os.path.basename(filename)
    report_path = os.path.join(REPORTS_DIR, safe_name)

    if not os.path.exists(report_path):
        abort(404, description="Report file not found.")

    return send_file(report_path, as_attachment=True, download_name=safe_name)


# -------------------------------------------------------------
# Helper: Seed Initial Demo Data (for examiner review)
# -------------------------------------------------------------

def seed_initial_demo_data():
    """
    Seeds a sample case and sample evidence files if the database is newly initialized.
    Copies sample files from evidence/demo_staging/ if available.
    """
    init_db()
    existing_cases = get_all_cases()
    if len(existing_cases) == 0:
        create_case(
            case_id="CASE-2026-001",
            case_name="Commercial Jewelry Store CCTV Incident",
            description="Forensic investigation into after-hours unauthorized entry captured across perimeter and vault CCTV units.",
            investigator_name="Lead Forensic Investigator"
        )

        staging_dir = os.path.join(EVIDENCE_DIR, 'demo_staging')
        if os.path.exists(staging_dir):
            demo_items = [
                ('hik_ch01_20261029_100000.mp4', 'Main Entrance - Channel 1', 'Auto-Detect', 'Hikvision 4MP Turret Dome export.'),
                ('dahua_ch02_20261029_101500.mp4', 'Cash Counter - Channel 2', 'Auto-Detect', 'Dahua 5MP Bullet Camera export.'),
                ('hw_CAM03_20261029_103000.mp4', 'Rear Loading Dock - Camera 3', 'Auto-Detect', 'Honeywell NVR export footage.'),
                ('proprietary_vendor_stream.dav', 'Back Alley Perimeter DVR', 'Auto-Detect', 'Dahua proprietary raw bitstream (.dav). Demonstrates unsupported browser container handling.')
            ]

            for fname, src, v_choice, note in demo_items:
                source_file = os.path.join(staging_dir, fname)
                if os.path.exists(source_file):
                    class DummyFileStorage:
                        def __init__(self, path, name):
                            self.path = path
                            self.filename = name
                        def save(self, dest):
                            shutil.copy2(self.path, dest)

                    dummy = DummyFileStorage(source_file, fname)
                    ingest_evidence_file(
                        file_storage=dummy,
                        case_id="CASE-2026-001",
                        source=src,
                        vendor_choice=v_choice,
                        notes=note,
                        investigator_name="Lead Forensic Investigator"
                    )


# Ensure database & sample data exist when starting
with app.app_context():
    seed_initial_demo_data()


if __name__ == '__main__':
    # Academic prototype default host and port
    app.run(host='127.0.0.1', port=5000, debug=True)
