"""
database.py - SQLite Database Management for Forensic Analysis Tool.

This module handles:
1. SQLite connection management and table creation.
2. The four core forensic tables: Users, Cases, Evidence, Activity_Log.
3. CRUD helper functions for cases, evidence, and audit logging.
"""

import os
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Path to SQLite database file
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forensics.db')


def get_db_connection():
    """
    Establishes and returns a connection to the SQLite database.
    Configures Row factory so columns can be accessed by name.
    Enables foreign key enforcement.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """
    Initializes the database schema with the 4 required tables:
    1. users: Authorized forensic investigators.
    2. cases: Investigation case files.
    3. evidence: CCTV video evidence records and integrity hashes.
    4. activity_log: Immutable audit trail for chain of custody.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT DEFAULT 'Investigator',
        created_at TEXT NOT NULL
    )
    """)

    # 2. Cases Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE NOT NULL,
        case_name TEXT NOT NULL,
        description TEXT,
        investigator_name TEXT NOT NULL,
        status TEXT DEFAULT 'Open',
        created_at TEXT NOT NULL
    )
    """)

    # 3. Evidence Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id TEXT UNIQUE NOT NULL,
        case_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        original_path TEXT NOT NULL,
        working_path TEXT NOT NULL,
        file_type TEXT,
        file_size INTEGER,
        vendor TEXT,
        source TEXT,
        sha256_original TEXT NOT NULL,
        sha256_current TEXT NOT NULL,
        integrity_status TEXT DEFAULT 'Integrity Verified',
        status TEXT DEFAULT 'Active',
        notes TEXT,
        uploaded_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    )
    """)

    # 4. Activity_Log Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        details TEXT,
        case_id TEXT,
        evidence_id TEXT,
        performed_by TEXT DEFAULT 'Investigator',
        timestamp TEXT NOT NULL
    )
    """)

    # Seed default investigator if no users exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_hash = generate_password_hash("forensics123")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, ('investigator', default_hash, 'Lead Forensic Investigator', 'Investigator', now))

    conn.commit()
    conn.close()


def log_activity(action, details, case_id=None, evidence_id=None, performed_by='Investigator'):
    """
    Records an immutable action in the activity_log for Chain of Custody.
    Actions include: Evidence uploaded, Hash calculated, Evidence analyzed,
    Integrity verified, Report generated, Case created.
    """
    conn = get_db_connection()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO activity_log (action, details, case_id, evidence_id, performed_by, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (action, details, case_id, evidence_id, performed_by, timestamp))
    conn.commit()
    conn.close()


# -------------------------------------------------------------
# Case Helper Functions
# -------------------------------------------------------------

def get_all_cases():
    """Returns all cases ordered by creation date descending."""
    conn = get_db_connection()
    cases = conn.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    conn.close()
    return cases


def get_case_by_id(case_id):
    """Returns a specific case by its unique case_id."""
    conn = get_db_connection()
    case = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    conn.close()
    return case


def create_case(case_id, case_name, description, investigator_name):
    """
    Creates a new case record and logs the creation activity.
    Returns (success: bool, message: str).
    """
    conn = get_db_connection()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn.execute("""
            INSERT INTO cases (case_id, case_name, description, investigator_name, status, created_at)
            VALUES (?, ?, ?, ?, 'Open', ?)
        """, (case_id.strip(), case_name.strip(), description.strip(), investigator_name.strip(), now))
        conn.commit()
        conn.close()

        log_activity(
            action="Case created",
            details=f"Case '{case_name.strip()}' initialized by {investigator_name.strip()}.",
            case_id=case_id.strip(),
            performed_by=investigator_name.strip()
        )
        return True, "Case created successfully."
    except sqlite3.IntegrityError:
        conn.close()
        return False, f"Case ID '{case_id}' already exists. Please choose a unique Case ID."
    except Exception as e:
        conn.close()
        return False, f"Error creating case: {str(e)}"


# -------------------------------------------------------------
# Evidence Helper Functions
# -------------------------------------------------------------

def get_all_evidence(case_id=None, search=None, vendor=None, status=None):
    """
    Returns evidence records with optional filtering by case_id, search term,
    vendor, or integrity status.
    """
    conn = get_db_connection()
    query = "SELECT * FROM evidence WHERE 1=1"
    params = []

    if case_id:
        query += " AND case_id = ?"
        params.append(case_id)
    if vendor and vendor != 'All':
        query += " AND vendor = ?"
        params.append(vendor)
    if status and status != 'All':
        query += " AND integrity_status = ?"
        params.append(status)
    if search:
        query += " AND (filename LIKE ? OR evidence_id LIKE ? OR source LIKE ? OR notes LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])

    query += " ORDER BY id DESC"
    evidence = conn.execute(query, params).fetchall()
    conn.close()
    return evidence


def get_evidence_by_case(case_id):
    """Returns all evidence items linked to a specific case."""
    conn = get_db_connection()
    evidence = conn.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY id DESC", (case_id,)).fetchall()
    conn.close()
    return evidence


def get_evidence_by_id(evidence_id):
    """Returns an evidence record by its unique evidence_id."""
    conn = get_db_connection()
    evidence = conn.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
    conn.close()
    return evidence


def insert_evidence(evidence_data):
    """Inserts a new evidence record into SQLite."""
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO evidence (
            evidence_id, case_id, filename, original_path, working_path,
            file_type, file_size, vendor, source, sha256_original,
            sha256_current, integrity_status, status, notes, uploaded_at
        ) VALUES (
            :evidence_id, :case_id, :filename, :original_path, :working_path,
            :file_type, :file_size, :vendor, :source, :sha256_original,
            :sha256_current, :integrity_status, :status, :notes, :uploaded_at
        )
    """, evidence_data)
    conn.commit()
    conn.close()


def update_evidence_integrity(evidence_id, current_hash, integrity_status):
    """Updates the current SHA-256 hash and integrity status for an evidence record."""
    conn = get_db_connection()
    conn.execute("""
        UPDATE evidence
        SET sha256_current = ?, integrity_status = ?
        WHERE evidence_id = ?
    """, (current_hash, integrity_status, evidence_id))
    conn.commit()
    conn.close()


# -------------------------------------------------------------
# Activity Log & Dashboard Statistics
# -------------------------------------------------------------

def get_activity_logs(limit=50, case_id=None):
    """Returns the most recent activity log entries."""
    conn = get_db_connection()
    if case_id:
        logs = conn.execute(
            "SELECT * FROM activity_log WHERE case_id = ? ORDER BY id DESC LIMIT ?",
            (case_id, limit)
        ).fetchall()
    else:
        logs = conn.execute(
            "SELECT * FROM activity_log ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return logs


def get_dashboard_stats():
    """
    Computes summary metrics for the main dashboard:
    - Total Cases
    - Total Evidence Files
    - Videos Available
    - Recent Activities count and list
    """
    conn = get_db_connection()

    total_cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    total_evidence = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    # Video files are files with video extensions or playable formats
    video_extensions = ('.mp4', '.avi', '.dav', '.mkv', '.mov', '.webm', '.flv')
    all_evidence = conn.execute("SELECT filename FROM evidence").fetchall()
    videos_available = sum(
        1 for row in all_evidence
        if any(row['filename'].lower().endswith(ext) for ext in video_extensions)
    )

    recent_activities = conn.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0]
    recent_logs = conn.execute("SELECT * FROM activity_log ORDER BY id DESC LIMIT 5").fetchall()

    conn.close()

    return {
        'total_cases': total_cases,
        'total_evidence': total_evidence,
        'videos_available': videos_available,
        'recent_activities': recent_activities,
        'recent_logs': recent_logs
    }


# -------------------------------------------------------------
# User Authentication Helpers
# -------------------------------------------------------------

def authenticate_user(username, password):
    """Validates user credentials against password hash."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        return user
    return None
