# Multi-Vendor DVR/NVR Forensic Analysis Tool for CCTV Evidence

[![Forensic Tool CI](https://github.com/GuruDeviKurmapu/multi-vendor-dvr-forensics/actions/workflows/test.yml/badge.svg)](https://github.com/GuruDeviKurmapu/multi-vendor-dvr-forensics/actions)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](#)
[![Integrity SHA-256](https://img.shields.io/badge/Integrity-SHA--256-green.svg)](#)

A clean, beginner-friendly academic digital forensic application designed for B.Tech Computer Science & Engineering capstone reviews and laboratory demonstrations.

---

## 1. Project Overview

In criminal investigations and corporate security audits, CCTV video evidence is the primary source of factual playback. However, forensic investigators face several challenges:
- Different surveillance manufacturers (e.g., **Hikvision**, **Dahua**, **Honeywell**) export recordings with distinct filename syntaxes, proprietary containers, and differing codec streams.
- Digital evidence must strictly adhere to the **Forensic Non-Destructive Principle**: the original physical evidence must never be altered or tampered with.
- Digital exhibits presented in a court of law must have verified cryptographic integrity (using **SHA-256**) and an unbroken **Chain of Custody audit trail**.

This project provides a simple, robust, and understandable web application built purely with Python, Flask, SQLite, HTML5, CSS3, and standard cryptographic hashing.

---

## 2. Technology Stack

- **Python 3**: Core backend programming language.
- **Flask**: Lightweight web framework and HTTP routing controller.
- **SQLite 3**: Embedded relational database (`forensics.db`).
- **Python `hashlib`**: Cryptographic SHA-256 checksum computation and live verification.
- **ReportLab**: Pure Python PDF generation library for official forensic reports.
- **HTML5 & CSS3**: Minimal, clean, white-background academic user interface.
- **HTML5 Video Player**: Browser native video player for MP4 and WebM preview.

> **Zero Complex Dependencies**: Avoids heavy machine learning frameworks, OpenCV, FFmpeg, React, Node.js, and external cloud services to ensure 100% explainability during academic viva reviews.

---

## 3. Project Structure

```text
multi_vendor_dvr_forensics/
│
├── app.py                      # Flask web routes and application controller
├── database.py                 # SQLite connection, tables, queries & activity logging
├── hashing.py                  # SHA-256 hashing, verification, and tamper demo logic
├── evidence.py                 # File handling, dual preservation, & rule-based vendor detector
├── report.py                   # PDF forensic examination report generator (ReportLab)
├── requirements.txt            # Minimal Python dependencies (Flask, ReportLab)
├── forensics.db                # SQLite database storing cases, evidence, and logs
│
├── templates/                  # Clean HTML templates
│   ├── base.html               # Shared layout, header, footer, & 6-item navigation bar
│   ├── login.html              # Investigator authentication & one-click demo login
│   ├── dashboard.html          # Metric cards, active cases, recent evidence, recent activities
│   ├── cases.html              # Case registry & case creation form
│   ├── case_details.html       # Individual case view with associated evidence inventory
│   ├── add_evidence.html       # Video evidence upload & vendor identification form
│   ├── analysis.html           # Multi-parameter evidence search, filter, and hash table
│   ├── video_viewer.html       # HTML5 video preview, hash cards, & viva demonstration controls
│   ├── activity.html           # Immutable chain of custody audit log table
│   └── reports.html            # PDF report generator & downloadable report archive
│
├── static/
│   ├── css/
│   │   └── style.css           # Clean, minimal white-background academic styling
│   └── js/
│       └── main.js             # Copy-to-clipboard and confirmation helpers
│
├── evidence/
│   ├── original/               # Read-only pristine original evidence master copies
│   ├── working/                # Working duplicates used for forensic analysis
│   └── demo_staging/           # Sample CCTV footage for quick academic demonstration
│
├── reports/                    # Generated forensic PDF reports
│
├── tests/
│   └── test_forensics.py       # Comprehensive automated unit test suite (12 tests)
│
├── PROJECT_INTERNAL_GUIDE.md   # Complete architectural and code walkthrough
└── VIVA_QUESTIONS.md           # 45+ Viva examination questions and beginner-friendly answers
```

---

## 4. Key Forensic Features

### A. Case Management
- Create and register forensic case files with Case ID, Case Name, Description, and Assigned Investigator.
- Browse existing cases, open dedicated case dossiers, and view all evidence exhibits linked to the case.

### B. Safe Dual-Copy Evidence Ingestion
- When CCTV video evidence is uploaded, the tool saves a pristine master copy into `evidence/original/` as write-protected.
- A bit-for-bit duplicate is created in `evidence/working/`. All video streaming, analysis, and testing occur exclusively on the working duplicate, ensuring original evidence is **never modified**.

### C. Rule-Based Vendor Identification
- Analyzes filename patterns and container signatures to classify hardware vendor:
  - **Hikvision**: Channel segmentation (`ch01_`, `ch02_`, `hik_`, `_h4_`, `hikvision`).
  - **Dahua**: Signature container `.dav`, magic bytes `DHAV`/`DAHUA`, or naming `dh_` / `_main_`.
  - **Honeywell**: Naming tags `hw_`, `CAM0X`, `HN_`, or `honeywell`.
  - **Unknown/Other**: Standard video containers without vendor-specific tags.
- Allows investigator manual override.

### D. Cryptographic SHA-256 Integrity Verification
- Reads files in memory-efficient 64 KB chunks via Python `hashlib.sha256`.
- Calculates an intake baseline hash (`sha256_original`).
- Provides a live on-demand "Verify Integrity Now" function that recalculates the current file hash and compares it bit-for-bit with the baseline:
  - Hashes match &rarr; **`Integrity Verified`** (Green badge)
  - Hashes differ &rarr; **`Integrity Mismatch`** (Red alert badge)

### E. Built-In HTML5 Video Viewer
- Uses the browser's native player to preview supported MP4 and WebM videos.
- For proprietary CCTV containers (such as Dahua `.dav` or raw streams), clearly displays an educational forensic notice explaining why web browsers lack native decoders and why forensic standards forbid destructive transcoding.

### F. Chain of Custody Activity Log
- Records an immutable chronological log in SQLite whenever:
  - A case is created.
  - Evidence is uploaded.
  - A hash is calculated or recalculated.
  - Evidence is analyzed.
  - A forensic report is compiled.

### G. Professional PDF Report Generation
- Uses ReportLab to compile court-admissible PDF examination reports containing Case details, Evidence inventory, SHA-256 comparisons, Investigator notes, and Activity audit history.

### H. Academic Demonstration Controls (Viva Mode)
- Built-in buttons allow the student to simulate evidence tampering (modifying 4 bytes on the working copy) to demonstrate immediate detection of an `Integrity Mismatch`, followed by one-click restoration from the pristine original evidence file.

---

## 5. Installation and Setup

### Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14
- Operating System: Windows, macOS, or Linux

### Step 1: Install Dependencies
Open your terminal or command prompt inside the project folder:
```bash
pip install -r requirements.txt
```

### Step 2: Run the Web Application
```bash
python app.py
```

### Step 3: Open in Browser
Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```

- Default credentials: `investigator` / `forensics123`
- Or click the **"One-Click Demo Login as Investigator"** button.

---

## 6. Running Automated Tests

Run the complete 12-test suite using Python's built-in `unittest` module:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

All 12 tests will execute and output `OK`.

---

## 7. Forensic Disclaimer & Academic Scope

This project is an academic prototype developed for educational demonstration.
- Vendor identification is heuristic and rule-based; it does not claim to decode every proprietary hardware revision or damaged storage cluster.
- Proprietary CCTV streams are stored bit-for-bit without alteration rather than transcoded, preserving forensic admissibility.
