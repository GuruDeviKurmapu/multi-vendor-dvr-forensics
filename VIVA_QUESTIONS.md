# Multi-Vendor DVR/NVR Forensic Analysis Tool: Viva Questions & Answers

This document contains 50 frequently asked questions (FAQs) and simple, beginner-friendly answers designed specifically for B.Tech Computer Science and Engineering students preparing for project reviews and viva examinations.

---

## Category 1: Project Introduction & Problem Statement

### Q1: What is the title and purpose of your project?
**Answer:** The title of our project is **Multi-Vendor DVR/NVR Forensic Analysis Tool for CCTV Evidence**. Its purpose is to provide a simple, secure, and standardized digital forensic web application to ingest CCTV video evidence, identify the hardware vendor (Hikvision, Dahua, Honeywell), verify file integrity using SHA-256 hashing, maintain an immutable Chain of Custody, and generate court-ready forensic examination reports.

### Q2: What real-world problem does this project address?
**Answer:** In criminal investigations, CCTV footage is often recovered from different DVR/NVR hardware brands. These vendors use differing filename syntaxes, proprietary formats (such as Dahua `.dav`), and custom containers. Investigators often lack a unified tool to verify that the evidence has not been tampered with or corrupted. Our tool provides a unified, vendor-neutral analysis platform that guarantees forensic preservation.

### Q3: What is the main objective of this system?
**Answer:** The main objectives are:
1. To safely store CCTV video evidence without modifying the original physical file (Forensic Non-Destructive Principle).
2. To compute and verify cryptographic SHA-256 checksums to prove evidence authenticity.
3. To classify the surveillance equipment vendor using rule-based heuristics.
4. To maintain an unbroken Chain of Custody audit log.
5. To automatically generate official PDF forensic reports.

### Q4: Who are the target users of this application?
**Answer:** Digital forensic examiners, law enforcement agencies, cybercrime investigators, private security auditors, and legal professionals who need to verify CCTV evidence before presenting it in court.

---

## Category 2: Technologies & Architecture

### Q5: What technologies are used in this project?
**Answer:**
- **Python 3:** Core programming language.
- **Flask:** Lightweight web framework and routing controller.
- **SQLite 3:** Relational database for storing cases, exhibits, and logs.
- **Python `hashlib`:** Standard library for cryptographic SHA-256 hashing.
- **ReportLab:** Pure Python library for generating court-admissible PDF reports.
- **HTML5 & CSS3:** Clean, minimal user interface designed for academic forensics.
- **HTML5 `<video>` Player:** Built-in browser video player for playback of supported MP4 and WebM containers.

### Q6: Why did you avoid heavy frameworks like React, Node.js, or cloud databases?
**Answer:** In digital forensics, simplicity, determinism, and explainability are paramount. Using Python and Flask with SQLite keeps the code lightweight, eliminates external third-party dependencies, ensures the application runs completely offline (air-gapped forensic workstation requirement), and makes every internal line of code easy to explain during academic evaluation.

### Q7: Why did you choose SQLite over MySQL or MongoDB?
**Answer:** SQLite is serverless, self-contained, zero-configuration, and stores the entire database in a single local file (`forensics.db`). In digital forensics, cases are often archived as standalone files. SQLite ensures maximum portability without requiring database server setup or network socket exposure.

### Q8: What architectural pattern does your project follow?
**Answer:** It follows a clean Model-View-Controller (MVC) pattern:
- **Model:** SQLite database (`database.py`) and data structures representing cases, evidence, and logs.
- **View:** HTML5 templates (`templates/`) styled with pure CSS (`static/css/style.css`).
- **Controller:** Flask route handlers in `app.py` coordinating data processing and rendering views.

### Q9: Name the 5 core Python files in your project and their responsibilities.
**Answer:**
1. `app.py`: Flask controller handling HTTP routes, sessions, and request dispatching.
2. `database.py`: SQLite connection lifecycle, schemas, and query execution.
3. `hashing.py`: SHA-256 calculation, integrity checking, and tamper demonstration helpers.
4. `evidence.py`: Evidence ingestion, safe dual-storage (original vs working), and rule-based vendor detection.
5. `report.py`: Automated PDF report compilation using ReportLab.

---

## Category 3: Surveillance Hardware: DVR vs. NVR

### Q10: What is a DVR, and how does it work?
**Answer:** DVR stands for **Digital Video Recorder**. In a DVR system, analog CCTV cameras transmit raw analog video signals over coaxial cables (RG59/BNC) to a central recorder. The DVR unit digitizes, compresses (e.g. H.264), and writes the video onto its internal hard drives.

### Q11: What is an NVR, and how does it work?
**Answer:** NVR stands for **Network Video Recorder**. In an NVR system, IP cameras digitize, encode, and compress the video footage internally at the camera level, then transmit the digital stream over Ethernet network cables (Cat5e/Cat6) to the NVR unit, which aggregates and stores the data.

### Q12: What are the key differences between a DVR and an NVR?
**Answer:**
| Parameter | DVR (Digital Video Recorder) | NVR (Network Video Recorder) |
| :--- | :--- | :--- |
| **Camera Type** | Analog CCTV cameras | Digital IP cameras |
| **Transmission** | Coaxial BNC cable | Ethernet (RJ45 / Cat6) / IP network |
| **Video Encoding** | Done at the central DVR unit | Done internally on the camera itself |
| **Power** | Separate power supply lines | Often uses Power over Ethernet (PoE) |
| **Resolution** | Typically standard / 1080p | High resolution (4K, 8MP, 12MP) |

---

## Category 4: Digital Forensics Principles & Chain of Custody

### Q13: What is the Fundamental Forensic Non-Destructive Principle?
**Answer:** The fundamental rule of digital forensics states that an investigator must **never alter, modify, or write to the original evidence**. All examination, decoding, streaming, and testing must be performed on an exact bit-for-bit duplicate (working copy) while the original remains write-protected.

### Q14: How does your tool uphold the Non-Destructive Principle?
**Answer:** When an evidence file is uploaded:
1. The master file is immediately saved in `evidence/original/` and treated as write-protected.
2. A separate bit-exact clone is written into `evidence/working/`.
3. All web playback, analysis, and tamper testing operate strictly on the working copy. The master file in `evidence/original/` is never modified.

### Q15: What is Chain of Custody (CoC)?
**Answer:** Chain of Custody is a chronological, legally documented paper or electronic audit trail that records who seized, handled, transferred, analyzed, and stored digital evidence. It proves that the evidence presented in court is the exact item seized and has not been altered or substituted.

### Q16: How is Chain of Custody implemented in your database?
**Answer:** We maintain an immutable `activity_log` table in SQLite. Every time a case is created, evidence is uploaded, a hash is calculated, evidence is examined, or a report is generated, a new row is appended containing the exact timestamp, action name, investigator ID, case ID, evidence ID, and descriptive details.

### Q17: What international standard governs digital evidence handling?
**Answer:** **ISO/IEC 27037** provides guidelines for the identification, collection, acquisition, and preservation of digital evidence.

---

## Category 5: Cryptographic Hashing & SHA-256

### Q18: What is SHA-256?
**Answer:** SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function published by the National Institute of Standards and Technology (NIST). It takes an input of any length and produces a fixed-size 256-bit (64-character hexadecimal) message digest.

### Q19: What are the three essential properties of SHA-256?
**Answer:**
1. **Deterministic:** The exact same file will always produce the exact same 64-character hash.
2. **One-Way (Pre-image Resistance):** It is computationally impossible to reconstruct the video footage from the hash string.
3. **Collision Resistant:** It is practically impossible to find two different video files that yield the identical hash.

### Q20: What is the "Avalanche Effect" in hashing?
**Answer:** The avalanche effect means that if even a single bit (1 to 0 or 0 to 1) is modified inside a multi-gigabyte video file, the resulting SHA-256 checksum changes drastically and unpredictably, immediately exposing the alteration.

### Q21: Why does your `calculate_sha256()` function read files in 64 KB chunks?
**Answer:** Video evidence files can be several gigabytes in size. If a program attempts to read an entire 5 GB video into memory at once with `f.read()`, it can cause memory overflow or crash the system. By reading in 64 KB (65,536 bytes) chunks in a loop, memory consumption stays strictly bounded to 64 KB regardless of file size.

### Q22: How does your tool determine "Integrity Verified" vs "Integrity Mismatch"?
**Answer:**
- At intake, the tool computes and records the original hash: $H_{original}$.
- During verification, the tool recalculates the current hash of the working file on disk: $H_{current}$.
- If $H_{current} == H_{original}$, it displays **Integrity Verified** (Green badge).
- If $H_{current} \neq H_{original}$, it displays **Integrity Mismatch** (Red alert badge).

### Q23: How can you demonstrate evidence tampering to an examiner?
**Answer:** We built a dedicated **"Simulate Tampering"** button in `video_viewer.html`. When clicked, it appends 16 bytes to the working copy only. When the page reloads, the current SHA-256 hash changes, and the tool immediately triggers an **Integrity Mismatch** badge. Clicking **"Restore Working Copy"** copies the pristine original over the working file and restores the **Integrity Verified** status.

---

## Category 6: Vendor Identification

### Q24: What vendors does your tool identify?
**Answer:**
1. **Hikvision**
2. **Dahua**
3. **Honeywell**
4. **Unknown/Other**

### Q25: How does rule-based vendor identification work?
**Answer:** Instead of relying on closed proprietary hardware tools, our tool analyzes:
1. **File extensions:** For example, `.dav` is the signature proprietary container used by Dahua DVRs.
2. **Header magic bytes:** Reads the first 64 bytes of the file for signatures like `DHAV` or `DAHUA`.
3. **Naming syntaxes:**
   - Hikvision: `hik_`, `hikvision`, or channel syntax like `ch01_`, `ch02_`, `_h4_`.
   - Dahua: `dh_`, `dahua`, `_main_`.
   - Honeywell: `hw_`, `honeywell`, `cam0`, `hn_`.
4. **User Override:** If the investigator manually knows the hardware source from the physical DVR casing, they can select it in the dropdown.

### Q26: Does your tool claim to identify every single DVR format in existence?
**Answer:** No. As an honest academic prototype, it uses a rule-based heuristic for common export conventions. It does not reverse-engineer every proprietary, encrypted, or legacy filesystem. If a file does not match known rules, it is safely classified as **Unknown/Other** and preserved bit-for-bit.

---

## Category 7: Video Playback & Browser Compatibility

### Q27: Why can web browsers play MP4 and WebM files directly?
**Answer:** Modern web browsers have built-in HTML5 media engines that natively decode standard open container formats like MP4 (H.264/AAC) and WebM (VP8/VP9) through hardware-accelerated video decoders without requiring external plugins.

### Q28: Why can't browsers natively play Dahua `.dav` or proprietary AVI files?
**Answer:** `.dav` is a proprietary container wrapping raw DHAV bitstreams. Browsers lack an internal demuxer/codec for DHAV headers.

### Q29: Why didn't you automatically convert or transcode `.dav` files to `.mp4`?
**Answer:** In digital forensics, transcoding a video recompresses the stream, altering pixel data and generating a completely different hash. This destroys the cryptographic authenticity of the exhibit in court. Forensic best practice dictates that the file must be stored in its bit-exact original format. The tool provides a download button so the examiner can open the uncompressed stream in a vendor-certified player.

---

## Category 8: Database & Schema Design

### Q30: What are the 4 main tables in your SQLite database?
**Answer:**
1. `users`: Stores investigator authentication credentials and roles.
2. `cases`: Stores case files (`case_id`, `case_name`, `investigator_name`, `description`, `status`).
3. `evidence`: Stores exhibit details, file paths, file sizes, vendors, and original/current SHA-256 hashes.
4. `activity_log`: Stores immutable chronological audit events (`action`, `details`, `timestamp`, `performed_by`).

### Q31: How is referential integrity enforced in SQLite?
**Answer:** We define a foreign key constraint:
```sql
FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
```
And we explicitly enable foreign key enforcement on every connection using:
```python
conn.execute("PRAGMA foreign_keys = ON;")
```

### Q32: What is SQL Injection, and how does your project prevent it?
**Answer:** SQL Injection is an attack where malicious SQL statements are inserted into entry fields. We prevent this by never concatenating user input into SQL queries. Instead, we use parameterized queries with `?` placeholders or named parameters, ensuring SQLite treats all inputs strictly as literal values.

---

## Category 9: Forensic Report Generation

### Q33: How are PDF reports generated in your project?
**Answer:** We use the Python `reportlab` library. When the user requests a case report, `report.py` queries SQLite for all case details, evidence items, hashes, and audit logs. It compiles them into a structured PDF document with tables, headers, and cryptographic summaries.

### Q34: What information is included in the generated forensic report?
**Answer:**
1. Case Summary (Case ID, Case Name, Date Created, Lead Investigator, Description).
2. Evidence Inventory Table (Exhibit ID, Filename, Vendor, Size, Integrity Status).
3. Cryptographic Hash Analysis (Original SHA-256, Current SHA-256, Match Status, Notes).
4. Chain of Custody History (Chronological table of actions, timestamps, and investigators).
5. Forensic Principles & Limitations Statement.

### Q35: Why is generating a PDF report important in a forensics tool?
**Answer:** In forensic science, findings must be communicated to prosecutors, defense attorneys, and judges. An automated, standardized PDF prevents human transcription errors, documents the cryptographic hashes, and provides a permanent, court-admissible record.

---

## Category 10: Academic Review & Demonstration

### Q36: Can you explain the end-to-end workflow when evidence is uploaded?
**Answer:**
1. The user selects a video file, assigns it to a case, and clicks "Ingest Evidence" on `add_evidence.html`.
2. Flask route `/evidence/add` in `app.py` receives the file.
3. `evidence.ingest_evidence_file()` saves the original file to `evidence/original/` as write-protected.
4. It creates a working copy in `evidence/working/`.
5. `hashing.calculate_sha256()` computes the baseline SHA-256 hash.
6. `evidence.detect_vendor()` determines if it is Hikvision, Dahua, Honeywell, or Unknown.
7. An exhibit record is inserted into SQLite table `evidence`.
8. Two events ("Evidence uploaded" and "Hash calculated") are written to `activity_log`.
9. The user is redirected to `video_viewer.html` showing the video player, metadata, and "Integrity Verified" badge.

### Q37: How do you search and filter evidence?
**Answer:** On the `/analysis` page, users can filter by Case ID, Vendor (Hikvision, Dahua, Honeywell, Unknown), or Integrity Status (Verified vs Mismatch), or type a keyword into the search bar. Flask reads these query parameters and executes a dynamic `SELECT` query with SQL `WHERE` clauses.

### Q38: How do you protect routes from unauthorized access?
**Answer:** We use a Python decorator `@login_required` that checks if `'user'` is present in Flask's encrypted session dictionary. If an unauthenticated user attempts to visit `/dashboard` or `/cases`, they are automatically redirected to `/login`.

### Q39: What is the purpose of the 12 automated unit tests in `tests/test_forensics.py`?
**Answer:** The test suite verifies that every component works reliably: database table creation, case insertion, duplicate rejection, SHA-256 accuracy, tamper detection, working copy restoration, vendor identification heuristics, browser compatibility checks, activity logging, and PDF report compilation.

### Q40: What are the main limitations of this academic prototype?
**Answer:**
1. It relies on rule-based heuristics rather than low-level proprietary disk sector parsing.
2. It does not automatically reconstruct physically scratched or damaged hard disk platters.
3. It cannot play proprietary raw streams in-browser without vendor-specific codecs.

### Q41: What future enhancements can be added to this project?
**Answer:**
1. Integration of open-source FFmpeg bindings for automated lossless forensic transcode streams.
2. Optical Character Recognition (OCR) to detect embedded CCTV camera timestamps automatically.
3. Automated facial detection or motion-based event clustering.
4. Distributed multi-examiner cryptographic signatures (e.g., asymmetric RSA digital signatures).

### Q42: What is the significance of the "One-Click Demo Login" button?
**Answer:** During an academic viva or project demonstration, examiners want to see the core features immediately without being delayed by forgotten passwords. The one-click login button sets an active session instantly as the Lead Forensic Investigator.

### Q43: How does the application handle duplicate Case IDs?
**Answer:** The `case_id` column in SQLite is marked `UNIQUE NOT NULL`. If an investigator attempts to create a case with an existing ID, SQLite raises an `IntegrityError`. `database.create_case()` catches this error and returns a clean error message: *"Case ID already exists. Please choose a unique Case ID."*

### Q44: Where does the application store physical evidence on disk?
**Answer:**
- Original master copies: `evidence/original/`
- Examination duplicates: `evidence/working/`
- Pre-packaged sample footage: `evidence/demo_staging/`
- Generated forensic reports: `reports/`

### Q45: How long does SHA-256 take to compute on a typical video file?
**Answer:** In Python using standard `hashlib`, reading in 64 KB blocks processes data at roughly 300 to 500 MB per second on modern hardware, meaning a standard 100 MB CCTV clip is hashed in less than a quarter of a second.

### Q46: Can two different video files have the same SHA-256 hash?
**Answer:** Theoretically, since the input space is infinite and the output space is $2^{256}$, hash collisions exist mathematically. However, finding a collision in SHA-256 would require $2^{128}$ operations (the birthday bound), which is computationally infeasible with all existing computers on Earth combined.

### Q47: What happens if an investigator closes the browser during an investigation?
**Answer:** Since all cases, exhibit records, and audit logs are stored persistently in the SQLite database file (`forensics.db`), and evidence files are saved on disk, no data is lost. Reopening the browser and signing back in restores access to all cases and evidence.

### Q48: How does the UI indicate that evidence is safe and verified?
**Answer:** A prominent green badge displaying **`Integrity Verified`** is rendered with a checkmark. If a single byte is altered, it turns into a prominent red badge displaying **`Integrity Mismatch`** with an alert icon.

### Q49: What is Locard's Exchange Principle, and how does it relate to CCTV forensics?
**Answer:** Locard's Exchange Principle states that "every contact leaves a trace." In physical forensics, a perpetrator leaves fingerprints or fibers. In CCTV forensics, the physical presence of the perpetrator is captured as photons on camera sensors, encoded into digital packets, and committed to DVR hard drives. Digital forensics ensures that this digital trace is preserved without interference.

### Q50: Why is this project well-suited for a B.Tech CSE capstone?
**Answer:** It demonstrates mastery across multiple foundational computer science disciplines:
- Web systems & HTTP protocols (Flask, MVC architecture).
- Relational database design & ACID properties (SQLite, foreign keys, schema normalization).
- Information security & cryptography (SHA-256, bit-level integrity, avalanche effect).
- File systems & data structures (chunked streaming, container formats, dual-storage preservation).
- Software engineering & testing (automated unit test suite, documentation, clean modular code).
