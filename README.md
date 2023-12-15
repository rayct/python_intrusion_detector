# Intrusion Detection System

This Python program performs intrusion detection based on log analysis to identify suspicious login attempts.

## Overview

The program reads a log file and analyzes log entries to detect potential intrusions based on failed login attempts within a specified time window.

## Program Functionality

### read_log_file(log_file)

- **Description:** Reads the content of the specified log file.
- **Parameters:**
  - `log_file`: Path to the log file.
- **Returns:** A list containing individual log entries.

### detect_intrusion(log_entries, max_attempts=3, time_window=60)

- **Description:** Analyzes log entries to detect potential intrusions.
- **Parameters:**
  - `log_entries`: List of log entries to be analyzed.
  - `max_attempts`: Maximum allowed failed login attempts before considering an intrusion (default: 3).
  - `time_window`: Time window in seconds for tracking attempts (default: 60).
- **Returns:** 
  - `intrusion_detected`: Boolean indicating whether an intrusion is detected.
  - `suspicious_ip`: IP address identified as suspicious in case of an intrusion.

## Usage

### Setup

1. Ensure you have Python installed on your system.
2. Clone or download this repository.

### Running the Program

1. Provide a log file in the format specified in the code or modify the code to match your log file format.
2. Open a terminal or command prompt.
3. Navigate to the directory containing the program.
4. Run the program using the following command:

   ```bash
   python filename.py
    ```
---

**Documentation By:** Raymond C. TURNER

**Revision:** Friday 15th December 2023

codestak.io