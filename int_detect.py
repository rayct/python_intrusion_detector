import time
import sys

def read_log_file(log_file):
    """
    Reads a log file and returns a list of log entries.

    Args:
    - log_file (str): The path to the log file.

    Returns:
    - list: A list containing log entries read from the file.
    """
    try:
        with open(log_file, 'r', encoding='utf-8') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading log file: {e}")
        sys.exit(1)

def detect_intrusion(log_entries, max_attempts=3, time_window=60):
    """
    Detects potential intrusion attempts based on failed login attempts within a specified time window.

    Args:
    - log_entries (list): A list of log entries to be analyzed.
    - max_attempts (int): Maximum number of failed login attempts allowed within the time window.
    - time_window (int): Time window in seconds within which the attempts are counted.

    Returns:
    - tuple: A tuple containing a boolean indicating whether intrusion is detected and the suspicious IP address.
    """
    ip_attempts = {}
    # Rest of the function remains unchanged
    # ...

    for entry in log_entries:
        parts = entry.split()
        if len(parts) >= 5 and parts[-2] == 'failed' and parts[-1] == 'attempt':
            timestamp, _, ip_address, _ = parts[:4]
            timestamp = time.mktime(time.strptime(timestamp, '%Y-%m-%d %H:%M:%S'))
            if ip_address in ip_attempts:
                if timestamp - ip_attempts[ip_address][-1] <= time_window:
                    ip_attempts[ip_address].append(timestamp)
                    if len(ip_attempts[ip_address]) >= max_attempts:
                        return True, ip_address
                else:
                    ip_attempts[ip_address] = [timestamp]
            else:
                ip_attempts[ip_address] = [timestamp]
    return False, None

if __name__ == "__main__":
    log_file = "sample_log.txt"
    log_entries = read_log_file(log_file)
    intrusion_detected, suspicious_ip = detect_intrusion(log_entries)

    if intrusion_detected:
        print(f"Intrusion detected from {suspicious_ip}.")
    else:
        print("No intrusion detected.")
