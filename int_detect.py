import time

def read_log_file(log_file):
    with open(log_file, 'r') as file:
        return file.readlines()

def detect_intrusion(log_entries, max_attempts=3, time_window=60):
    ip_attempts = {}
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
