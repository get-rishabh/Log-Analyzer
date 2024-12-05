import re
import csv
from collections import Counter, defaultdict

def parse_log_file(log_file_content):
    pattern = re.compile(
        r"(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] \"(?P<method>\w+) (?P<endpoint>.*?) HTTP/.*\" (?P<status>\d{3}) (?P<size>\d+)( \"(?P<message>.*?)\")?"
    )

    log_entries = []
    for line in log_file_content.splitlines():
        match = pattern.match(line)
        if match:
            log_entries.append(match.groupdict())
    return log_entries

def count_requests_per_ip(log_entries):
    ip_counter = Counter(entry['ip'] for entry in log_entries)
    return dict(ip_counter)

def find_most_frequent_endpoint(log_entries):
    endpoint_counter = Counter(entry['endpoint'] for entry in log_entries)
    return endpoint_counter.most_common(1)[0]

def detect_brute_force(log_entries, threshold=10):
    failed_logins = defaultdict(int)

    for entry in log_entries:
        if entry['status'] == '401' or (entry.get('message') and "Invalid credentials" in entry['message']):
            failed_logins[entry['ip']] += 1

    flagged_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return flagged_ips

    return flagged_ips
def save_to_csv(requests_per_ip, most_frequent_endpoint, flagged_ips):
    with open("log_analysis_results.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["Requests per IP Address"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in requests_per_ip.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])  # Blank line for separation
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_frequent_endpoint[0], most_frequent_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])  # Blank line for separation
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in flagged_ips.items():
            writer.writerow([ip, count])


if __name__ == "__main__":
    # Read log file content from a file
    with open("test.log", "r") as file:
        log_file_content = file.read()

    log_entries = parse_log_file(log_file_content)

    # 1. Count Requests per IP Address
    requests_per_ip = count_requests_per_ip(log_entries)
    print("\n-----------------------------Requests per IP Address :----------------------------------\n")
    print("IP Address         Request Count")
    for ip, count in requests_per_ip.items():
        print(f"{ip:<20}{count}")

    # 2. Identify the Most Frequently Accessed Endpoint
    most_frequent_endpoint = find_most_frequent_endpoint(log_entries)
    print("\n-------------------------Most Frequently Accessed Endpoint :----------------------------\n") 
    print(f"{most_frequent_endpoint[0]} Accessed {most_frequent_endpoint[1]} Times")

    # 3. Detect Suspicious Activity (Brute Force Login Attempts)
    flagged_ips = detect_brute_force(log_entries)
    if flagged_ips:
        print("\n--------------------------Suspicious Activity Detected:--------------------------------\n")
        print("IP Address         Failed Login Attempts")
        for ip, count in flagged_ips.items():
            print(f"{ip:<20}{count}")
    else:
        print("\n--------------------------No suspicious activity detected--------------------------\n")

    # 4. Save Results to CSV
    save_to_csv(requests_per_ip, most_frequent_endpoint, flagged_ips)
    print("\nResults have been saved to 'log_analysis_results.csv'")

    print("\n---------------------------------------------------------------------------------------")