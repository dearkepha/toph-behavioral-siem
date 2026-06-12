import json
from collections import Counter
suspicious_ips = []
cnt = Counter()

def read_entry():
    with open("log.json", "r") as log:
        for line in log:
            line.strip()
            clear_entry = json.loads(line)
            ip = clear_entry["ip_address"]
            timestamp = clear_entry["timestamp"]
            username = clear_entry["username"]
            login = clear_entry["login"]
        
            if ip.startswith("192.168.1.") or ip.startswith("10.0."):
                continue
            suspicious_ips.append((ip, username, login))

def burst_detector():
    read_entry()
    for ip, username, login in suspicious_ips:
        cnt[ip] += 1

    for ip in cnt:
        print(f"ip {ip} tried to log in a total of {cnt[ip]} times under the username {username}. {login} login attempt. It got in after {cnt[ip]-1} tries")
burst_detector()

