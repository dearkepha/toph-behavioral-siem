import json

with open("log.json", "r") as log:
    for line in log:
        log_entry = json.loads(log.readline()) #picks a line from the log script and translates it into a json string
        ip = log_entry["ip_address"]
        timestamp = log_entry["timestamp"]
        username = log_entry["username"]

        time_part = timestamp.split()[3]
        hour = int(time_part.split(":")[0])

        if (hour >= 23 or hour <= 4) and ip.startswith("45.221.8."):
            print(f"Suspicious access from ip {ip}. Username {username} at time {timestamp}")
