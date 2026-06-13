import json
suspicious_ips = []

def read_entry():
    with open("log.json", "r") as log:
        for line in log:
            line.strip()
            clear_entry = json.loads(line)
            ip = clear_entry["ip_address"]
            timestamp = clear_entry["timestamp"]
            username = clear_entry["username"]
            login = clear_entry["login"]
        
            if ip.startswith("192.168.1.") or ip.startswith("10.0."): #every ip that is not from an expected network get's dumped into a list to be analyzed
                continue
            suspicious_ips.append((ip, username, login))

def burst_detector():
    read_entry()
    ip_data = {}
    
    for ip, username, login in suspicious_ips:
        if ip not in ip_data:
            ip_data[ip] = {"count" : 0, "username" : username, "login" : login} #ip_data is a dictionary where every value for that ip is another dictionary containing info about it's respective address
        ip_data[ip]["count"]+=1
        ip_data[ip]["login"] = login
    for ip in ip_data:
        print(f"ip {ip} tried to log in a total of {ip_data[ip]['count']} times under the username {ip_data[ip]['username']}. Login {ip_data[ip]['login']}")
burst_detector()

