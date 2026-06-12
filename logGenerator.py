import json, random, ipaddress, time
from datetime import datetime

names = ["admin", "root", "john_doe", "guest", "administrator", "sysadmin", "user1", "test_user", "superuser", "dev_user", "moderator", "db_admin", "network_wizard", "cyber_ninja", "pixel_guru", "code_monkey", "tech_support", "data_boss", "cloud_strider", "bit_flipper"]

internal_subnet = ipaddress.IPv4Network("192.168.1.0/24")
external_subnet = ipaddress.IPv4Network("10.0.0.0/16")
unusual_subnet = ipaddress.IPv4Network("45.221.8.0/24") #purposefully unusual, potentially suspicious, subnet

HOURS = list(range(24))
HOUR_WEIGHTS = [2, 2, 1, 1, 1, 2, 5, 10, 20, 30, 40, 50, 80, 85, 60, 40, 30, 25, 20, 15, 10, 5, 3, 2] #traffic weight. Heavy during the day, small late at night


def generate_log_entry():
    generated_logs = []

    chosen_hour = random.choices(HOURS, weights=HOUR_WEIGHTS, k=1)[0] #pick the hour based on traffic volume weights

    if chosen_hour >= 23 or chosen_hour <= 4: #LATE NIGHT: 55% chance normal internal access. 45% chance of potentially malicious IP
        subnets = [internal_subnet, unusual_subnet]
        ip_weights = [40, 60]
    else: #common access. Only a 5% chance of suspicious IPs
        subnets = [internal_subnet, external_subnet, unusual_subnet]
        ip_weights = [75, 25, 5]

    chosen_net = random.choices(subnets, weights=ip_weights, k=1)[0] #randomly chooses the subnet based on the daytime
    chosen_host = random.choice(list(chosen_net.hosts())) #sets the host inside the chosen subnet

    now = datetime.now()
    random_date = now.replace(hour=chosen_hour, minute=random.randint(0, 59), second=random.randint(0, 59)) #picks the current day, but randomizes the specific time to reflect accesses durint that day
    timestamp = time.ctime(random_date.timestamp()) #converts timestamp into ctime notation
    
    #Defining if the login attempt was successful or not
    if chosen_net == unusual_subnet:
        login_attempt = "Failed"
    else:
        login_attempt = "Successful"

    username = random.choice(names)

    probable_attack = False
    if (chosen_hour >= 23 or chosen_hour <= 4) and chosen_net == unusual_subnet: #if an unusual ip logs late at night the attack "sensor" is triggered
        probable_attack = True

    if probable_attack == True:
        login_attempt = "Failed"
        attack_chance = random.randint(1,100) 
        breakin_chance = random.randint(1,100)

        if attack_chance >= 45: #there is a 65% chance that an unusual ip late at night tries to log in bursts, indicating attacks
            base_seconds = random_date.timestamp() #converts the current time to seconds and add 2 seconds every iteration. The goal is to simulate an attack coming in bursts

            burst_lenght = random.randint(5,12)
            for i in range(burst_lenght):
                current_seconds = base_seconds + (i*2)
                
                if i == burst_lenght -1 and breakin_chance >= 50:
                    login_attempt = "Successful"
                else:
                    login_attempt = "Failed"

                suspicious_entries = {
                    "timestamp" : time.ctime(current_seconds),
                    "ip_address" : str(chosen_host),
                    "username" : username,
                    "login" : login_attempt
                }
                generated_logs.append((current_seconds, json.dumps(suspicious_entries)))

            return generated_logs
            
    
    normal_entry = {
        "timestamp" : str(timestamp),
        "ip_address" : str(chosen_host),
        "username" : username,
        "login" : login_attempt
    }
    base_seconds = random_date.timestamp()
    generated_logs.append((base_seconds, json.dumps(normal_entry)))

    return generated_logs

master_log = []

for line in range(200):
    log_batch = generate_log_entry()
    for entry in log_batch:
            master_log.append(entry)

master_log.sort()

with open("log.json", "w") as log:
    for raw_time, json_string in master_log:
        log.write(f"{json_string}\n")
    log.flush()
