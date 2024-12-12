import re 
import json
from collections import Counter
 
with open('server_logs.txt') as server_logs: 

    pattern=re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<date>.?)\] "(?P<method>GET|POST|PUT|DELETE|PATCH) (?P<url>.?) HTTP/1\.1" (?P<status>\d{3})')


    setirler = pattern.finditer(str(server_logs))
    
    lsit=[]

    for setir in setirler: 
        lsit.append(setir.groupdict())

    for pat in server_logs:
        print(pat)


    enteries = [pat['ip'] for pat in lsit if pat['status'] == '40' ]

    entery_count = Counter(enteries)

    entery_logs = {ip: count for ip, count in entery_count.items() if count > 5}

with open ('entery_logs.json', 'w') as json_file:
    json.dump(entery_logs, json_file, indent=4)

print(entery_logs)

threat_ip = {ip: count for ip, count in entery_count.items() if count > 3}

with open ('threat_ip.json', 'w') as json_file:
    json.dump(threat_ip, json_file, indent=4 )
    
print(threat_ip) 

with open ('fl_logs.json', 'r') as file2:
    entery_logs_data = json.load(file2)

with open ('th_ip.json', 'r') as file2:
    threat_data = json.load(file2)

    
