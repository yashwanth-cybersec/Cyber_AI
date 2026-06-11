# simulation/scenarios/collection.py  — T1560
import time, random

def run(intensity="medium"):
    user = random.choice(["attacker","jsmith","SYSTEM"])
    now  = time.time()
    n    = {"low":2,"medium":4,"high":6}.get(intensity, 4)
    events = []
    for i in range(n):
        events.append({"type":"process_create","ip":"local","username":user,
                       "timestamp":now-i*5,"source":"simulation","severity":"HIGH",
                       "process":"7z.exe","cmdline":f"7z a -p secret archive_{i}.zip C:\\Users\\*\\Documents\\"})
    events.append({"type":"admin_access","ip":"local","username":user,
                   "timestamp":now-1,"source":"simulation","severity":"HIGH",
                   "command":"findstr /si password *.txt *.xml *.ini"})
    return {"technique_id":"T1560","technique_name":"Collection / Data Staging",
            "tactic":"Collection","severity":"HIGH","intensity":intensity,
            "target_user":user,"event_count":len(events),"events":events,
            "description":f"Simulated data staging: {n} archives created, credential search"}
