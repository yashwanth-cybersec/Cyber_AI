# simulation/scenarios/brute_force.py  — T1110 Brute Force
import time, random

def run(intensity="medium"):
    counts = {"low":4,"medium":8,"high":20}
    n      = counts.get(intensity, 8)
    ips    = ["45.33.32.156","185.220.101.45","192.168.99.254","91.108.4.180"]
    users  = ["administrator","admin","root","svc_backup","jsmith"]
    ip     = random.choice(ips)
    user   = random.choice(users)
    now    = time.time()
    events = [{"type":"fail_login","ip":ip,"username":user,
               "timestamp":now-(n-i)*random.uniform(1.5,4),"source":"simulation","severity":"MEDIUM"}
              for i in range(n)]
    if intensity == "high":
        events.append({"type":"login_success","ip":ip,"username":user,
                       "timestamp":now,"source":"simulation","severity":"HIGH"})
    return {"technique_id":"T1110","technique_name":"Brute Force Attack",
            "tactic":"Credential Access","severity":"HIGH","intensity":intensity,
            "attacker_ip":ip,"target_user":user,"event_count":len(events),"events":events,
            "description":f"Simulated {n} failed logins from {ip} against '{user}'"}
