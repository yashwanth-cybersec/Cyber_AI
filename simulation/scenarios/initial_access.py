# simulation/scenarios/initial_access.py  — T1566
import time, random

def run(intensity="medium"):
    user = random.choice(["jsmith","finance_user","hr_admin"])
    ip   = random.choice(["45.33.32.156","185.220.101.45"])
    now  = time.time()
    events = [
        {"type":"process_create","ip":"local","username":user,
         "timestamp":now-30,"source":"simulation","severity":"HIGH",
         "process":"winword.exe","cmdline":"winword.exe invoice_2026.docm"},
        {"type":"process_create","ip":"local","username":user,
         "timestamp":now-20,"source":"simulation","severity":"CRITICAL",
         "process":"cmd.exe","cmdline":"cmd.exe /c powershell -nop -enc JABjAGwA"},
        {"type":"port_connect","ip":ip,"username":user,
         "timestamp":now-10,"source":"simulation","severity":"CRITICAL","port":443,
         "detail":"Macro payload calling back to attacker"},
    ]
    if intensity == "high":
        events.append({"type":"fail_login","ip":ip,"username":"administrator",
                       "timestamp":now,"source":"simulation","severity":"HIGH"})
    return {"technique_id":"T1566","technique_name":"Phishing / Initial Access",
            "tactic":"Initial Access","severity":"HIGH","intensity":intensity,
            "target_user":user,"attacker_ip":ip,"event_count":len(events),"events":events,
            "description":f"Simulated phishing: Office macro → shell → C2 callback"}
