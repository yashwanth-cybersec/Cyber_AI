# simulation/scenarios/ransomware.py  — T1486
import time, random

PROCS  = ["encrypt.exe","locker.exe","vssadmin.exe","wbadmin.exe","bcdedit.exe"]
CMDS   = ["vssadmin delete shadows /all /quiet","bcdedit /set {default} recoveryenabled No",
          "wbadmin delete catalog -quiet","net stop \"Volume Shadow Copy\""]

def run(intensity="medium"):
    ip   = f"185.{random.randint(1,254)}.{random.randint(1,254)}.1"
    user = random.choice(["SYSTEM","Administrator"])
    now  = time.time()
    events = []
    for p in random.sample(PROCS, 2):
        events.append({"type":"suspicious_process","ip":"local","username":user,
                       "timestamp":now-60,"source":"simulation","severity":"CRITICAL","process":p})
    nc = {"low":1,"medium":3,"high":6}.get(intensity, 3)
    for cmd in random.sample(CMDS, min(nc, len(CMDS))):
        events.append({"type":"admin_access","ip":"local","username":user,
                       "timestamp":now-45,"source":"simulation","severity":"CRITICAL","command":cmd})
    if intensity in ("medium","high"):
        events.append({"type":"cpu_spike","ip":"local","username":user,
                       "timestamp":now-30,"source":"simulation","severity":"HIGH",
                       "cpu":random.uniform(85,99),"process":"encrypt.exe"})
    events.append({"type":"port_connect","ip":ip,"username":user,
                   "timestamp":now,"source":"simulation","severity":"CRITICAL","port":443,
                   "detail":"Ransomware C2 callback"})
    return {"technique_id":"T1486","technique_name":"Ransomware Behaviour",
            "tactic":"Impact","severity":"CRITICAL","intensity":intensity,
            "attacker_ip":ip,"event_count":len(events),"events":events,
            "description":"Simulated ransomware kill chain — backup deletion, encryption spike, C2"}
