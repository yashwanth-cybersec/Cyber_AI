# simulation/scenarios/c2_remote_access.py  — T1219
import time, random

C2_IPS = ["185.220.101.45","5.188.206.14","91.108.56.200"]
RATS   = ["njrat.exe","asyncrat.exe","quasar.exe","remcos.exe","nanocore.exe"]

def run(intensity="medium"):
    ip   = random.choice(C2_IPS)
    rat  = random.choice(RATS)
    user = random.choice(["SYSTEM","attacker"])
    now  = time.time()
    n    = {"low":3,"medium":6,"high":12}.get(intensity, 6)
    events = []
    events.append({"type":"suspicious_process","ip":"local","username":user,
                   "timestamp":now-60,"source":"simulation","severity":"CRITICAL",
                   "process":rat,"detail":f"Known RAT process: {rat}"})
    for i in range(n):
        events.append({"type":"port_connect","ip":ip,"username":user,
                       "timestamp":now-i*20,"source":"simulation","severity":"HIGH",
                       "port":random.choice([4444,1337,8080,443]),
                       "detail":f"RAT keepalive #{i+1}"})
    return {"technique_id":"T1219","technique_name":"C2 Remote Access Tool",
            "tactic":"Command and Control","severity":"CRITICAL","intensity":intensity,
            "c2_ip":ip,"tool":rat,"event_count":len(events),"events":events,
            "description":f"Simulated RAT {rat} connecting to C2 {ip} with {n} keepalives"}
