# simulation/scenarios/c2_beacon.py  — T1071
import time, random

C2_IPS = ["185.220.101.45","5.188.206.14","91.108.56.200","194.165.16.77"]
UAS    = ["python-requests/2.28.0","curl/7.68.0","Go-http-client/1.1"]

def run(intensity="medium"):
    ip  = random.choice(C2_IPS)
    ua  = random.choice(UAS)
    now = time.time()
    n   = {"low":3,"medium":6,"high":12}.get(intensity, 6)
    ivl = {"low":60,"medium":30,"high":15}.get(intensity, 30)
    events = [{"type":"port_connect","ip":ip,"username":"SYSTEM",
               "timestamp":now-(n-i)*(ivl+random.uniform(-2,2)),
               "source":"simulation","severity":"HIGH","port":80,
               "detail":f"C2 beacon #{i+1} interval~{ivl}s"} for i in range(n)]
    return {"technique_id":"T1071","technique_name":"C2 Beaconing",
            "tactic":"Command and Control","severity":"CRITICAL","intensity":intensity,
            "c2_ip":ip,"beacon_count":n,"event_count":len(events),"events":events,
            "description":f"Simulated {n} C2 beacons to {ip} at {ivl}s intervals"}
