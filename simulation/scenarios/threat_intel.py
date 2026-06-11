# simulation/scenarios/threat_intel.py  — T1583 Known Malicious Infrastructure
import time, random

BAD_IPS = ["185.220.101.45","45.33.32.156","5.188.206.14","194.165.16.77","91.108.56.200"]

def run(intensity="medium"):
    n   = {"low":2,"medium":4,"high":8}.get(intensity, 4)
    ips = random.sample(BAD_IPS, min(n, len(BAD_IPS)))
    now = time.time()
    events = []
    for i, ip in enumerate(ips):
        events.append({"type":"port_connect","ip":ip,"username":"unknown",
                       "timestamp":now-i*random.uniform(5,20),"source":"simulation",
                       "severity":"CRITICAL","port":random.choice([80,443,4444,1337]),
                       "detail":f"Known malicious IP: {ip}"})
    return {"technique_id":"T1583","technique_name":"Known Malicious Infrastructure",
            "tactic":"Resource Development","severity":"CRITICAL","intensity":intensity,
            "malicious_ips":ips,"event_count":len(events),"events":events,
            "description":f"Simulated {len(ips)} connections from known-bad threat intel IPs"}
