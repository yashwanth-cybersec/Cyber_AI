# simulation/scenarios/honeypot.py  — T1595 Reconnaissance
import time, random

HONEYPOT_PORTS = [2222, 8888, 9999, 4444, 21]

def run(intensity="medium"):
    ip  = random.choice(["45.33.32.156","185.220.101.45","91.108.4.180"])
    now = time.time()
    n   = {"low":2,"medium":4,"high":7}.get(intensity, 4)
    ports_hit = random.sample(HONEYPOT_PORTS, min(n, len(HONEYPOT_PORTS)))
    events = []
    for i, port in enumerate(ports_hit):
        events.append({"type":"port_connect","ip":ip,"username":"unknown",
                       "timestamp":now-i*random.uniform(1,5),"source":"simulation",
                       "severity":"CRITICAL","port":port,
                       "detail":f"Honeypot hit on port {port}"})
    return {"technique_id":"T1595","technique_name":"Reconnaissance / Honeypot Trigger",
            "tactic":"Reconnaissance","severity":"CRITICAL","intensity":intensity,
            "attacker_ip":ip,"ports_hit":ports_hit,"event_count":len(events),"events":events,
            "description":f"Simulated attacker scanning {len(ports_hit)} honeypot ports from {ip}"}
