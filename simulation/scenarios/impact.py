# simulation/scenarios/impact.py  — T1489 Service Stop + T1486
import time, random

CMDS = ["net stop MSSQLSERVER","net stop \"SQL Server (MSSQLSERVER)\"",
        "net stop W3SVC","net stop wuauserv","sc config MSSQLSERVER start= disabled"]

def run(intensity="medium"):
    user = random.choice(["SYSTEM","Administrator"])
    ip   = f"185.{random.randint(1,254)}.{random.randint(1,254)}.1"
    now  = time.time()
    n    = {"low":2,"medium":4,"high":6}.get(intensity, 4)
    events = []
    for cmd in random.sample(CMDS, min(n, len(CMDS))):
        events.append({"type":"admin_access","ip":"local","username":user,
                       "timestamp":now-random.randint(5,30),"source":"simulation",
                       "severity":"CRITICAL","command":cmd})
    events.append({"type":"cpu_spike","ip":"local","username":user,
                   "timestamp":now-5,"source":"simulation","severity":"HIGH",
                   "cpu":random.uniform(80,99),"process":"impact.exe"})
    events.append({"type":"port_connect","ip":ip,"username":user,
                   "timestamp":now,"source":"simulation","severity":"CRITICAL",
                   "port":443,"detail":"Impact C2 callback"})
    return {"technique_id":"T1489","technique_name":"Impact / Service Stop",
            "tactic":"Impact","severity":"CRITICAL","intensity":intensity,
            "attacker_ip":ip,"event_count":len(events),"events":events,
            "description":f"Simulated service disruption: {n} critical services stopped"}
