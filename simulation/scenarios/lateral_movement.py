# simulation/scenarios/lateral_movement.py  — T1021
import time, random

HOSTS  = ["SERVER-DB","SERVER-HR","SERVER-FINANCE","DC-01","SERVER-BACKUP"]
PORTS  = {22:"SSH",3389:"RDP",445:"SMB",5985:"WinRM"}

def run(intensity="medium"):
    user  = random.choice(["svc_backup","admin","jsmith"])
    ip    = f"192.168.{random.randint(1,5)}.{random.randint(2,254)}"
    now   = time.time()
    nh    = {"low":2,"medium":4,"high":6}.get(intensity, 4)
    hosts = random.sample(HOSTS, min(nh, len(HOSTS)))
    port, svc = random.choice(list(PORTS.items()))
    events = []
    for i, host in enumerate(hosts):
        events.append({"type":"login_success","ip":ip,"username":user,
                       "timestamp":now-(nh-i)*15,"source":"simulation","severity":"MEDIUM",
                       "target_host":host,"port":port})
        events.append({"type":"port_connect","ip":ip,"username":user,
                       "timestamp":now-(nh-i)*15+1,"source":"simulation","severity":"MEDIUM",
                       "port":port,"target_host":host})
    return {"technique_id":"T1021","technique_name":"Lateral Movement",
            "tactic":"Lateral Movement","severity":"CRITICAL","intensity":intensity,
            "attacker_ip":ip,"target_user":user,"hosts_accessed":hosts,
            "event_count":len(events),"events":events,
            "description":f"Simulated lateral movement by '{user}' across {len(hosts)} hosts via {svc}"}
